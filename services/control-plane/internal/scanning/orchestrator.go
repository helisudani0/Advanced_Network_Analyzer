package scanning

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"ravynel-control-plane/internal/store"
)

const (
	maxScanTargets = 4096
	workerLimit    = 64
	probeTimeout   = 250 * time.Millisecond
)

var commonTCPPorts = []int{22, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443}

type Orchestrator struct {
	repo    store.Repository
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

func NewOrchestrator(repo store.Repository) *Orchestrator {
	return &Orchestrator{repo: repo, running: map[string]context.CancelFunc{}}
}

func (o *Orchestrator) StartNetworkScan(networkRange string) store.Scan {
	now := time.Now().UTC()
	scan := store.Scan{ID: newID(), Range: strings.TrimSpace(networkRange), Status: store.ScanRunning, Progress: 1, CreatedAt: now, UpdatedAt: now}
	o.repo.CreateScan(scan)
	ctx, cancel := context.WithCancel(context.Background())
	o.mu.Lock()
	o.running[scan.ID] = cancel
	o.mu.Unlock()
	go o.run(ctx, scan)
	return scan
}

func (o *Orchestrator) StopScan(id string) bool {
	o.mu.Lock()
	cancel, ok := o.running[id]
	if ok {
		cancel()
		delete(o.running, id)
	}
	o.mu.Unlock()
	return ok
}

func (o *Orchestrator) Shutdown(ctx context.Context) {
	o.mu.Lock()
	for _, cancel := range o.running {
		cancel()
	}
	o.running = map[string]context.CancelFunc{}
	o.mu.Unlock()
	<-ctx.Done()
}

func (o *Orchestrator) run(ctx context.Context, scan store.Scan) {
	targets, err := expandTargets(scan.Range, maxScanTargets)
	if err != nil || len(targets) == 0 {
		o.finish(scan, store.ScanFailed, 100)
		return
	}

	var scanMu sync.Mutex
	var completed int64
	jobs := make(chan netip.Addr)
	workers := min(workerLimit, len(targets))
	var wg sync.WaitGroup

	updateProgress := func(status store.ScanStatus, progress int) {
		scanMu.Lock()
		defer scanMu.Unlock()
		if progress < scan.Progress {
			progress = scan.Progress
		}
		scan.Status = status
		scan.Progress = progress
		scan.UpdatedAt = time.Now().UTC()
		o.repo.UpdateScan(scan)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if asset, ok := probeHost(ctx, target.String(), scan.ID); ok {
					o.repo.UpsertAsset(asset)
				}
				done := atomic.AddInt64(&completed, 1)
				progress := int((done * 100) / int64(len(targets)))
				if progress < 1 {
					progress = 1
				}
				updateProgress(store.ScanRunning, progress)
			}
		}()
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			o.finish(scan, store.ScanCanceled, int((atomic.LoadInt64(&completed)*100)/int64(len(targets))))
			return
		case jobs <- target:
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case <-ctx.Done():
		o.finish(scan, store.ScanCanceled, int((atomic.LoadInt64(&completed)*100)/int64(len(targets))))
	default:
		o.finish(scan, store.ScanDone, 100)
	}
}

func (o *Orchestrator) finish(scan store.Scan, status store.ScanStatus, progress int) {
	o.mu.Lock()
	delete(o.running, scan.ID)
	o.mu.Unlock()
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	scan.Status = status
	scan.Progress = progress
	scan.UpdatedAt = time.Now().UTC()
	o.repo.UpdateScan(scan)
}

func expandTargets(raw string, limit int) ([]netip.Addr, error) {
	parts := strings.FieldsFunc(strings.TrimSpace(raw), func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	if len(parts) == 0 {
		return nil, errors.New("network range is required")
	}

	seen := map[string]struct{}{}
	targets := make([]netip.Addr, 0)
	for _, part := range parts {
		if prefix, err := netip.ParsePrefix(part); err == nil {
			prefix = prefix.Masked()
			for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
				if !addr.IsValid() {
					break
				}
				key := addr.String()
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					targets = append(targets, addr)
				}
				if len(targets) >= limit {
					return sortTargets(targets), nil
				}
			}
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		key := addr.String()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			targets = append(targets, addr)
		}
		if len(targets) >= limit {
			break
		}
	}
	return sortTargets(targets), nil
}

func sortTargets(targets []netip.Addr) []netip.Addr {
	sort.Slice(targets, func(i, j int) bool { return targets[i].Less(targets[j]) })
	return targets
}

func probeHost(ctx context.Context, ip string, scanID string) (store.Asset, bool) {
	openPorts := make([]int, 0)
	for _, port := range commonTCPPorts {
		select {
		case <-ctx.Done():
			return store.Asset{}, false
		default:
		}
		dialer := net.Dialer{Timeout: probeTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		_ = conn.Close()
		openPorts = append(openPorts, port)
	}
	if len(openPorts) == 0 {
		return store.Asset{}, false
	}
	now := time.Now().UTC()
	return store.Asset{
		ID:           ip,
		IP:           ip,
		Hostname:     lookupHostname(ctx, ip),
		Role:         classifyRole(openPorts),
		Risk:         classifyRisk(openPorts),
		Status:       "online",
		OpenPorts:    openPorts,
		FirstSeen:    now,
		LastSeen:     now,
		SourceScanID: scanID,
	}, true
}

func lookupHostname(parent context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(parent, 350*time.Millisecond)
	defer cancel()
	type result struct {
		names []string
	}
	ch := make(chan result, 1)
	go func() {
		names, _ := net.LookupAddr(ip)
		ch <- result{names: names}
	}()
	select {
	case <-ctx.Done():
		return ""
	case item := <-ch:
		if len(item.names) == 0 {
			return ""
		}
		return strings.TrimSuffix(item.names[0], ".")
	}
}

func classifyRole(openPorts []int) string {
	ports := map[int]bool{}
	for _, port := range openPorts {
		ports[port] = true
	}
	switch {
	case ports[3389]:
		return "Windows remote access"
	case ports[445] || ports[139]:
		return "Windows file service"
	case ports[80] || ports[443] || ports[8080] || ports[8443]:
		return "Web service"
	case ports[22]:
		return "SSH service"
	case ports[53]:
		return "DNS service"
	default:
		return "Network service"
	}
}

func classifyRisk(openPorts []int) string {
	for _, port := range openPorts {
		switch port {
		case 3389, 445, 139, 5900:
			return "medium"
		}
	}
	return "low"
}

func newID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
