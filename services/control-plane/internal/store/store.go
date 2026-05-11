package store

import (
	"sort"
	"sync"
	"time"
)

type ScanStatus string

const (
	ScanQueued   ScanStatus = "queued"
	ScanRunning  ScanStatus = "running"
	ScanDone     ScanStatus = "completed"
	ScanFailed   ScanStatus = "failed"
	ScanCanceled ScanStatus = "canceled"
)

type Scan struct {
	ID        string     `json:"id"`
	Range     string     `json:"range"`
	Status    ScanStatus `json:"status"`
	Progress  int        `json:"progress"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type Agent struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	Version  string    `json:"version"`
	LastSeen time.Time `json:"last_seen"`
}

type Asset struct {
	ID           string    `json:"id"`
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Role         string    `json:"role"`
	Risk         string    `json:"risk"`
	Status       string    `json:"status"`
	OpenPorts    []int     `json:"open_ports"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SourceScanID string    `json:"source_scan_id"`
}

type Repository interface {
	CreateScan(scan Scan) Scan
	UpdateScan(scan Scan) Scan
	ListScans() []Scan
	GetScan(id string) (Scan, bool)
	UpsertAgent(agent Agent) Agent
	ListAgents() []Agent
	UpsertAsset(asset Asset) Asset
	ListAssets() []Asset
}

type MemoryRepository struct {
	mu     sync.RWMutex
	scans  map[string]Scan
	agents map[string]Agent
	assets map[string]Asset
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{scans: map[string]Scan{}, agents: map[string]Agent{}, assets: map[string]Asset{}}
}

func (r *MemoryRepository) CreateScan(scan Scan) Scan {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scans[scan.ID] = scan
	return scan
}

func (r *MemoryRepository) UpdateScan(scan Scan) Scan {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scans[scan.ID] = scan
	return scan
}

func (r *MemoryRepository) ListScans() []Scan {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rows := make([]Scan, 0, len(r.scans))
	for _, scan := range r.scans {
		rows = append(rows, scan)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	return rows
}

func (r *MemoryRepository) GetScan(id string) (Scan, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	scan, ok := r.scans[id]
	return scan, ok
}

func (r *MemoryRepository) UpsertAgent(agent Agent) Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[agent.ID] = agent
	return agent
}

func (r *MemoryRepository) ListAgents() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rows := make([]Agent, 0, len(r.agents))
	for _, agent := range r.agents {
		rows = append(rows, agent)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LastSeen.After(rows[j].LastSeen) })
	return rows
}

func (r *MemoryRepository) UpsertAsset(asset Asset) Asset {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.assets[asset.ID]; ok && !existing.FirstSeen.IsZero() {
		asset.FirstSeen = existing.FirstSeen
	}
	r.assets[asset.ID] = asset
	return asset
}

func (r *MemoryRepository) ListAssets() []Asset {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rows := make([]Asset, 0, len(r.assets))
	for _, asset := range r.assets {
		rows = append(rows, asset)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LastSeen.After(rows[j].LastSeen) })
	return rows
}
