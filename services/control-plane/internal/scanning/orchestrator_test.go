package scanning

import (
	"net"
	"testing"
	"time"

	"ravynel-control-plane/internal/store"
)

func TestNetworkScanDiscoversReachableAsset(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	oldPorts := commonTCPPorts
	commonTCPPorts = []int{port}
	defer func() { commonTCPPorts = oldPorts }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	repo := store.NewMemoryRepository()
	orchestrator := NewOrchestrator(repo)
	orchestrator.StartNetworkScan("127.0.0.1")

	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatalf("scan did not complete; scans=%+v assets=%+v", repo.ListScans(), repo.ListAssets())
		case <-ticker.C:
			scans := repo.ListScans()
			if len(scans) == 0 || scans[0].Status != store.ScanDone {
				continue
			}
			assets := repo.ListAssets()
			if len(assets) != 1 {
				t.Fatalf("expected one discovered asset, got %+v", assets)
			}
			if assets[0].IP != "127.0.0.1" {
				t.Fatalf("expected localhost asset, got %+v", assets[0])
			}
			if len(assets[0].OpenPorts) != 1 || assets[0].OpenPorts[0] != port {
				t.Fatalf("expected discovered port %d, got %+v", port, assets[0].OpenPorts)
			}
			return
		}
	}
}
