package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ravynel-control-plane/internal/api"
	"ravynel-control-plane/internal/grpcserver"
	"ravynel-control-plane/internal/scanning"
	"ravynel-control-plane/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	repository := store.NewMemoryRepository()
	orchestrator := scanning.NewOrchestrator(repository)
	go func() {
		listener, err := net.Listen("tcp", env("RAVYNEL_GRPC_ADDR", ":9443"))
		if err != nil {
			log.Printf("grpc listener failed: %v", err)
			return
		}
		server := grpcserver.New(repository, orchestrator)
		log.Printf("Ravynel agent gRPC listening on %s", listener.Addr())
		if err := server.Serve(listener); err != nil {
			log.Printf("grpc stopped: %v", err)
		}
	}()
	httpAddr := env("RAVYNEL_HTTP_ADDR", "0.0.0.0:8088")
	httpServer := api.New(repository, orchestrator)
	go func() {
		log.Printf("Ravynel control plane listening on http://%s", httpAddr)
		if err := httpServer.Run(httpAddr); err != nil {
			log.Printf("http stopped: %v", err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	orchestrator.Shutdown(shutdownCtx)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
