package grpcserver

import (
	"net"
	"time"

	"google.golang.org/grpc"
	"ravynel-control-plane/internal/scanning"
	"ravynel-control-plane/internal/store"
)

func New(repo store.Repository, orchestrator *scanning.Orchestrator) *grpc.Server {
	_ = repo
	_ = orchestrator
	server := grpc.NewServer()
	return server
}

func TouchAgent(repo store.Repository, id string, hostname string, version string) store.Agent {
	return repo.UpsertAgent(store.Agent{ID: id, Hostname: hostname, Version: version, LastSeen: time.Now().UTC()})
}

func ServeHealth(listener net.Listener) error {
	server := grpc.NewServer()
	return server.Serve(listener)
}
