package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/eyupio/zoomies/internal/backend"
	"github.com/eyupio/zoomies/internal/config"
	"github.com/eyupio/zoomies/internal/installer"
	"github.com/eyupio/zoomies/internal/store"
)

// installerJoin is installer.Join, a variable so that a test can read what the
// flags became without the join probing the real host's container runtimes.
var installerJoin = installer.Join

// prepareVMPalAgent settles what VM isolation implies, before validation reads it.
//
// This process is `zoomies agent`, so it is not an embedded agent whatever the
// default says; the validator refuses vmpal on an embedded agent because a
// controller would build its backends without asking about isolation. The
// backend kind is process because that is the kind the VM backend registers as,
// and a default of docker would name a backend this registry does not hold.
func prepareVMPalAgent(cfg *config.Config) {
	if cfg.Agent.ProcessIsolation != config.ProcessIsolationVMPal {
		return
	}
	cfg.Agent.Embedded = false
	cfg.Agent.Backend = string(store.BackendProcess)
}

// buildAgentBackends is the standalone agent's registry. With VM isolation it
// holds the VM backend and nothing else: Docker, Podman or the bare process
// backend beside it would each be a way for a job to run on the Mac itself.
func buildAgentBackends(ctx context.Context, cfg *config.Config, log *slog.Logger) (*backend.Registry, error) {
	if cfg.Agent.ProcessIsolation != config.ProcessIsolationVMPal {
		return buildBackends(ctx, cfg, log)
	}
	reg, err := backend.NewVMPalRegistry(installer.VMPalBackendOptions(cfg, log))
	if err != nil {
		return nil, err
	}
	// An unavailable backend is not a reason to stop: the agent reports it on
	// the Hosts page and probes again, and it starts no clone meanwhile.
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, info := range reg.Probe(probeCtx) {
		if info.Available {
			log.Info("VM backend available", "endpoint", info.Endpoint)
		} else {
			log.Warn("VM backend not available", "detail", info.Detail)
		}
	}
	return reg, nil
}
