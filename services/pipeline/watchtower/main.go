package main

import (
	"context"
	"errors"
	"log"
	"os/signal"
	"syscall"
	"time"

	"watchtower/internal/config"
	"watchtower/internal/deployer"
	"watchtower/internal/registry"
)

const maxImageBytes = 64 << 20

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// init services
	reg, err := registry.New(cfg)
	if err != nil {
		log.Fatalf("registry client: %v", err)
	}

	dep, err := deployer.New(cfg)
	if err != nil {
		log.Fatalf("deployer: %v", err)
	}
	//

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Remove any leftover staging containers
	if err := dep.CleanupStale(ctx); err != nil {
		log.Printf("warn: cleanup stale staging containers: %v", err)
	}
	//

	// Retrieve info about already deployed containers
	deployedDigest := ""
	if ref, err := dep.CurrentDeployedRef(ctx); err != nil {
		log.Printf("warn: could not inspect existing %s: %v", cfg.AppContainer, err)
	} else if ref != "" {
		if d := digestFromRef(ref); d != "" {
			deployedDigest = d
			log.Printf("startup: %s already running at %s", cfg.AppContainer, deployedDigest)
			dep.PruneImages(ctx, cfg.Repo, deployedDigest)
		}
	}
	//

	log.Printf("watchtower up: repo=%s tag=%s poll=%s deploy_timeout=%s",
		cfg.Repo, cfg.Tag, cfg.PollInterval, cfg.DeployTimeout)

	// Main loop
	rejectedDigest := ""
	lastResolveErr := ""
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			dep.Teardown(cleanupCtx)
			cancel()
			return
		case <-ticker.C:
			runOnce(ctx, cfg, reg, dep, &deployedDigest, &rejectedDigest, &lastResolveErr)
		}
	}
	//
}

func runOnce(
	ctx context.Context,
	cfg config.Config,
	reg *registry.Client,
	dep *deployer.Deployer,
	deployedDigest *string,
	rejectedDigest *string,
	lastResolveErr *string,
) {
	digest, size, err := reg.Resolve(cfg.Tag)
	if err != nil {
		if msg := err.Error(); msg != *lastResolveErr {
			log.Printf("resolve %s:%s: %v", cfg.Repo, cfg.Tag, err)
			*lastResolveErr = msg
		}
		return
	}
	*lastResolveErr = ""
	if digest == *deployedDigest {
		return // nothing new
	}
	if digest == *rejectedDigest {
		return
	}
	if size > maxImageBytes {
		log.Printf("REJECT %s: image declares %d bytes, limit is %d", digest, size, maxImageBytes)
		*rejectedDigest = digest
		return
	}
	log.Printf("new digest for %s:%s -> %s (currently deployed: %s)", cfg.Repo, cfg.Tag, digest, *deployedDigest)

	deployCtx, cancel := context.WithTimeout(ctx, 2*cfg.DeployTimeout+5*time.Second)
	defer cancel()
	if err := dep.Deploy(deployCtx, cfg.Repo, digest, cfg.DeployTimeout); err != nil {
		log.Printf("REJECT %s: deploy failed, rolled back: %v", digest, err)
		if errors.Is(err, deployer.ErrImageRejected) {
			*rejectedDigest = digest
		}
		return // leave old app running
	}

	*deployedDigest = digest
	log.Printf("DEPLOYED %s -> %s", cfg.AppContainer, digest)
}

func digestFromRef(ref string) string {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == '@' {
			return ref[i+1:]
		}
	}
	return ""
}
