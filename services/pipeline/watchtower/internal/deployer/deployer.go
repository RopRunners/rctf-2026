package deployer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"watchtower/internal/config"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

const maxUnpackedBytes = 256 << 20

var ErrImageRejected = errors.New("image rejected")

var removeOpts = container.RemoveOptions{Force: true, RemoveVolumes: true}

type Deployer struct {
	cli           *client.Client
	containerName string
	dockerNet     string
	appVolume     string
	appPort       string
	registryHost  string
	registryURL   string
}

func New(cfg config.Config) (*Deployer, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Deployer{
		cli:           cli,
		containerName: cfg.AppContainer,
		dockerNet:     cfg.AppNetwork,
		appVolume:     cfg.AppVolume,
		appPort:       cfg.AppPort,
		registryHost:  cfg.RegistryHost,
		registryURL:   cfg.RegistryURL,
	}, nil
}

func (d *Deployer) CurrentDeployedRef(ctx context.Context) (string, error) {
	inspect, err := d.cli.ContainerInspect(ctx, d.containerName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("inspect %s: %w", d.containerName, err)
	}
	return inspect.Config.Image, nil
}

func (d *Deployer) CleanupStale(ctx context.Context) error {
	prefix := d.containerName + "-new-"
	list, err := d.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return fmt.Errorf("list stale containers: %w", err)
	}
	for _, c := range list {
		if !hasNamePrefix(c.Names, prefix) {
			continue
		}
		_ = d.cli.ContainerRemove(ctx, c.ID, removeOpts)
	}
	return nil
}

func hasNamePrefix(names []string, prefix string) bool {
	for _, n := range names {
		if strings.HasPrefix(strings.TrimPrefix(n, "/"), prefix) {
			return true
		}
	}
	return false
}

func (d *Deployer) Teardown(ctx context.Context) {
	if err := d.CleanupStale(ctx); err != nil {
		log.Printf("warn: teardown staging cleanup: %v", err)
	}
	id, err := d.resolveExistingID(ctx, d.containerName)
	if err != nil {
		log.Printf("warn: teardown inspect %s: %v", d.containerName, err)
		return
	}
	if id == "" {
		return
	}
	if err := d.cli.ContainerRemove(ctx, id, removeOpts); err != nil {
		log.Printf("warn: teardown remove %s: %v", d.containerName, err)
		return
	}
	log.Printf("teardown: removed %s", d.containerName)
}

func (d *Deployer) registryAuthHeader() (string, error) {
	cfg := struct {
		ServerAddress string `json:"serveraddress"`
	}{
		ServerAddress: d.registryHost,
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (d *Deployer) Deploy(ctx context.Context, repo, digest string, healthTimeout time.Duration) error {
	authHeader, err := d.registryAuthHeader()
	if err != nil {
		return fmt.Errorf("build registry auth: %w", err)
	}

	pullCtx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	rc, err := d.cli.ImagePull(pullCtx, d.imageRef(repo, digest), image.PullOptions{RegistryAuth: authHeader})
	if err != nil {
		return fmt.Errorf("image pull %s: %w", d.imageRef(repo, digest), err)
	}
	if _, err := io.Copy(io.Discard, rc); err != nil {
		rc.Close()
		return fmt.Errorf("read pull stream: %w", err)
	}
	rc.Close()

	imageRef := d.imageRef(repo, digest)
	if insp, err := d.cli.ImageInspect(ctx, imageRef); err != nil {
		log.Printf("warn: inspect pulled image %s: %v", digest, err)
	} else if insp.Size > maxUnpackedBytes {
		if _, rmErr := d.cli.ImageRemove(ctx, imageRef, image.RemoveOptions{PruneChildren: true}); rmErr != nil {
			log.Printf("warn: remove oversized image %s: %v", digest, rmErr)
		}
		return fmt.Errorf("%w: unpacks to %d bytes, limit is %d", ErrImageRejected, insp.Size, maxUnpackedBytes)
	}

	shortDigest := strings.TrimPrefix(digest, "sha256:")
	if len(shortDigest) > 12 {
		shortDigest = shortDigest[:12]
	}
	stagingName := fmt.Sprintf("%s-new-%s", d.containerName, shortDigest)

	containerCfg := &container.Config{
		Image: d.imageRef(repo, digest),
	}
	pidsLimit := int64(100)
	memory := int64(128 * 1024 * 1024)
	hostCfg := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: d.appVolume,
				Target: "/data",
			},
		},
		CapDrop:         []string{"ALL"},
		SecurityOpt:     []string{"no-new-privileges:true"},
		RestartPolicy:   container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		PublishAllPorts: false,
		NetworkMode:     container.NetworkMode(d.dockerNet),
		ReadonlyRootfs:  true,
		Tmpfs:           map[string]string{"/tmp": "rw,noexec,nosuid,size=32m"},
		LogConfig: container.LogConfig{
			Type:   "json-file",
			Config: map[string]string{"max-size": "10m", "max-file": "2"},
		},
		Resources: container.Resources{
			Memory:     memory,
			MemorySwap: memory,
			NanoCPUs:   500_000_000,
			PidsLimit:  &pidsLimit,
			Ulimits: []*container.Ulimit{
				{Name: "nofile", Soft: 4096, Hard: 4096},
			},
		},
	}
	netCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			d.dockerNet: {},
		},
	}

	created, err := d.cli.ContainerCreate(ctx, containerCfg, hostCfg, netCfg, nil, stagingName)
	if err != nil {
		return fmt.Errorf("create staging container: %w", err)
	}
	stagingID := created.ID

	if err := d.cli.ContainerStart(ctx, stagingID, container.StartOptions{}); err != nil {
		d.forceRemove(stagingID)
		return fmt.Errorf("start staging container: %w", err)
	}

	if err := d.waitHealthy(ctx, stagingName, healthTimeout); err != nil {
		d.forceRemove(stagingID)
		return fmt.Errorf("staging container failed health check, rolled back: %w", err)
	}

	if oldID, err := d.resolveExistingID(ctx, d.containerName); err == nil && oldID != "" {
		timeout := 2
		_ = d.cli.ContainerStop(ctx, oldID, container.StopOptions{Timeout: &timeout})
		_ = d.cli.ContainerRemove(ctx, oldID, removeOpts)
	}
	if err := d.cli.ContainerRename(ctx, stagingID, d.containerName); err != nil {
		return fmt.Errorf("CRITICAL: renamed staging container failed after old was removed: %w", err)
	}

	d.PruneImages(ctx, repo, digest)
	return nil
}

func (d *Deployer) PruneImages(ctx context.Context, repo, keepDigest string) {
	keepRef := d.imageRef(repo, keepDigest)
	prefix := fmt.Sprintf("%s/%s@", d.registryHost, repo)

	imgs, err := d.cli.ImageList(ctx, image.ListOptions{All: true})
	if err != nil {
		log.Printf("warn: prune list images: %v", err)
		return
	}
	for _, im := range imgs {
		for _, rd := range im.RepoDigests {
			if !strings.HasPrefix(rd, prefix) || rd == keepRef {
				continue
			}
			if _, err := d.cli.ImageRemove(ctx, rd, image.RemoveOptions{PruneChildren: true}); err != nil {
				log.Printf("warn: prune image %s: %v", rd, err)
			} else {
				log.Printf("pruned old image %s", rd)
			}
			break
		}
	}
}

func (d *Deployer) resolveExistingID(ctx context.Context, name string) (string, error) {
	insp, err := d.cli.ContainerInspect(ctx, name)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return insp.ID, nil
}

func (d *Deployer) forceRemove(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.cli.ContainerRemove(ctx, id, removeOpts)
}

func (d *Deployer) waitHealthy(ctx context.Context, stagingName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://%s:%s/healthz", stagingName, d.appPort)
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(300 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("healthz returned status %d", resp.StatusCode)
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for healthy: %w", lastErr)
}

func (d *Deployer) imageRef(repo, digest string) string {
	return fmt.Sprintf("%s/%s@%s", d.registryHost, repo, digest)
}
