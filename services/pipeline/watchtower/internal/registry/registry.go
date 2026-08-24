package registry

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"watchtower/internal/config"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Client struct {
	host string // host:port
	repo string
}

func New(cfg config.Config) (*Client, error) {
	u, err := url.Parse(cfg.RegistryURL)
	if err != nil {
		return nil, fmt.Errorf("parse ZOT_URL: %w", err)
	}

	host := u.Host
	if host == "" {
		host = strings.TrimPrefix(strings.TrimPrefix(cfg.RegistryURL, "http://"), "https://")
	}

	return &Client{
		host: host,
		repo: cfg.Repo,
	}, nil
}

func (c *Client) Resolve(tag string) (string, int64, error) {
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", c.host, c.repo, tag), name.Insecure)
	if err != nil {
		return "", 0, fmt.Errorf("parse tag ref: %w", err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return "", 0, fmt.Errorf("resolve tag: %w", err)
	}
	digest := desc.Digest.String()

	img, err := desc.Image()
	if err != nil {
		return digest, 0, fmt.Errorf("read image %s: %w", digest, err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return digest, 0, fmt.Errorf("read manifest %s: %w", digest, err)
	}

	size := manifest.Config.Size
	if size < 0 {
		return digest, 0, fmt.Errorf("manifest %s declares negative config size %d", digest, size)
	}
	for i, layer := range manifest.Layers {
		if layer.Size < 0 {
			return digest, 0, fmt.Errorf("manifest %s layer %d declares negative size %d", digest, i, layer.Size)
		}
		if size > math.MaxInt64-layer.Size {
			return digest, 0, fmt.Errorf("manifest %s declares layer sizes that overflow int64", digest)
		}
		size += layer.Size
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return digest, 0, fmt.Errorf("read config %s: %w", digest, err)
	}
	if len(cfgFile.Config.Volumes) > 0 {
		declared := make([]string, 0, len(cfgFile.Config.Volumes))
		for v := range cfgFile.Config.Volumes {
			declared = append(declared, v)
		}
		sort.Strings(declared)
		return digest, 0, fmt.Errorf("image %s declares volumes %v", digest, declared)
	}

	return digest, size, nil
}
