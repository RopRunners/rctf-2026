package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	RegistryHost  string
	RegistryURL   string
	Repo          string
	Tag           string
	AppContainer  string
	AppNetwork    string
	AppVolume     string
	AppPort       string
	PollInterval  time.Duration
	DeployTimeout time.Duration
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "fatal: required env %s is empty\n", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (Config, error) {
	c := Config{
		RegistryHost: mustEnv("REGISTRY_HOST"),
		RegistryURL:  mustEnv("REGISTRY_URL"),
		Repo:         envOr("REPO", "pipeline/app"),
		Tag:          envOr("TAG", "latest"),
		AppContainer: envOr("APP_CONTAINER", "pipeline-app"),
		AppNetwork:   envOr("APP_NETWORK", "pipeline"),
		AppVolume:    envOr("FLAG_VOLUME", "pipeline_app"),
		AppPort:      envOr("APP_PORT", "8080"),
	}

	pollStr := envOr("POLL_INTERVAL", "2s")
	poll, err := time.ParseDuration(pollStr)
	if err != nil {
		return Config{}, fmt.Errorf("bad POLL_INTERVAL %q: %w", pollStr, err)
	}
	c.PollInterval = poll

	deployStr := envOr("DEPLOY_TIMEOUT", "8s")
	deploy, err := time.ParseDuration(deployStr)
	if err != nil {
		return Config{}, fmt.Errorf("bad DEPLOY_TIMEOUT %q: %w", deployStr, err)
	}
	c.DeployTimeout = deploy

	return c, nil
}
