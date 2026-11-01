package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the owner's consent, in a file only root can change (/etc/beacon/beacon.json): which fields are
// sent and how often. Nothing is on unless it is listed. The reporter itself never writes this file.
type Config struct {
	Fields          []string `json:"fields"`
	IntervalSeconds int      `json:"interval_seconds"`
	// Root is where the machine's files are read from: "/" normally, "/host" in a container.
	Root string `json:"root"`

	path string // where it was read from, so the run loop can re-read it
}

func configPathOf(c Config) string { return c.path }

const (
	minInterval     = 30
	maxInterval     = 3600
	defaultInterval = 30
)

func LoadConfig(path string) (Config, error) {
	c := Config{IntervalSeconds: defaultInterval, Root: "/", path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil // no file: nothing switched on
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	known := map[string]bool{}
	for _, f := range Fields {
		known[f.ID] = true
	}
	for _, id := range c.Fields {
		if !known[id] {
			return c, fmt.Errorf("%s: unknown field %q (beacon fields lists them)", path, id)
		}
	}
	if c.IntervalSeconds < minInterval {
		c.IntervalSeconds = minInterval
	}
	if c.IntervalSeconds > maxInterval {
		c.IntervalSeconds = maxInterval
	}
	if c.Root == "" {
		c.Root = "/"
	}
	return c, nil
}

// Server is a place reports go, as `beacon join` recorded it. The join secret is not kept.
type Server struct {
	URL  string `json:"url"`
	ID   string `json:"server_id"`
	Name string `json:"name"`
}

// Status is what the run loop last saw per server; it alone writes it.
type Status struct {
	LastResult  string    `json:"last_result"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSent    time.Time `json:"last_sent"`
	NextDue     time.Time `json:"next_due"`
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON replaces the file in one step (write, then rename), so a reader never sees half of it.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	handOver(path)
	return nil
}

func LoadServers(dir string) ([]Server, error) {
	var s []Server
	return s, readJSON(filepath.Join(dir, "servers.json"), &s)
}

func SaveServers(dir string, s []Server) error {
	return writeJSON(filepath.Join(dir, "servers.json"), s)
}

func LoadStatus(dir string) (map[string]Status, error) {
	s := map[string]Status{}
	return s, readJSON(filepath.Join(dir, "status.json"), &s)
}

func SaveStatus(dir string, s map[string]Status) error {
	return writeJSON(filepath.Join(dir, "status.json"), s)
}
