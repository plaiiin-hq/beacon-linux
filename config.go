package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// SaveFields sets the "fields" list in the consent file and leaves everything else in it as it was (the interval, the
// root, anything the admin added). It replaces the file in one step. Only root can do this: the file is root's, and the
// service, which runs as its own user, can read it but never write it.
func SaveFields(path string, fields []string) error {
	known := map[string]bool{}
	for _, f := range Fields {
		known[f.ID] = true
	}
	for _, id := range fields {
		if !known[id] {
			return fmt.Errorf("unknown field %q (beacon fields lists them)", id)
		}
	}
	raw := map[string]json.RawMessage{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	sort.Strings(fields)
	list, _ := json.Marshal(fields)
	raw["fields"] = list
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil {
		return friendly(path, err)
	}
	return friendly(path, os.Rename(tmp, path))
}

func friendly(path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("cannot write %s: the consent file belongs to root, so run this with sudo", path)
	}
	return err
}

// Toggle returns the field list after switching ids on or off. "all" means every field this version knows; it is
// written out as that explicit list, so a later version's new fields stay off until the admin switches them on.
func Toggle(current, ids []string, on bool) ([]string, error) {
	want := map[string]bool{}
	for _, id := range ids {
		if id == "all" {
			for _, f := range Fields {
				want[f.ID] = true
			}
			continue
		}
		ok := false
		for _, f := range Fields {
			if f.ID == id {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown field %q (beacon fields lists them, or use \"all\")", id)
		}
		want[id] = true
	}
	set := map[string]bool{}
	for _, id := range current {
		set[id] = true
	}
	for id := range want {
		set[id] = on
	}
	var out []string
	for id, v := range set {
		if v {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}
