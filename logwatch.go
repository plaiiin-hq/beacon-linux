package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Privilege separation for the recent logins. The Beacon that talks to the server is confined so that it cannot read /var/log at
// all, and sshd's log is readable only by the group adm anyway. Rather than loosen the one process that has the network, a second
// one reads the log: `beacon logwatch`, run by its own unit as its own account, with no network, seeing only auth.log and wtmp
// of /var/log. It writes the few parsed fields (who, from where, when, how) to a small file; the Beacon reads that file and never
// the log. So a flaw in the Beacon cannot read the log, and a flaw in the log reader has nowhere to send anything.
//
// The reader is idle until an admin has switched the logins field on: with it off it reads nothing and removes its file.

// helperFile is where the log reader leaves its answer, relative to the root the Beacon looks at.
const helperFile = "run/beacon-logs/recent.json"

// helperFresh is how old an answer may be and still be believed: the reader updates it every 30 s.
const helperFresh = 150 * time.Second

type helperDoc struct {
	At       int64          `json:"at"`
	Coverage string         `json:"coverage"`
	Recent   []helperRecent `json:"recent"`
}

type helperRecent struct {
	User   string `json:"user"`
	Source string `json:"source,omitempty"`
	Via    string `json:"via,omitempty"`
	TTY    string `json:"tty,omitempty"`
	PID    string `json:"pid,omitempty"`
	At     int64  `json:"at"`
	Ended  int64  `json:"ended,omitempty"`
}

// logwatchOnce is one turn of the log reader: read the logs when logins is switched on, else leave nothing behind.
func logwatchOnce(cfg Config, outDir string, now time.Time) error {
	path := filepath.Join(outDir, "recent.json")
	if !slices.Contains(cfg.Fields, "logins") {
		_ = os.Remove(path)
		return nil
	}
	coverage, rows := recentFromLogs(cfg.Root)
	doc := helperDoc{At: now.Unix(), Coverage: coverage, Recent: make([]helperRecent, 0, len(rows))}
	for _, r := range rows {
		doc.Recent = append(doc.Recent, helperRecent{User: r.user, Source: r.source, Via: r.via, TTY: r.tty, PID: r.pid, At: r.at, Ended: r.ended})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path) // whole or not at all: the Beacon never reads half an answer
}

// logwatch runs until stopped.
func logwatch(cfg Config, outDir string) {
	log.Printf("beacon logwatch: writing the parsed ssh logins to %s while logins is switched on", outDir)
	for {
		if fresh, err := LoadConfig(configPathOf(cfg)); err == nil {
			cfg = fresh
		}
		if err := logwatchOnce(cfg, outDir, time.Now()); err != nil {
			log.Printf("beacon logwatch: %v", err)
		}
		time.Sleep(30 * time.Second)
	}
}

// recentFromHelper reads what the log reader left. It is believed only when it is recent, small and well formed, and every string in
// it is cleaned again: the file is written by another process, so it is input like any other.
func recentFromHelper(root string, now time.Time) (string, []recent, bool) {
	path := filepath.Join(root, helperFile)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return "", nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, false
	}
	var doc helperDoc
	if json.Unmarshal(b, &doc) != nil || now.Sub(time.Unix(doc.At, 0)) > helperFresh || doc.At > now.Unix()+60 {
		return "", nil, false
	}
	switch doc.Coverage {
	case "auth.log", "wtmp", "snapshot":
	default:
		return "", nil, false
	}
	rows := []recent{}
	for _, r := range doc.Recent {
		if len(rows) >= maxRecent {
			break
		}
		if u := clean(r.User); u != "" && r.At > 0 {
			rows = append(rows, recent{user: u, source: clean(r.Source), via: clean(r.Via), tty: clean(r.TTY), pid: clean(r.PID), at: r.At, ended: r.Ended})
		}
	}
	return doc.Coverage, rows, true
}
