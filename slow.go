package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// slowFields change rarely and weigh a lot (a package list is tens of kilobytes), so they are not resent every call-in:
// a report leaves one out and says so ("unchanged"), and the server keeps the value from the previous report. They go in
// full at start, whenever they change, and at least once an hour.
var slowFields = map[string]bool{"packages": true}

const slowEvery = time.Hour

type slowSent struct {
	hash string
	at   time.Time
}

// slowState remembers, per server and field, what was last sent in full and when. In memory only: after a restart every
// slow field goes out in full once, so a server that lost it is never left without.
type slowState map[string]map[string]slowSent

func hashOf(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// BodyFor is the report for one server: the whole report, except slow fields it already has and that have not changed,
// which are named in "unchanged" instead. It returns the bytes and the slow fields sent in full, which the caller records
// once the server has accepted the report.
func (st slowState) BodyFor(server string, report map[string]any, now time.Time) (body []byte, sentFull map[string]string) {
	out := map[string]any{}
	var unchanged []string
	sentFull = map[string]string{}
	for k, v := range report {
		if !slowFields[k] {
			out[k] = v
			continue
		}
		h := hashOf(v)
		prev, known := st[server][k]
		if known && prev.hash == h && now.Sub(prev.at) < slowEvery {
			unchanged = append(unchanged, k)
			continue
		}
		out[k] = v
		sentFull[k] = h
	}
	if len(unchanged) > 0 {
		sort.Strings(unchanged)
		out["unchanged"] = unchanged
	}
	body, _ = json.Marshal(out)
	return body, sentFull
}

// Record notes that the server accepted these slow fields in full.
func (st slowState) Record(server string, sentFull map[string]string, now time.Time) {
	if st[server] == nil {
		st[server] = map[string]slowSent{}
	}
	for k, h := range sentFull {
		st[server][k] = slowSent{hash: h, at: now}
	}
}
