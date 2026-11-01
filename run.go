package main

import (
	"encoding/json"
	"log"
	"path/filepath"
	"time"
)

// isDue: at start always; afterwards when the server's time has come, else one interval after the last try.
func isDue(st Status, now time.Time, interval int, startup bool) bool {
	if startup {
		return true
	}
	if !st.NextDue.IsZero() {
		return !now.Before(st.NextDue)
	}
	return st.LastAttempt.IsZero() || now.Sub(st.LastAttempt) >= time.Duration(interval)*time.Second
}

// sendOnce sends the report to one server and records what came back; the next try is when the server said,
// else one interval from now (a failure waits as long as a success, so a server that is down is not hammered).
func sendOnce(c *Client, key DeviceKey, s Server, body []byte, interval int, st Status) Status {
	now := c.Now()
	o := c.Send(s.URL, s.ID, key, body, interval)
	st.LastAttempt = now
	st.LastResult = o.Result
	if o.Detail != "" {
		st.LastResult += ": " + o.Detail
	}
	if o.Result == "accepted" {
		st.LastSent = now
	}
	st.NextDue = o.Next
	if st.NextDue.IsZero() {
		st.NextDue = now.Add(time.Duration(interval) * time.Second)
	}
	return st
}

// run sends to every joined server once at start, then on schedule. The consent file and the server list are
// re-read every tick, so switching a field off or leaving a server takes effect without a restart.
func run(cfg Config, dir string, c *Client) {
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("beacon: device %s, state in %s", key.DeviceID(), dir)
	startup := true
	for {
		if fresh, err := LoadConfig(configPathOf(cfg)); err == nil {
			cfg = fresh
		}
		servers, _ := LoadServers(dir)
		st, _ := LoadStatus(dir)
		changed := false
		if len(cfg.Fields) > 0 {
			body, _ := json.Marshal(Report(cfg.Root, cfg.Fields))
			var sentTo []string
			for _, s := range servers {
				if isDue(st[s.URL], c.Now(), cfg.IntervalSeconds, startup) {
					st[s.URL] = sendOnce(c, key, s, body, cfg.IntervalSeconds, st[s.URL])
					log.Printf("%s: %s (%d fields, %d bytes)", s.Name, st[s.URL].LastResult, len(cfg.Fields), len(body))
					if st[s.URL].LastResult == "accepted" {
						sentTo = append(sentTo, s.Name)
					}
					changed = true
				}
			}
			// What left, exactly: `beacon last` shows it, so an admin can check the wire against the consent file.
			if len(sentTo) > 0 {
				_ = writeJSON(filepath.Join(dir, "last-report.json"), map[string]any{
					"sent_at": c.Now().UTC().Format(time.RFC3339), "to": sentTo, "report": json.RawMessage(body)})
			}
		}
		if changed {
			if err := SaveStatus(dir, st); err != nil {
				log.Printf("could not save status: %v", err)
			}
		}
		startup = false
		time.Sleep(5 * time.Second)
	}
}
