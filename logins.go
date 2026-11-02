package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// logins: who has a session open on this machine right now, as a flat set. A session is where somebody is logged in: an ssh
// connection, a console, a desktop. Each one says who (user), from where (source: the remote address of an ssh login, empty at the
// machine's own keyboard or console), on which terminal (tty) and since when. Nothing is run: systemd-logind keeps one small file
// per session in /run/systemd/sessions, and those are read. (The files say "private data, do not parse": the keys read here have been
// stable for years, and a release that changes them makes this field say nothing rather than something wrong: a session without a
// USER is skipped, and a machine with no readable session files falls back to utmp.) Where logind is not there (Alpine, containers of their own), the
// login records in /var/run/utmp are read instead; they are kept by the same programs but can outlive a crash, so logind wins.
//
// The report is the set and nothing else: the server tells a new login from a logout by comparing this report with the last one,
// and each session's id (tty and start time) stays the same for as long as it lasts, so the same session reported twice is one.

// maxSessions bounds a report: a machine with a login flood reports this many and says it dropped the rest.
const maxSessions = 50

// maxName bounds the text taken from a file, so a hostile account or host name cannot make the report large.
const maxName = 64

type session struct {
	user, source, tty, kind string
	since                   int64
	// no is logind's number for the session (the file's name): the identity of one with no terminal (ssh running a single command),
	// which would otherwise be told apart from another of the same person only by the second it began in.
	no string
}

// clean keeps printable text only and bounds it: a name comes from a file anyone with an account can influence.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= maxName {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func logins(root string) (any, bool) {
	sessions, ok := logindSessions(root)
	if !ok {
		sessions, ok = utmpSessions(root)
	}
	if !ok {
		return nil, false // neither source here: say nothing, not "nobody"
	}
	// One entry per session, whatever the source said twice.
	byID := map[string]session{}
	for _, s := range sessions {
		byID[sessionID(s)] = s
	}
	all := make([]session, 0, len(byID))
	for _, s := range byID {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { // stable between reports, so an unchanged set is an unchanged report
		if all[i].since != all[j].since {
			return all[i].since < all[j].since
		}
		return sessionID(all[i]) < sessionID(all[j])
	})
	out := map[string]any{"count": len(all)}
	if len(all) > maxSessions {
		all = all[:maxSessions]
		out["truncated"] = true
	}
	rows := make([]map[string]any, 0, len(all))
	for _, s := range all {
		row := map[string]any{"id": sessionID(s), "user": s.user, "since": s.since}
		if s.tty != "" {
			row["tty"] = s.tty
		}
		if s.source != "" {
			row["source"] = s.source
		}
		if s.kind != "" {
			row["type"] = s.kind
		}
		rows = append(rows, row)
	}
	out["sessions"] = rows
	return out, true
}

func sessionID(s session) string {
	where := s.tty
	if where == "" && s.no != "" {
		where = "#" + s.no
	}
	return s.user + "@" + where + "@" + strconv.FormatInt(s.since, 10)
}

// logindSessions reads /run/systemd/sessions/<id>: KEY=value lines. Only sessions of people count (CLASS=user), and one that is
// closing is already gone.
func logindSessions(root string) ([]session, bool) {
	dir := filepath.Join(root, "run/systemd/sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	out := []session{}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".ref") || strings.HasPrefix(e.Name(), ".") {
			continue // "<id>.ref" is logind's own bookkeeping
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(b) > 16*1024 {
			continue
		}
		kv := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[k] = v
			}
		}
		if kv["USER"] == "" || (kv["CLASS"] != "" && kv["CLASS"] != "user") || kv["STATE"] == "closing" {
			continue
		}
		s := session{user: clean(kv["USER"]), tty: clean(kv["TTY"]), kind: clean(kv["TYPE"]), no: clean(e.Name())}
		if kv["REMOTE"] == "1" {
			s.source = clean(kv["REMOTE_HOST"])
		}
		if us, err := strconv.ParseInt(kv["REALTIME"], 10, 64); err == nil {
			s.since = us / 1_000_000 // logind keeps microseconds
		}
		if s.user != "" {
			out = append(out, s)
		}
	}
	return out, true
}

// utmpSessions reads the login records of glibc's struct utmp (384 bytes each on 64-bit Linux): a record of type USER_PROCESS (7)
// is a login. A file of any other shape (musl keeps none, a 32-bit layout is a different size) says nothing.
func utmpSessions(root string) ([]session, bool) {
	b, err := os.ReadFile(filepath.Join(root, "var/run/utmp"))
	if err != nil || len(b) == 0 || len(b)%utmpSize != 0 || len(b) > utmpSize*4096 {
		return nil, false
	}
	str := func(rec []byte) string {
		if i := strings.IndexByte(string(rec), 0); i >= 0 {
			rec = rec[:i]
		}
		return string(rec)
	}
	out := []session{}
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		r := b[off : off+utmpSize]
		if binary.LittleEndian.Uint32(r[0:4]) != 7 {
			continue
		}
		s := session{tty: clean(str(r[8:40])), user: clean(str(r[44:76])), source: clean(str(r[76:332])),
			since: int64(int32(binary.LittleEndian.Uint32(r[340:344])))}
		if s.user != "" {
			out = append(out, s)
		}
	}
	return out, true
}

const utmpSize = 384
