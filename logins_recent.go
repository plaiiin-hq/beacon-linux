package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Recent logins: the live set in logins.go is a snapshot, so a session that begins and ends between two reports (ssh running one
// command) is never in it. This reads what the system wrote down about logins as they happened, and says how much of the picture that
// gives. Best effort, in order of how much it sees:
//
//	"auth.log"  every ssh login, from sshd's own log (Debian and Ubuntu with rsyslog)   var/log/auth.log
//	"wtmp"      logins that had a terminal, from the system's login history           var/log/wtmp
//	"snapshot"  neither is here: only what is open at the moment of a report
//
// Cost is bounded by construction. A log is read from where the last read stopped, never again from the start; a line is skipped by a
// byte search before anything is parsed; and one read takes at most maxRead bytes, so a log flooded by a password-guessing run costs the
// same as a quiet one (the rest of that flood is skipped, and the next read starts at the end). The first read looks at the last
// firstRead bytes only. What was found is kept in memory, at most maxRecent entries, newest last.

const (
	maxRecent = 30
	maxRead   = 1 << 20   // the most one report reads from a log
	firstRead = 256 << 10 // how far back the first read looks
)

type recent struct {
	user, source, via, tty, pid string
	at, ended                   int64
}

var recentState struct {
	sync.Mutex
	path    string
	info    os.FileInfo
	off     int64
	entries []recent
}

// recentLogins returns the coverage level and the logins found, oldest first.
func recentLogins(root string) (string, []recent) {
	if rows, ok := readLog(filepath.Join(root, "var/log/auth.log"), parseAuthLog); ok {
		return "auth.log", rows
	}
	if rows, ok := readLog(filepath.Join(root, "var/log/wtmp"), parseWtmp); ok {
		return "wtmp", rows
	}
	return "snapshot", nil
}

// readLog reads what is new in path since the last time, hands it to parse and returns everything kept so far.
func readLog(path string, parse func(data []byte, add func(recent), end func(pid, tty string, at int64))) ([]recent, bool) {
	recentState.Lock()
	defer recentState.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	if recentState.path != path {
		recentState.path, recentState.info, recentState.off, recentState.entries = path, nil, 0, nil
	}
	size := info.Size()
	switch {
	case recentState.info == nil:
		recentState.off = max(0, size-firstRead) // the first look: only the recent end
	case !os.SameFile(recentState.info, info) || size < recentState.off:
		recentState.off = 0 // rotated or truncated: the new file from its start
	}
	recentState.info = info
	if size-recentState.off > maxRead {
		recentState.off = size - maxRead // a flood: skip to the last maxRead bytes
	}
	if size > recentState.off {
		buf := make([]byte, size-recentState.off)
		n, _ := io.ReadFull(io.NewSectionReader(f, recentState.off, int64(len(buf))), buf)
		buf = buf[:n]
		consumed := int64(n)
		if strings.HasSuffix(path, "wtmp") {
			consumed -= consumed % utmpSize // whole records only
			buf = buf[:consumed]
		} else if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			consumed, buf = int64(i+1), buf[:i+1] // whole lines only: a half-written one is read next time
		} else {
			consumed, buf = 0, nil
		}
		parse(buf, func(r recent) {
			recentState.entries = append(recentState.entries, r)
			if len(recentState.entries) > maxRecent {
				recentState.entries = recentState.entries[len(recentState.entries)-maxRecent:]
			}
		}, func(pid, tty string, at int64) {
			for i := len(recentState.entries) - 1; i >= 0; i-- {
				e := &recentState.entries[i]
				if e.ended == 0 && ((pid != "" && e.pid == pid) || (pid == "" && tty != "" && e.tty == tty)) {
					e.ended = at
					return
				}
			}
		})
		recentState.off += consumed
	}
	return append([]recent(nil), recentState.entries...), true
}

var (
	sshdTag  = []byte("sshd[")
	accepted = []byte("Accepted ")
	closedS  = []byte("session closed for user ")
)

// parseAuthLog finds, in sshd's lines, a login ("Accepted publickey for root from 203.0.113.9 port 51234 ssh2") and the end of its
// session ("session closed for user root"), which carries the same sshd process number. Both the traditional stamp (Nov  2 09:23:58)
// and the ISO one (2026-11-02T09:23:58.123+01:00) are read; the traditional one has no year and no zone, so it is taken in this
// machine's zone and the current year, which is right unless the Beacon runs in a container set to another zone.
func parseAuthLog(data []byte, add func(recent), end func(pid, tty string, at int64)) {
	now := time.Now()
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		k := bytes.Index(line, sshdTag) // the cheap test that skips nearly every line
		if k < 0 {
			continue
		}
		rest := line[k+len(sshdTag):]
		j := bytes.IndexByte(rest, ']')
		if j < 0 || j > 10 {
			continue
		}
		pid, msg := string(rest[:j]), strings.TrimPrefix(string(rest[j+1:]), ":")
		msg = strings.TrimSpace(msg)
		switch {
		case strings.HasPrefix(msg, string(accepted)):
			// Accepted <method> for <user> from <address> port <n> ...
			f := strings.Fields(msg)
			if len(f) < 6 || f[2] != "for" {
				continue
			}
			from := ""
			for x := 3; x+1 < len(f); x++ {
				if f[x] == "from" {
					from = f[x+1]
					break
				}
			}
			if at := stampOf(line[:k], now); at > 0 {
				add(recent{user: clean(f[3]), source: clean(from), via: clean(f[1]), pid: pid, at: at})
			}
		case strings.Contains(msg, string(closedS)):
			if at := stampOf(line[:k], now); at > 0 {
				end(pid, "", at)
			}
		}
	}
}

// stampOf reads the time at the start of a log line; 0 when it is not one.
func stampOf(head []byte, now time.Time) int64 {
	s := string(head)
	if len(s) > 25 && s[4] == '-' && s[10] == 'T' {
		if sp := strings.IndexByte(s, ' '); sp > 0 {
			if t, err := time.Parse(time.RFC3339Nano, s[:sp]); err == nil {
				return t.Unix()
			}
		}
	}
	if len(s) >= 15 {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", s[:15], time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0) // a December line read in January
			}
			return t.Unix()
		}
	}
	return 0
}

// parseWtmp reads glibc's login history, the same 384-byte records as utmp: USER_PROCESS (7) is a login, DEAD_PROCESS (8) the end of
// the session on that terminal.
func parseWtmp(data []byte, add func(recent), end func(pid, tty string, at int64)) {
	cstr := func(b []byte) string {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		return string(b)
	}
	for off := 0; off+utmpSize <= len(data); off += utmpSize {
		r := data[off : off+utmpSize]
		at := int64(int32(binary.LittleEndian.Uint32(r[340:344])))
		pid := strconv.Itoa(int(int32(binary.LittleEndian.Uint32(r[4:8]))))
		switch binary.LittleEndian.Uint32(r[0:4]) {
		case 7:
			if u := clean(cstr(r[44:76])); u != "" {
				add(recent{user: u, tty: clean(cstr(r[8:40])), source: clean(cstr(r[76:332])), pid: pid, at: at})
			}
		case 8:
			end(pid, clean(cstr(r[8:40])), at)
		}
	}
}
