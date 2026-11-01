package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// serviceUser is the account the systemd unit runs as. `beacon join` is usually run as root; whatever it
// writes into the state directory is handed to this account, or the service could not read its own key.
const serviceUser = "beacon"

// handOver gives path to the service account when run as root and the account exists (read from /etc/passwd:
// no cgo, no NSS). Anywhere else (a container, a test, a normal user) it does nothing.
func handOver(path string) {
	if os.Geteuid() != 0 {
		return
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		p := strings.Split(s.Text(), ":")
		if len(p) >= 4 && p[0] == serviceUser {
			uid, err1 := strconv.Atoi(p[2])
			gid, err2 := strconv.Atoi(p[3])
			if err1 == nil && err2 == nil {
				_ = os.Chown(path, uid, gid)
			}
			return
		}
	}
}
