package main

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Field is one thing this machine can report. A field is READ only when it is switched on: nothing is collected
// and filtered afterwards. Every reader only reads files, under Root (/ normally, the host's files mounted
// read-only under /host in a container). None of them runs a program.
type Field struct {
	ID, Title, Source string
	Read              func(root string) (any, bool)
}

func readTrim(root, path string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// osRelease parses /etc/os-release (or /usr/lib/os-release) into its KEY=value pairs.
func osRelease(root string) map[string]string {
	out := map[string]string{}
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(root, p))
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			k, v, ok := strings.Cut(s.Text(), "=")
			if ok {
				out[k] = strings.Trim(v, `"'`)
			}
		}
		f.Close()
		break
	}
	return out
}

func meminfoMB(root string) (any, bool) {
	text, ok := readTrim(root, "proc/meminfo")
	if !ok {
		return nil, false
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, err := strconv.Atoi(f[1])
				if err == nil {
					return kb / 1024, true
				}
			}
		}
	}
	return nil, false
}

func cpu(root string) (any, bool) {
	text, ok := readTrim(root, "proc/cpuinfo")
	if !ok {
		return nil, false
	}
	model, count := "", 0
	for _, line := range strings.Split(text, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(k) {
		case "processor":
			count++
		case "model name", "Model", "cpu model":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		}
	}
	if count == 0 {
		return nil, false
	}
	out := map[string]any{"threads": count}
	if model != "" { // ARM's cpuinfo names no model
		out["model"] = model
	}
	return out, true
}

// bootTime: when the machine last started (btime in /proc/stat), so the value changes per boot, not per report.
func bootTime(root string) (any, bool) {
	text, ok := readTrim(root, "proc/stat")
	if !ok {
		return nil, false
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, err := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			if err == nil {
				return v, true
			}
		}
	}
	return nil, false
}

// diskEncryption: device-mapper devices whose uuid starts with CRYPT- are dm-crypt/LUKS volumes.
func diskEncryption(root string) (any, bool) {
	matches, _ := filepath.Glob(filepath.Join(root, "sys/block/*/dm/uuid"))
	crypt := []string{}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err == nil && strings.HasPrefix(string(b), "CRYPT-") {
			name, _ := os.ReadFile(filepath.Join(filepath.Dir(m), "name"))
			crypt = append(crypt, strings.TrimSpace(string(name)))
		}
	}
	sort.Strings(crypt)
	return map[string]any{"encrypted_volumes": len(crypt), "names": crypt}, true
}

// secureBoot reads the SecureBoot EFI variable: 4 bytes of attributes, then 1 byte, 1 = on.
func secureBoot(root string) (any, bool) {
	matches, _ := filepath.Glob(filepath.Join(root, "sys/firmware/efi/efivars/SecureBoot-*"))
	if len(matches) == 0 {
		if _, err := os.Stat(filepath.Join(root, "sys/firmware/efi")); err != nil {
			return "not an EFI system", true
		}
		return "unknown", true
	}
	b, err := os.ReadFile(matches[0])
	if err != nil || len(b) < 5 {
		return "unknown", true
	}
	if b[4] == 1 {
		return "on", true
	}
	return "off", true
}

// dpkgPackages: installed packages and versions from dpkg's status file (Debian, Ubuntu). The file is a few megabytes and
// changes only when a package does, so it is parsed once and again only when its size or modification time changes; the
// parse itself takes a short rest every few thousand lines, so even that never lands as a burst.
var dpkgCache struct {
	sync.Mutex
	path  string
	size  int64
	mtime time.Time
	value []map[string]string
}

func dpkgPackages(root string) (any, bool) {
	path := filepath.Join(root, "var/lib/dpkg/status")
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	dpkgCache.Lock()
	defer dpkgCache.Unlock()
	if dpkgCache.path == path && dpkgCache.size == info.Size() && dpkgCache.mtime.Equal(info.ModTime()) && dpkgCache.value != nil {
		return dpkgCache.value, true
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	out := []map[string]string{}
	name, version, installed := "", "", false
	flush := func() {
		if name != "" && installed {
			out = append(out, map[string]string{"name": name, "version": version})
		}
		name, version, installed = "", "", false
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for lines := 1; s.Scan(); lines++ {
		line := s.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = line[9:]
		case strings.HasPrefix(line, "Version: "):
			version = line[9:]
		case strings.HasPrefix(line, "Status: "):
			installed = strings.HasSuffix(line, " installed")
		}
		if lines%4000 == 0 {
			time.Sleep(2 * time.Millisecond) // a micro break
		}
	}
	flush()
	sort.Slice(out, func(i, j int) bool { return out[i]["name"] < out[j]["name"] })
	dpkgCache.path, dpkgCache.size, dpkgCache.mtime, dpkgCache.value = path, info.Size(), info.ModTime(), out
	return out, true
}

// Identifying marks the fields that name this particular machine, not just its kind: a list shows them so an admin
// can leave them off and still report the rest.
var Identifying = map[string]bool{"hostname": true, "network": true, "packages": true, "model": true}

// Fields is everything this reporter can read, in the order `beacon fields` lists it.
var Fields = []Field{
	{"os_name", "OS name", "/etc/os-release NAME", func(r string) (any, bool) { v, ok := osRelease(r)["PRETTY_NAME"]; return v, ok }},
	{"os_version", "OS version", "/etc/os-release VERSION_ID", func(r string) (any, bool) { v, ok := osRelease(r)["VERSION_ID"]; return v, ok }},
	{"kernel", "Kernel", "/proc/sys/kernel/osrelease", func(r string) (any, bool) { return readTrim(r, "proc/sys/kernel/osrelease") }},
	{"hostname", "Host name", "/proc/sys/kernel/hostname", func(r string) (any, bool) { return readTrim(r, "proc/sys/kernel/hostname") }},
	{"model", "Hardware model", "/sys/class/dmi/id/product_name, sys_vendor", func(r string) (any, bool) {
		name, ok1 := readTrim(r, "sys/class/dmi/id/product_name")
		vendor, ok2 := readTrim(r, "sys/class/dmi/id/sys_vendor")
		if !ok1 && !ok2 {
			return nil, false
		}
		return strings.TrimSpace(vendor + " " + name), true
	}},
	{"network", "Network interfaces", "IP and MAC addresses (netlink)", networkInterfaces},
	{"location_self", "Self-reported location", "/etc/timezone or /etc/localtime, and the admin's own words (beacon place)", selfReportedLocation},
	{"cpu", "CPU", "/proc/cpuinfo", cpu},
	{"memory_mb", "Memory", "/proc/meminfo MemTotal", meminfoMB},
	{"disks", "Disks", "/proc/mounts, statfs (size and free space per filesystem)", disks},
	{"boot_time", "Last boot", "/proc/stat btime", bootTime},
	{"disk_encryption", "Disk encryption", "/sys/block/*/dm/uuid (dm-crypt)", diskEncryption},
	{"secure_boot", "Secure Boot", "/sys/firmware/efi/efivars/SecureBoot-*", secureBoot},
	{"packages", "Installed packages", "/var/lib/dpkg/status", dpkgPackages},
}

// Report reads exactly the enabled fields. A field that cannot be read on this machine is left out.
func Report(root string, enabled []string) map[string]any {
	on := map[string]bool{}
	for _, id := range enabled {
		on[id] = true
	}
	out := map[string]any{}
	for _, f := range Fields {
		if on[f.ID] {
			if v, ok := f.Read(root); ok {
				out[f.ID] = v
			}
			time.Sleep(2 * time.Millisecond) // a micro break between fields: a report is a trickle, not a burst
		}
	}
	// Which Beacon is reporting: sent with every report that carries anything, so a list can tell which machines run an old one.
	if len(out) > 0 {
		out["beacon_version"] = Version
	}
	return out
}
