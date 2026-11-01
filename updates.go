package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// updates: what is waiting to be installed, and above all what is waiting that fixes a security problem. Nothing is run and
// nothing is downloaded: the package manager already keeps its lists of what each archive offers on disk, so the security
// archive's list is compared with what dpkg says is installed. A package whose security entry is newer than the installed
// version is a security update waiting. The answer also says when the lists were last refreshed, because a machine that has
// not refreshed them for weeks cannot know, and a quiet "0" would then be a lie.

var pendingRe = regexp.MustCompile(`(\d+) updates? can be applied immediately`)

var updatesCache struct {
	sync.Mutex
	key   string
	value map[string]any
}

func updates(root string) (any, bool) {
	lists := filepath.Join(root, "var/lib/apt/lists")
	if _, err := os.Stat(lists); err != nil {
		return nil, false // not a dpkg/apt system
	}
	installed := map[string]string{}
	pk, ok := dpkgPackages(root)
	if !ok {
		return nil, false
	}
	for _, p := range pk.([]map[string]string) {
		installed[p["name"]] = p["version"]
	}
	files, _ := filepath.Glob(filepath.Join(lists, "*security*_Packages"))
	sort.Strings(files)

	// Parsed again only when a list or the installed set changed: a few megabytes, once, not at every report.
	var key strings.Builder
	key.WriteString(strconv.Itoa(len(installed)))
	var newestList time.Time
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			key.WriteString("|" + f + strconv.FormatInt(info.Size(), 10) + info.ModTime().String())
		}
	}
	if m, err := os.Stat(filepath.Join(root, "var/lib/dpkg/status")); err == nil {
		key.WriteString("|dpkg" + m.ModTime().String())
	}
	for _, f := range listFreshness(lists) {
		if f.After(newestList) {
			newestList = f
		}
	}
	updatesCache.Lock()
	defer updatesCache.Unlock()
	var sec map[string]any
	if updatesCache.key == key.String() && updatesCache.value != nil {
		sec = updatesCache.value
	} else {
		sec = securityUpdates(files, installed)
		updatesCache.key, updatesCache.value = key.String(), sec
	}

	out := map[string]any{"security": sec["security"], "security_packages": sec["packages"]}
	if !newestList.IsZero() {
		out["lists_checked_at"] = newestList.Unix()
	}
	if txt, ok := readTrim(root, "var/lib/update-notifier/updates-available"); ok {
		if m := pendingRe.FindStringSubmatch(txt); m != nil {
			n, _ := strconv.Atoi(m[1])
			out["pending"] = n
		}
	}
	if _, err := os.Stat(filepath.Join(root, "var/run/reboot-required")); err == nil {
		out["reboot_required"] = true
		if b, err := os.ReadFile(filepath.Join(root, "var/run/reboot-required.pkgs")); err == nil {
			var names []string
			seen := map[string]bool{}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !seen[l] && len(names) < 10 {
					seen[l] = true
					names = append(names, l)
				}
			}
			out["reboot_packages"] = names
		}
	} else {
		out["reboot_required"] = false
	}
	return out, true
}

// listFreshness: the modification times of the archives' release files, which change whenever the lists are refreshed
// (the package files themselves only change when the archive's content did).
func listFreshness(lists string) []time.Time {
	var out []time.Time
	matches, _ := filepath.Glob(filepath.Join(lists, "*InRelease"))
	rel, _ := filepath.Glob(filepath.Join(lists, "*_Release"))
	for _, f := range append(matches, rel...) {
		if info, err := os.Stat(f); err == nil {
			out = append(out, info.ModTime())
		}
	}
	return out
}

// securityUpdates compares each security archive list with the installed versions.
func securityUpdates(files []string, installed map[string]string) map[string]any {
	best := map[string]string{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 1<<20), 1<<20)
		name := ""
		for lines := 1; s.Scan(); lines++ {
			line := s.Text()
			switch {
			case strings.HasPrefix(line, "Package: "):
				name = line[9:]
			case strings.HasPrefix(line, "Version: "):
				if have, ok := installed[name]; ok {
					if v := line[9:]; debCompare(v, have) > 0 && (best[name] == "" || debCompare(v, best[name]) > 0) {
						best[name] = v
					}
				}
			}
			if lines%4000 == 0 {
				time.Sleep(2 * time.Millisecond) // a micro break, like every other heavy read
			}
		}
		f.Close()
	}
	names := make([]string, 0, len(best))
	for n := range best {
		names = append(names, n)
	}
	sort.Strings(names)
	list := []map[string]string{}
	for _, n := range names {
		if len(list) < 30 {
			list = append(list, map[string]string{"name": n, "installed": installed[n], "available": best[n]})
		}
	}
	return map[string]any{"security": len(names), "packages": list}
}

// debCompare orders two Debian version strings the way dpkg does (epoch, upstream, revision; "~" sorts before everything).
func debCompare(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDebVersion(v string) (epoch int, upstream, revision string) {
	if i := strings.Index(v, ":"); i >= 0 {
		epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func debOrder(c byte, present bool) int {
	switch {
	case !present:
		return 0
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc byte
			ah, bh := i < len(a), j < len(b)
			if ah {
				ac = a[i]
			}
			if bh {
				bc = b[j]
			}
			if x, y := debOrder(ac, ah), debOrder(bc, bh); x != y {
				if x < y {
					return -1
				}
				return 1
			}
			if ah {
				i++
			}
			if bh {
				j++
			}
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		diff := 0
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if diff != 0 {
			if diff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}
