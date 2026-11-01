package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Disk is one mounted filesystem as the inventory reports it: what it is and how big, plus what is free right now.
// The free space changes all the time, so the server keeps only its latest value and never builds a history of it.
type Disk struct {
	Mount  string  `json:"mount"`
	Device string  `json:"device"`
	FS     string  `json:"fs"`
	SizeGB float64 `json:"size_gb"`
	FreeGB float64 `json:"free_gb"`
}

// realFS are the filesystems that hold data a person would call a disk; pseudo ones (proc, sysfs, tmpfs, cgroup, …) are
// left out. overlay is in because it is what a container's root is.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "vfat": true,
	"exfat": true, "ntfs": true, "ntfs3": true, "reiserfs": true, "jfs": true, "overlay": true, "fuseblk": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true,
}

// disks reads the mount table and asks the kernel (statfs) for each filesystem's size: it reads, it runs nothing.
// A mount that cannot be asked (hidden from the service, gone) is left out, and a filesystem mounted twice is listed once.
func disks(root string) (any, bool) {
	text, ok := readTrim(root, "proc/mounts")
	if !ok {
		return nil, false
	}
	// A filesystem is one disk however many places it is mounted: bind mounts (and a service's sandbox, which binds a few
	// files into view) share its filesystem ID. The shortest mount point names it.
	type candidate struct {
		disk Disk
		fsid string
	}
	var found []candidate
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] {
			continue
		}
		device, mount, fs := f[0], unescapeMount(f[1]), f[2]
		var st syscall.Statfs_t
		if err := syscall.Statfs(filepath.Join(root, mount), &st); err != nil || st.Blocks == 0 {
			continue
		}
		bs := float64(st.Bsize)
		found = append(found, candidate{Disk{Mount: mount, Device: device, FS: fs,
			SizeGB: round1(float64(st.Blocks) * bs / 1e9), FreeGB: round1(float64(st.Bavail) * bs / 1e9)}, fmt.Sprint(st.Fsid)})
	}
	sort.Slice(found, func(i, j int) bool {
		if len(found[i].disk.Mount) != len(found[j].disk.Mount) {
			return len(found[i].disk.Mount) < len(found[j].disk.Mount)
		}
		return found[i].disk.Mount < found[j].disk.Mount
	})
	seen := map[string]bool{}
	out := []Disk{}
	for _, c := range found {
		if seen[c.fsid] {
			continue
		}
		seen[c.fsid] = true
		out = append(out, c.disk)
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out, true
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// unescapeMount undoes the octal escapes /proc/mounts uses for spaces and the like (\040).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := parseOctal(s[i+1 : i+4]); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseOctal(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '7' {
			return 0, os.ErrInvalid
		}
		n = n*8 + int(r-'0')
	}
	return n, nil
}
