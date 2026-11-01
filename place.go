package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// declaredPlace is where the admin says this machine is, in their own words ("Zurich, rack 3"), from the consent file.
// It is read at the start of every call-in, so changing it takes effect without a restart.
var declaredPlace string

// selfReportedLocation is where this machine says it is: the admin's own words if they gave some, and the city its time
// zone names. A claim, not a measurement: nothing here looks at the network or a GPS, and a server set to UTC names no
// city, which is why the admin can say it.
func selfReportedLocation(root string) (any, bool) {
	out := map[string]any{}
	if p := strings.TrimSpace(declaredPlace); p != "" {
		out["place"] = p
		out["source"] = "set by the admin"
	}
	if id := timezoneID(root); id != "" {
		out["timezone"] = id
		if city := cityOf(id); city != "" {
			out["city"] = city
		}
		if _, ok := out["source"]; !ok {
			out["source"] = "time zone setting"
		}
		_, off := time.Now().In(loadZone(id)).Zone()
		out["utc_offset"] = formatOffset(off)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// timezoneID reads the zone name the way the system keeps it: /etc/timezone (Debian, Ubuntu), else where /etc/localtime
// points (zoneinfo/Europe/Zurich).
func timezoneID(root string) string {
	if b, err := os.ReadFile(filepath.Join(root, "etc/timezone")); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	if target, err := os.Readlink(filepath.Join(root, "etc/localtime")); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
	}
	return ""
}

// cityOf: "Europe/Zurich" → "Zurich", "America/Argentina/Buenos_Aires" → "Buenos Aires"; "UTC" and "Etc/…" name no city.
func cityOf(id string) string {
	if !strings.Contains(id, "/") || strings.HasPrefix(id, "Etc/") {
		return ""
	}
	return strings.ReplaceAll(id[strings.LastIndex(id, "/")+1:], "_", " ")
}

func loadZone(id string) *time.Location {
	if l, err := time.LoadLocation(id); err == nil {
		return l
	}
	return time.UTC
}

func formatOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign, seconds = "-", -seconds
	}
	return sign + two(seconds/3600) + ":" + two(seconds%3600/60)
}

func two(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
