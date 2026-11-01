package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a Status inventory: it proves itself with its key, registers devices with the right secret,
// and accepts reports only when the signature over "<timestamp>:<body>" is the registered device's.
type fakeServer struct {
	*httptest.Server
	key      ed25519.PrivateKey
	mu       sync.Mutex
	devices  map[string]ed25519.PublicKey // device id → key
	approved map[string]bool
	reports  []string
	interval []string
	answer   int    // status for reports; 0 = 200 with a schedule
	next     string // nextReportAt to answer
	redirect bool
}

func newFakeServer(t *testing.T) *fakeServer {
	_, priv, _ := ed25519.GenerateKey(nil)
	f := &fakeServer{key: priv, devices: map[string]ed25519.PublicKey{}, approved: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) id() string { return Fingerprint(f.key.Public().(ed25519.PublicKey)) }

func (f *fakeServer) join() string {
	return f.URL + "#" + f.id() + "." + "s3cret_-xxxxxxxxxxxxxxxxxxxxxxxx"
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if f.redirect {
		http.Redirect(w, r, "https://evil.example/collect", http.StatusTemporaryRedirect)
		return
	}
	switch r.URL.Path {
	case "/api/server/challenge":
		var in struct{ Challenge string }
		_ = json.Unmarshal(body, &in)
		c, _ := base64.StdEncoding.DecodeString(in.Challenge)
		sig := ed25519.Sign(f.key, append(append([]byte{}, serverPrefix...), c...))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"publicKey": base64.StdEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey)),
			"signature": base64.StdEncoding.EncodeToString(sig),
		})
	case "/api/inventory/v1/register":
		var in struct{ PublicKey, Label, JoinSecret, EnrollToken string }
		_ = json.Unmarshal(body, &in)
		if in.EnrollToken == "tok_yyyyyyyyyyyyyyyyyyyyyyyy" {
			raw, _ := base64.StdEncoding.DecodeString(in.PublicKey)
			f.devices[Fingerprint(raw)] = raw
			f.approved[Fingerprint(raw)] = true
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
			return
		}
		if in.JoinSecret != "s3cret_-xxxxxxxxxxxxxxxxxxxxxxxx" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(in.PublicKey)
		f.devices[Fingerprint(raw)] = raw
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	case "/api/inventory/v1/report":
		id := r.Header.Get("X-Inventory-Device")
		pub, ok := f.devices[id]
		ts := r.Header.Get("X-Inventory-Timestamp")
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Inventory-Signature"))
		if !ok || !f.approved[id] || !ed25519.Verify(pub, append([]byte(ts+":"), body...), sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.interval = append(f.interval, r.Header.Get("X-Inventory-Interval"))
		if f.answer != 0 {
			w.WriteHeader(f.answer)
			_, _ = w.Write([]byte(`{"nextReportAt":"` + f.next + `"}`))
			return
		}
		f.reports = append(f.reports, string(body))
		_ = json.NewEncoder(w).Encode(map[string]any{"intervalSeconds": 30, "nextReportAt": f.next})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestAJoinStringIsParsedAndItsSecretNeverPrinted(t *testing.T) {
	j, err := ParseJoin(" https://status.example.com/#" + strings.Repeat("A", 43) + ".s3cret_-xxxxxxxxxxxxxxxx ")
	if err != nil {
		t.Fatal(err)
	}
	if j.ServerURL != "https://status.example.com" || j.ServerID != strings.Repeat("A", 43) {
		t.Fatalf("%+v", j)
	}
	if strings.Contains(j.String(), "s3cret") {
		t.Fatal("the secret is printed")
	}
	for _, bad := range []string{"", "https://x", "https://x#abc", "https://x#" + strings.Repeat("A", 43) + ".short",
		"http://status.example.com#" + strings.Repeat("A", 43) + ".s3cret_-xxxxxxxxxxxxxxxx"} {
		if _, err := ParseJoin(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTheDeviceKeyIsKeptPrivateAndReloaded(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "device.key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	k2, _ := LoadOrCreateKey(dir)
	if k1.DeviceID() != k2.DeviceID() || len(k1.DeviceID()) != 43 {
		t.Fatal("not the same key, or not a 43-character fingerprint")
	}
	_ = os.Chmod(filepath.Join(dir, "device.key"), 0o644)
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("a key file others can read is used")
	}
}

func TestJoiningRegistersAndAWrongServerGetsNothing(t *testing.T) {
	f := newFakeServer(t)
	key, _ := LoadOrCreateKey(t.TempDir())
	j, _ := ParseJoin(f.join())
	state, err := NewClient().Register(j, key, "web-1")
	if err != nil || state != "pending" {
		t.Fatalf("%v %q", err, state)
	}

	other := newFakeServer(t) // answers the challenge with a different key
	j2, _ := ParseJoin(other.URL + "#" + f.id() + ".s3cret_-xxxxxxxxxxxxxxxxxxxxxxxx")
	if _, err := NewClient().Register(j2, key, "web-1"); err != ErrWrongServer {
		t.Fatalf("wrong server: %v", err)
	}
	if len(other.devices) != 0 {
		t.Fatal("the impostor received the registration")
	}
}

func TestAReportIsSignedSaysItsIntervalAndHearsWhenItIsNextExpected(t *testing.T) {
	f := newFakeServer(t)
	key, _ := LoadOrCreateKey(t.TempDir())
	j, _ := ParseJoin(f.join())
	_, _ = NewClient().Register(j, key, "web-1")

	if o := NewClient().Send(f.URL, f.id(), key, []byte(`{"kernel":"6.8"}`), 30); o.Result != "not_approved" {
		t.Fatalf("before approval: %+v", o)
	}
	f.approved[key.DeviceID()] = true
	f.next = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
	o := NewClient().Send(f.URL, f.id(), key, []byte(`{"kernel":"6.8"}`), 30)
	if o.Result != "accepted" || o.Next.IsZero() || f.interval[len(f.interval)-1] != "30" {
		t.Fatalf("%+v %v", o, f.interval)
	}
	if len(f.reports) != 1 || f.reports[0] != `{"kernel":"6.8"}` {
		t.Fatalf("%v", f.reports)
	}
}

func TestTooSoonIsToldWhenToComeBackAndARedirectIsNotFollowed(t *testing.T) {
	f := newFakeServer(t)
	key, _ := LoadOrCreateKey(t.TempDir())
	j, _ := ParseJoin(f.join())
	_, _ = NewClient().Register(j, key, "web-1")
	f.approved[key.DeviceID()] = true
	f.answer, f.next = http.StatusTooManyRequests, time.Now().Add(25*time.Second).UTC().Format(time.RFC3339)
	if o := NewClient().Send(f.URL, f.id(), key, []byte(`{}`), 30); o.Result != "too_soon" || o.Next.IsZero() {
		t.Fatalf("%+v", o)
	}
	f.redirect = true
	if o := NewClient().Send(f.URL, f.id(), key, []byte(`{}`), 30); o.Result == "accepted" {
		t.Fatal("followed a redirect")
	}
}

func TestTheServerCanOnlyDelayTheNextReportByAnHour(t *testing.T) {
	now := time.Now()
	if got := NextReportAt([]byte(`{"nextReportAt":"2099-01-01T00:00:00Z"}`), now); !got.Equal(now.Add(time.Hour)) {
		t.Fatal(got)
	}
	if got := NextReportAt([]byte(`{"nextReportAt":"2001-01-01T00:00:00Z"}`), now); !got.Equal(now) {
		t.Fatal(got)
	}
	if !NextReportAt([]byte(`{"send":["serial"]}`), now).IsZero() {
		t.Fatal("read something that is not a time")
	}
}

func TestScheduling(t *testing.T) {
	now := time.Now()
	if !isDue(Status{NextDue: now.Add(time.Hour)}, now, 30, true) {
		t.Error("at start everything is sent")
	}
	if isDue(Status{NextDue: now.Add(10 * time.Second)}, now, 30, false) || !isDue(Status{NextDue: now}, now, 30, false) {
		t.Error("the server's time is followed")
	}
	if isDue(Status{LastAttempt: now.Add(-20 * time.Second)}, now, 30, false) || !isDue(Status{LastAttempt: now.Add(-31 * time.Second)}, now, 30, false) {
		t.Error("without a server time the interval counts from the last try")
	}
}

func write(t *testing.T, root, path, content string) {
	p := filepath.Join(root, path)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyTheFieldsSwitchedOnAreReadFromTheMachinesFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_ID=\"24.04\"\n")
	write(t, root, "proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	write(t, root, "proc/meminfo", "MemTotal:       16314916 kB\nMemFree: 1 kB\n")
	write(t, root, "proc/stat", "cpu  1 2 3\nbtime 1761900000\n")
	write(t, root, "sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-sda3_crypt\n")
	write(t, root, "sys/block/dm-0/dm/name", "sda3_crypt\n")
	write(t, root, "var/lib/dpkg/status", "Package: openssl\nStatus: install ok installed\nVersion: 3.0.13\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\n")

	r := Report(root, []string{"os_name", "os_version", "kernel", "memory_mb", "boot_time", "disk_encryption", "packages"})
	b, _ := json.Marshal(r)
	for _, want := range []string{`"os_name":"Ubuntu 24.04.1 LTS"`, `"os_version":"24.04"`, `"kernel":"6.8.0-45-generic"`,
		`"memory_mb":15932`, `"boot_time":1761900000`, `"encrypted_volumes":1`, `{"name":"openssl","version":"3.0.13"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if strings.Contains(string(b), "gone") {
		t.Error("a removed package is reported")
	}
	if len(Report(root, nil)) != 0 {
		t.Error("something is reported with nothing switched on")
	}
	if _, ok := Report(root, []string{"hostname"})["hostname"]; ok {
		t.Error("a field the machine cannot answer is left out, not invented")
	}
}

func TestTheConsentFileIsCheckedAndHeldToTheIntervalRange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "beacon.json")
	write(t, dir, "beacon.json", `{"fields":["kernel"],"interval_seconds":5}`)
	c, err := LoadConfig(p)
	if err != nil || c.IntervalSeconds != 30 {
		t.Fatalf("%v %+v", err, c)
	}
	write(t, dir, "beacon.json", `{"fields":["everything"]}`)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("an unknown field is accepted")
	}
	c, _ = LoadConfig(filepath.Join(dir, "missing.json"))
	if len(c.Fields) != 0 {
		t.Fatal("no consent file must mean nothing on")
	}
}

func TestALinkFromTheInventoryPageJoinsWithItsTokenAndCanComeBackApproved(t *testing.T) {
	f := newFakeServer(t)
	link := "plaiiin-infrastructure://join?url=" + url.QueryEscape(f.URL) + "&server=" + f.id() + "&token=tok_yyyyyyyyyyyyyyyyyyyyyyyy"
	j, err := ParseJoin(link)
	if err != nil || !j.Enrollment || j.ServerURL != f.URL {
		t.Fatalf("%v %+v", err, j)
	}
	key, _ := LoadOrCreateKey(t.TempDir())
	state, err := NewClient().Register(j, key, "web-1")
	if err != nil || state != "approved" {
		t.Fatalf("%v %q", err, state)
	}
	if _, err := ParseJoin("plaiiin-infrastructure://join?url=" + url.QueryEscape(f.URL) + "&server=short&token=tok_yyyyyyyyyyyyyyyyyyyyyyyy"); err == nil {
		t.Fatal("a bad server ID is accepted")
	}
}

func TestAnInterfaceIsReportedOnlyWhenANetworkCanReachIt(t *testing.T) {
	cidr := func(s string) net.Addr { ip, n, _ := net.ParseCIDR(s); n.IP = ip; return n }
	row, ok := ifaceRow("eth0", "52:54:00:12:34:56", []net.Addr{cidr("10.0.0.5/24"), cidr("fe80::1/64"), cidr("2a01:4f8::5/64")})
	if !ok || row.MAC != "52:54:00:12:34:56" || len(row.IPv4) != 1 || len(row.IPv6) != 2 {
		t.Fatalf("%+v %v", row, ok)
	}
	if _, ok := ifaceRow("docker0", "02:42:ac:11:00:01", []net.Addr{cidr("fe80::42:acff:fe11:1/64")}); ok {
		t.Fatal("an interface with only a link-local address is reported")
	}
}

func TestEnableAndDisableKeepTheRestOfTheConsentFileAndAllIsExplicit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "beacon.json")
	write(t, dir, "beacon.json", `{"fields":["kernel"],"interval_seconds":120,"root":"/host"}`)

	next, err := Toggle([]string{"kernel"}, []string{"os_name", "memory_mb"}, true)
	if err != nil || len(next) != 3 {
		t.Fatalf("%v %v", next, err)
	}
	if err := SaveFields(p, next); err != nil {
		t.Fatal(err)
	}
	c, _ := LoadConfig(p)
	if c.IntervalSeconds != 120 || c.Root != "/host" || len(c.Fields) != 3 {
		t.Fatalf("the rest of the file changed: %+v", c)
	}

	all, _ := Toggle(c.Fields, []string{"all"}, true)
	if len(all) != len(Fields) {
		t.Fatalf("all is %d of %d", len(all), len(Fields))
	}
	none, _ := Toggle(all, []string{"all"}, false)
	if len(none) != 0 {
		t.Fatalf("disable all left %v", none)
	}
	one, _ := Toggle(all, []string{"packages"}, false)
	if len(one) != len(Fields)-1 {
		t.Fatalf("disable one left %v", one)
	}
	if _, err := Toggle(nil, []string{"serial_number"}, true); err == nil {
		t.Fatal("an unknown field is accepted")
	}
	if err := SaveFields(p, []string{"bogus"}); err == nil {
		t.Fatal("an unknown field was saved")
	}
}

func TestTheFieldsThatNameThisMachineAreMarked(t *testing.T) {
	for _, id := range []string{"hostname", "network", "packages"} {
		if !Identifying[id] {
			t.Errorf("%s is not marked as identifying", id)
		}
	}
	if Identifying["kernel"] || Identifying["os_name"] {
		t.Error("a field that only names the kind of machine is marked")
	}
}

func TestDisksListRealFilesystemsOnlyOnceAndReadTheirSizes(t *testing.T) {
	root := t.TempDir()
	mnt := filepath.Join(root, "data dir")
	_ = os.MkdirAll(mnt, 0o755)
	write(t, root, "proc/mounts", "proc /proc proc rw 0 0\n/dev/sda1 /data\\040dir ext4 rw 0 0\n/dev/sda1 /again ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sdb1 /gone xfs rw 0 0\noverlay /data\\040dir/bound overlay rw 0 0\n")
	_ = os.MkdirAll(filepath.Join(mnt, "bound"), 0o755)
	got, ok := disks(root)
	if !ok {
		t.Fatal("no disks")
	}
	list := got.([]Disk)
	if len(list) != 1 || list[0].Mount != "/data dir" /* the bind mount inside it is the same filesystem: listed once, by its shortest mount point */ || list[0].FS != "ext4" || list[0].SizeGB <= 0 || list[0].FreeGB > list[0].SizeGB {
		t.Fatalf("%+v", list)
	}
	if unescapeMount(`/mnt/my\040disk`) != "/mnt/my disk" {
		t.Fatal("octal escape")
	}
}

func TestASlowFieldIsSentInFullAtFirstWhenChangedAndEveryHourOtherwiseItIsNamedUnchanged(t *testing.T) {
	st := slowState{}
	now := time.Now()
	report := map[string]any{"kernel": "6.8", "packages": []string{"a", "b"}}

	body, full := st.BodyFor("s", report, now)
	if !strings.Contains(string(body), `"packages"`) || strings.Contains(string(body), "unchanged") {
		t.Fatalf("first report must carry the package list: %s", body)
	}
	st.Record("s", full, now)

	body, full = st.BodyFor("s", report, now.Add(30*time.Second))
	if strings.Contains(string(body), `"packages":`) || !strings.Contains(string(body), `"unchanged":["packages"]`) || !strings.Contains(string(body), `"kernel":"6.8"`) {
		t.Fatalf("an unchanged package list is left out and named: %s", body)
	}
	if len(full) != 0 {
		t.Fatal("nothing slow was sent in full")
	}

	changed := map[string]any{"kernel": "6.8", "packages": []string{"a", "b", "c"}}
	body, _ = st.BodyFor("s", changed, now.Add(time.Minute))
	if !strings.Contains(string(body), `"packages"`) || strings.Contains(string(body), "unchanged") {
		t.Fatalf("a changed list goes in full: %s", body)
	}

	body, _ = st.BodyFor("s", report, now.Add(61*time.Minute))
	if !strings.Contains(string(body), `"packages":`) {
		t.Fatalf("at least hourly, in full: %s", body)
	}
	body, _ = st.BodyFor("another server", report, now.Add(time.Minute))
	if !strings.Contains(string(body), `"packages":`) {
		t.Fatal("each server gets the list in full the first time")
	}
}
