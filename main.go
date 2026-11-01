// Command beacon reports facts about this Linux machine to a plaiiin Status inventory: only the fields the
// owner switched on in /etc/beacon/beacon.json, only to servers the owner joined. It reads files and nothing
// else: it runs no programs, opens no port, and takes no instructions from a server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const usage = `beacon: report this machine's facts to a plaiiin Status inventory

  beacon fields                         what can be reported, and what is switched on
  beacon enable <field…|all>            switch fields on (root; "all" is every field this version has)
  beacon disable <field…|all>           switch fields off ("disable all" stops reporting anything)
  beacon last                           the exact report that was last sent, and to whom
  beacon place "<where it is>"          say where this machine is, in your own words (root); empty clears it
  beacon dry-run                        the exact report that would be sent
  beacon join <join string> [--name N]  register with a server: its join string (Settings → Agents) or a
                                        plaiiin-infrastructure:// link from its Inventory page
  beacon leave <server address>         stop reporting to a server
  beacon status                         servers and what each last answered
  beacon run                            send on schedule until stopped (the systemd unit runs this)

  --config <file>   consent file (default /etc/beacon/beacon.json)
  --state <dir>     key and servers (default $STATE_DIRECTORY or /var/lib/beacon)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	// One thread is all this needs: it never uses more than one core, however busy the Go runtime would like to be.
	runtime.GOMAXPROCS(1)
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "/etc/beacon/beacon.json", "consent file")
	defaultState := os.Getenv("STATE_DIRECTORY")
	if defaultState == "" {
		defaultState = "/var/lib/beacon"
	}
	stateDir := fs.String("state", defaultState, "state directory")
	name := fs.String("name", "", "the name this machine suggests to the server")
	args := reorder(os.Args[2:])
	_ = fs.Parse(args)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	switch cmd {
	case "fields":
		listFields(cfg)
	case "enable", "disable":
		if fs.NArg() == 0 {
			log.Fatalf("usage: beacon %s <field…|all>   (beacon fields lists them)", cmd)
		}
		next, err := Toggle(cfg.Fields, fs.Args(), cmd == "enable")
		if err != nil {
			log.Fatal(err)
		}
		if err := SaveFields(*configPath, next); err != nil {
			log.Fatal(err)
		}
		cfg.Fields = next
		listFields(cfg)
		fmt.Println("\nA running service picks this up within a few seconds.")
	case "place":
		if err := SavePlace(*configPath, strings.Join(fs.Args(), " ")); err != nil {
			log.Fatal(err)
		}
		if p := strings.Join(fs.Args(), " "); p == "" {
			fmt.Println("Cleared. Switch the field on or off with: sudo beacon enable|disable location_self")
		} else {
			fmt.Printf("This machine is now reported as: %s\n(sent when location_self is on: sudo beacon enable location_self)\n", p)
		}
	case "last":
		showLast(*stateDir)
	case "dry-run":
		body, _ := json.MarshalIndent(Report(cfg.Root, cfg.Fields), "", "  ")
		fmt.Println(string(body))
		if len(cfg.Fields) == 0 {
			fmt.Fprintln(os.Stderr, "Nothing is switched on, so nothing would be sent.")
		}
	case "join":
		if fs.NArg() != 1 {
			log.Fatal("usage: beacon join <join string> [--name N]")
		}
		join(cfg, *stateDir, fs.Arg(0), *name)
	case "leave":
		if fs.NArg() != 1 {
			log.Fatal("usage: beacon leave <server address>")
		}
		leave(*stateDir, fs.Arg(0))
	case "status":
		status(*stateDir)
	case "run":
		run(cfg, *stateDir, NewClient())
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
}

// reorder puts flags before positional arguments, so `beacon join <string> --name x` works.
func reorder(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			rest = append(rest, args[i])
		}
	}
	return append(flags, rest...)
}

func listFields(cfg Config) {
	on := map[string]bool{}
	for _, id := range cfg.Fields {
		on[id] = true
	}
	for _, f := range Fields {
		mark := "off"
		if on[f.ID] {
			mark = "ON "
		}
		tag := ""
		if Identifying[f.ID] {
			tag = "  (identifies this machine)"
		}
		fmt.Printf("%s  %-16s %-20s %s%s\n", mark, f.ID, f.Title, f.Source, tag)
	}
	fmt.Printf("\nevery %d s. Switch on: sudo beacon enable <field…|all>; off: sudo beacon disable <field…|all>\n", cfg.IntervalSeconds)
}

func join(cfg Config, dir, text, name string) {
	j, err := ParseJoin(text)
	if err != nil {
		log.Fatal(err)
	}
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		log.Fatal(err)
	}
	if name == "" {
		if h, ok := readTrim(cfg.Root, "proc/sys/kernel/hostname"); ok {
			name = h
		}
	}
	state, err := NewClient().Register(j, key, name)
	if err != nil {
		log.Fatal(err)
	}
	servers, err := LoadServers(dir)
	if err != nil {
		log.Fatal(err)
	}
	kept := servers[:0]
	for _, s := range servers {
		if s.URL != j.ServerURL {
			kept = append(kept, s)
		}
	}
	host := strings.TrimPrefix(strings.TrimPrefix(j.ServerURL, "https://"), "http://")
	if err := SaveServers(dir, append(kept, Server{URL: j.ServerURL, ID: j.ServerID, Name: host})); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Added %s as %q (device %s…).\n", host, name, key.DeviceID()[:8])
	if state == "approved" {
		fmt.Println("Approved: reports count from the next one. Switch fields on in the consent file.")
	} else {
		fmt.Println("Waiting for an admin on the server to approve this device. Nothing it sends counts until then;")
		fmt.Println("nothing is shared either, until fields are switched on in the consent file.")
	}
}

func leave(dir, address string) {
	servers, err := LoadServers(dir)
	if err != nil {
		log.Fatal(err)
	}
	kept, found := servers[:0], false
	for _, s := range servers {
		if s.URL == strings.TrimSuffix(address, "/") || s.Name == address {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	if !found {
		log.Fatalf("no server %s", address)
	}
	if err := SaveServers(dir, kept); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Stopped reporting there. The server keeps what it already received; ask its admin to remove this device.")
}

func status(dir string) {
	servers, _ := LoadServers(dir)
	st, _ := LoadStatus(dir)
	if len(servers) == 0 {
		fmt.Println("No servers. Nothing leaves this machine.")
		return
	}
	for _, s := range servers {
		x := st[s.URL]
		fmt.Printf("%s\n  last: %s (%s)\n  next: %s\n", s.Name, orDash(x.LastResult), ago(x.LastAttempt), ago(x.NextDue))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format(time.RFC3339)
}

// showLast prints the report that was last sent: the exact bytes, who got them and when. Run it as root (or the service
// account): the state directory is private to the service.
func showLast(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "last-report.json"))
	if err != nil {
		log.Fatalf("nothing has been sent yet (%v)", err)
	}
	fmt.Println(string(b))
}
