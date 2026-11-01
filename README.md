> **A read-only publication.** This repository is a snapshot of the plaiiin Beacon for Linux source, published so
> you can read it, build it and compare your build with what we ship. It is not developed here: there is no issue
> tracker or pull request intake, and history before a release is not part of it.
> To check a package against this source: `Scripts/build.sh` rebuilds the binaries; they are byte-identical to the
> ones in the packages (`SHA256SUMS` at https://plaiiin.com/packages/), given the same Go version.

# plaiiin Beacon for Linux

*Infrastructure reporting that leaves you in control.*

Reports this machine's facts to a plaiiin Status inventory: only the fields its owner switches on, only to the
servers its owner joins. One static Go binary, standard library only. It reads files and nothing else: it runs
no program, opens no port, and takes no instruction from a server. Design: `docs/beacon-design.md` (Linux reporter).

| | |
|---|---|
| consent | `/etc/beacon/beacon.json`, root's: `"fields"` (all off by default), `"interval_seconds"` (30..3600). Change it with `sudo beacon enable <field…\|all>` and `sudo beacon disable <field…\|all>`, or edit the file; a running service notices within seconds. |
| state | `/var/lib/beacon`: the device key (0600) and the servers joined; the join secret is not kept |
| check what is sent | `beacon dry-run` prints the exact report; `beacon fields` lists what can be read, from which file, and which fields identify the machine; `sudo beacon last` prints the report that was last sent, and to whom |

## What an admin controls

| you want | do |
|---|---|
| nothing reported | the default; or `sudo beacon disable all`, or `sudo systemctl stop beacon` |
| everything this version can report | `sudo beacon enable all` (written as an explicit list: fields a later version adds stay off until you switch them on) |
| the kind of machine, not which one | `sudo beacon enable os_name os_version kernel memory_mb cpu` and leave the ones `beacon fields` marks "identifies this machine" off (host name, network addresses, package list) |
| to see it before it goes | `beacon dry-run` |
| to check afterwards | `sudo beacon last` |
| only certain servers | `beacon join` adds one; `beacon leave <server>` removes it; each is pinned to its server's key |
| to stop it for good | `sudo apt remove plaiiin-beacon` (or `dnf remove`); its state in `/var/lib/beacon` goes with `purge` |

It never opens a port, never asks anyone for an update, and takes no instructions from a server.

## Install (package)

```
curl -fsSL https://plaiiin.com/packages/install.sh | sh
```

`Bundle/install.sh`: adds the signed repository (apt, dnf/yum or zypper) and installs the package; it starts
nothing. Its SHA-256 is on https://plaiiin.com/packages/ for anyone who reads it before running it. By hand,
from the signed repository at https://plaiiin.com/packages/ (key `C5237B7F71EEAF7FEF515C5A0471AD09AF62F53A`):

```
# Debian, Ubuntu
sudo curl -fsSL https://plaiiin.com/packages/plaiiin-packages.gpg -o /usr/share/keyrings/plaiiin.gpg
sudo curl -fsSL https://plaiiin.com/packages/plaiiin.sources -o /etc/apt/sources.list.d/plaiiin.sources
sudo apt update && sudo apt install plaiiin-beacon
# Fedora, RHEL
sudo curl -fsSL https://plaiiin.com/packages/plaiiin.repo -o /etc/yum.repos.d/plaiiin.repo && sudo dnf install plaiiin-beacon

sudoedit /etc/beacon/beacon.json                            # switch fields on
sudo beacon join '<link or join string>'                   # a plaiiin-infrastructure:// link from the Inventory page, or the join string
sudo systemctl enable --now beacon
```

The unit (`Bundle/beacon.service`) is confined by systemd: its own account, read-only system, no capabilities,
internet sockets only, and nothing but its own binary is executable (`NoExecPaths=/`). Check it yourself:
`systemd-analyze security beacon.service` (1.4, "OK", for 0.1.2).

## Run (container)

`compose.yml`: a 2.7 MB `scratch` image, non-root, `read_only`, `cap_drop: ALL`, `no-new-privileges`; the host's
facts come in as read-only file mounts under `/host` (mount only what the switched-on fields need).

```
docker compose run --rm beacon join '<join string>' --name "$(hostname)"
docker compose up -d
```


## Build

`Scripts/build.sh [version]` → `dist/`: binaries for amd64 and arm64, `.deb` and `.rpm` (nfpm), `SHA256SUMS`.
No cgo, `-trimpath`, no build ID: the same commit and Go version give the same bytes, so anyone can rebuild and
compare. `go test ./...` runs against a fake inventory server that checks signatures the way the real one does.
