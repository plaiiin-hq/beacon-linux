#!/bin/sh
# plaiiin Beacon installer: curl -fsSL https://plaiiin.com/packages/install.sh | sh
#
# What it does, and nothing else:
#   1. adds the plaiiin package signing key and the signed apt or dnf repository at https://plaiiin.com/packages/
#   2. installs the plaiiin-beacon package from it
# It does not start Beacon, switch any field on or join any server: that stays the owner's choice.
# Updates then come with the system's own `apt upgrade` / `dnf upgrade`.
# Read it first if you like: curl -fsSL https://plaiiin.com/packages/install.sh -o install.sh && less install.sh
set -eu

BASE="https://plaiiin.com/packages"
FINGERPRINT="C5237B7F71EEAF7FEF515C5A0471AD09AF62F53A"

say() { printf '%s\n' "$*"; }
die() { printf 'plaiiin Beacon installer: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else die "run as root, or install sudo"; fi
command -v curl >/dev/null 2>&1 || die "curl is needed"
[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux; on a Mac, iPhone or iPad use the App Store app"
case "$(uname -m)" in x86_64|amd64|aarch64|arm64) ;; *) die "no package for $(uname -m) (amd64 and arm64 only)";; esac

if command -v apt-get >/dev/null 2>&1; then
    say "Adding the plaiiin apt repository (key $FINGERPRINT)…"
    $SUDO install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
    curl -fsSL "$BASE/plaiiin-packages.gpg" | $SUDO tee /usr/share/keyrings/plaiiin.gpg >/dev/null
    curl -fsSL "$BASE/plaiiin.sources" | $SUDO tee /etc/apt/sources.list.d/plaiiin.sources >/dev/null
    $SUDO apt-get update -qq -o Dir::Etc::sourcelist=sources.list.d/plaiiin.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
    $SUDO apt-get install -y plaiiin-beacon
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PM=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
    say "Adding the plaiiin $PM repository (key $FINGERPRINT)…"
    curl -fsSL "$BASE/plaiiin.repo" | $SUDO tee /etc/yum.repos.d/plaiiin.repo >/dev/null
    $SUDO "$PM" install -y plaiiin-beacon
elif command -v zypper >/dev/null 2>&1; then
    say "Adding the plaiiin zypper repository (key $FINGERPRINT)…"
    $SUDO rpm --import "$BASE/plaiiin-packages.asc"
    $SUDO zypper --non-interactive addrepo --gpgcheck --refresh "$BASE/rpm" plaiiin
    $SUDO zypper --non-interactive install plaiiin-beacon
else
    die "no apt, dnf, yum or zypper here; see $BASE/ for the packages and the container image"
fi

say ""
say "plaiiin Beacon is installed; nothing is shared yet. Next:"
say "  sudoedit /etc/beacon/beacon.json                 switch on what may be reported (all off)"
say "  beacon dry-run                                   see the exact report"
say "  sudo beacon join '<link or join string>'         from the server's Inventory page"
say "  sudo systemctl enable --now beacon"
