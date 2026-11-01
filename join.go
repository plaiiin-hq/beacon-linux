package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// JoinString is what a server's admin page hands out: https://address#<server ID>.<secret>. The server ID pins
// the server (the fingerprint of its key); the secret lets a new device register and is not kept afterwards.
type JoinString struct {
	ServerURL string
	ServerID  string
	Secret    string
	// Enrollment: from a plaiiin-infrastructure:// link; Secret is then a signed-in person's one-time token.
	Enrollment bool
}

const linkScheme = "plaiiin-infrastructure"

func isURLSafe(s string) bool {
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func ParseJoin(text string) (JoinString, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return JoinString{}, errors.New("paste the join string from the server")
	}
	if strings.HasPrefix(strings.ToLower(s), linkScheme+"://") {
		return parseLink(s)
	}
	hash := strings.LastIndex(s, "#")
	if hash < 0 {
		return JoinString{}, errors.New("a join string looks like https://address#id.secret: there is no # in this one")
	}
	address, rest := s[:hash], s[hash+1:]
	dot := strings.Index(rest, ".")
	if dot < 0 {
		return JoinString{}, errors.New("after the # a join string has <server ID>.<secret>")
	}
	id, secret := rest[:dot], rest[dot+1:]
	if len(id) != 43 || !isURLSafe(id) {
		return JoinString{}, errors.New("the server ID in this join string is not valid")
	}
	if len(secret) < 16 || !isURLSafe(secret) {
		return JoinString{}, errors.New("the secret in this join string is missing or not valid")
	}
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return JoinString{}, errors.New("the address in this join string is not a web address")
	}
	host := u.Hostname()
	if u.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return JoinString{}, fmt.Errorf("use https:// for %s: over plain http someone in the middle could read the secret", host)
	}
	return JoinString{ServerURL: strings.TrimSuffix(address, "/"), ServerID: id, Secret: secret}, nil
}

// parseLink reads plaiiin-infrastructure://join?url=<address>&server=<server ID>&token=<one-time token>,
// the link the server's Inventory page makes for a signed-in person.
func parseLink(s string) (JoinString, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host != "join" {
		return JoinString{}, errors.New("this link is not a plaiiin-infrastructure://join link")
	}
	q := u.Query()
	id, token := q.Get("server"), q.Get("token")
	if len(id) != 43 || !isURLSafe(id) {
		return JoinString{}, errors.New("the server ID in this link is not valid")
	}
	if len(token) < 16 || !isURLSafe(token) {
		return JoinString{}, errors.New("the token in this link is missing or not valid")
	}
	address, err := url.Parse(q.Get("url"))
	if err != nil || address.Host == "" || (address.Scheme != "https" && address.Scheme != "http") {
		return JoinString{}, errors.New("the address in this link is not a web address")
	}
	host := address.Hostname()
	if address.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return JoinString{}, fmt.Errorf("use https:// for %s", host)
	}
	return JoinString{ServerURL: strings.TrimSuffix(q.Get("url"), "/"), ServerID: id, Secret: token, Enrollment: true}, nil
}

// String never shows the secret.
func (j JoinString) String() string {
	return fmt.Sprintf("JoinString(%s, server %s)", j.ServerURL, j.ServerID)
}
