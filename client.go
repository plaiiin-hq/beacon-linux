package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// serverPrefix is what a Status server signs in front of a challenge, so its signature means nothing elsewhere.
var serverPrefix = []byte("plaiiin-status-server-v1\x00")

// longestDelay is the furthest a server can push the next report out. It can only delay a report, never cause one.
const longestDelay = time.Hour

// Client talks to one kind of server, the inventory. Before anything is sent, the server proves it holds the
// key the join string pinned. Redirects are refused: a signed report goes only where the owner chose. An
// answer is read for a status code and, at most, the time of the next call-in; nothing else in it is used.
type Client struct {
	HTTP *http.Client
	Now  func() time.Time
}

func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout:       15 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Now: time.Now,
	}
}

func (c *Client) post(base, path string, body []byte, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, base+"/"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, data, err
}

// VerifyServer: the server signs a fresh random challenge with its key; the key's fingerprint must be the pinned ID.
func (c *Client) VerifyServer(base, serverID string) bool {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return false
	}
	body, _ := json.Marshal(map[string]string{"challenge": base64.StdEncoding.EncodeToString(challenge)})
	status, data, err := c.post(base, "api/server/challenge", body, nil)
	if err != nil || status != http.StatusOK {
		return false
	}
	var answer struct {
		PublicKey string `json:"publicKey"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(data, &answer) != nil {
		return false
	}
	raw, err1 := base64.StdEncoding.DecodeString(answer.PublicKey)
	sig, err2 := base64.StdEncoding.DecodeString(answer.Signature)
	if err1 != nil || err2 != nil || len(raw) != ed25519.PublicKeySize || Fingerprint(raw) != serverID {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), append(append([]byte{}, serverPrefix...), challenge...), sig)
}

var ErrWrongServer = errors.New("that is not the server the join string names; nothing was sent")

// Register introduces this device to the server named in the join string. Returns the server's status for it
// ("pending" until an admin approves, or "approved").
func (c *Client) Register(join JoinString, key DeviceKey, name string) (string, error) {
	if !c.VerifyServer(join.ServerURL, join.ServerID) {
		return "", ErrWrongServer
	}
	credential := "joinSecret"
	if join.Enrollment {
		credential = "enrollToken"
	}
	body, _ := json.Marshal(map[string]string{"publicKey": key.PublicBase64(), "label": name, credential: join.Secret})
	status, data, err := c.post(join.ServerURL, "api/inventory/v1/register", body, nil)
	if err != nil {
		return "", fmt.Errorf("could not reach the server: %w", err)
	}
	switch status {
	case http.StatusOK:
		var answer struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(data, &answer)
		return answer.Status, nil
	case http.StatusForbidden:
		if join.Enrollment {
			return "", errors.New("the server did not accept this link: it works once, for 10 minutes; make a new one on its Inventory page")
		}
		return "", errors.New("the server did not accept the secret; copy a fresh join string from its admin page")
	case http.StatusTooManyRequests:
		return "", errors.New("too many tries from this address; try again later")
	default:
		return "", fmt.Errorf("the server answered HTTP %d", status)
	}
}

// Outcome of a report: what happened, and when the server next expects this device (zero if it did not say).
type Outcome struct {
	Result string // accepted, not_approved, too_soon, too_large, wrong_server, failed
	Detail string
	Next   time.Time
}

// Send posts a signed report and says how often this device means to call in.
func (c *Client) Send(base, serverID string, key DeviceKey, body []byte, intervalSeconds int) Outcome {
	if !c.VerifyServer(base, serverID) {
		return Outcome{Result: "wrong_server", Detail: ErrWrongServer.Error()}
	}
	ts := c.Now().UTC().Format(time.RFC3339)
	status, data, err := c.post(base, "api/inventory/v1/report", body, map[string]string{
		"X-Inventory-Device":    key.DeviceID(),
		"X-Inventory-Timestamp": ts,
		"X-Inventory-Signature": key.Sign(ts, body),
		"X-Inventory-Interval":  strconv.Itoa(intervalSeconds),
	})
	if err != nil {
		return Outcome{Result: "failed", Detail: err.Error()}
	}
	o := Outcome{}
	switch status {
	case http.StatusOK, http.StatusNoContent:
		o.Result = "accepted"
	case http.StatusUnauthorized:
		o.Result, o.Detail = "not_approved", "not accepted yet: an admin has to approve this device on the server"
	case http.StatusTooManyRequests:
		o.Result, o.Detail = "too_soon", "too soon for the server; it said when to call in next"
	case http.StatusRequestEntityTooLarge:
		o.Result, o.Detail = "too_large", "the report was too large for the server"
	default:
		o.Result, o.Detail = "failed", fmt.Sprintf("HTTP %d", status)
	}
	if status == http.StatusOK || status == http.StatusTooManyRequests {
		o.Next = NextReportAt(data, c.Now())
	}
	return o
}

// NextReportAt reads nextReportAt from an answer, held to [now, now + 1 h]; zero when absent or unreadable.
func NextReportAt(data []byte, now time.Time) time.Time {
	var answer struct {
		NextReportAt string `json:"nextReportAt"`
	}
	if json.Unmarshal(data, &answer) != nil || answer.NextReportAt == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, answer.NextReportAt)
	if err != nil {
		return time.Time{}
	}
	if t.Before(now) {
		return now
	}
	if t.After(now.Add(longestDelay)) {
		return now.Add(longestDelay)
	}
	return t
}
