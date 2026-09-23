package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&livejournal{}) }

var livejournalAuthToken = regexp.MustCompile(`"auth_token"\s*:\s*"([^"]+)"`)

// livejournal reads a sessionless auth token from the public create page,
// then asks signup.check_email whether the address can still be registered.
// status "ok" is a miss. status "error" with an already-in-use message is a
// hit. Other validation errors stay errors.
type livejournal struct{}

func (livejournal) Name() string     { return "livejournal" }
func (livejournal) Domain() string   { return "livejournal.com" }
func (livejournal) Category() string { return "social" }
func (livejournal) Method() string   { return "register" }

func (s *livejournal) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *livejournal) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "livejournal",
		domain:        "livejournal.com",
		category:      "social",
		method:        "register",
		deleteURL:     "https://www.livejournal.com/accountstatus.bml",
		securityURL:   "https://www.livejournal.com/manage/settings/",
		foundEvidence: "Signup check said this email is already in use.",
		missEvidence:  "Signup check said this email can still be registered.",
	}.result(status, detail, elapsed)
}

func (s *livejournal) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, _, body, err := get(ctx, c, "https://www.livejournal.com/create/", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	match := livejournalAuthToken.FindSubmatch(body)
	if match == nil {
		return checker.StatusError, "create page did not include auth token"
	}
	token := string(match[1])
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "signup.check_email",
		"params": map[string]string{
			"email":      email,
			"auth_token": token,
		},
		"id": 1,
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	postHeader := make(http.Header)
	postHeader.Set("Accept", "application/json")
	postHeader.Set("Origin", "https://www.livejournal.com")
	postHeader.Set("Referer", "https://www.livejournal.com/create/")
	status, _, body, err = postJSON(ctx, c, "https://www.livejournal.com/__api/", payload, postHeader)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Result *struct {
			Status string `json:"status"`
			ErrMsg string `json:"errmsg"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result == nil {
		return unexpected()
	}
	switch strings.ToLower(strings.TrimSpace(resp.Result.Status)) {
	case "ok":
		return checker.StatusNotFound, ""
	case "error":
		msg := strings.ToLower(resp.Result.ErrMsg)
		if strings.Contains(msg, "already") || strings.Contains(msg, "in use") || strings.Contains(msg, "taken") || strings.Contains(msg, "registered") {
			return checker.StatusFound, ""
		}
		if resp.Result.ErrMsg != "" {
			return checker.StatusError, "unexpected response"
		}
		return unexpected()
	default:
		return unexpected()
	}
}
