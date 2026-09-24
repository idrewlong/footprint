package sites

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&tumblr{}) }

// tumblr reads the public API token from the register page, then posts an
// incomplete registration to the account validator. The validator checks
// the email before the password, so a one-character password gets "User
// already exists" for a hit and a password error for a miss. Nothing is
// created and no mail is sent.
type tumblr struct{}

func (tumblr) Name() string     { return "tumblr" }
func (tumblr) Domain() string   { return "tumblr.com" }
func (tumblr) Category() string { return "social" }
func (tumblr) Method() string   { return "register" }

var tumblrTokenPattern = regexp.MustCompile(`"API_TOKEN":"([A-Za-z0-9]+)"`)

func (s *tumblr) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *tumblr) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "tumblr",
		domain:        "tumblr.com",
		category:      "social",
		method:        "register",
		deleteURL:     "https://www.tumblr.com/settings/account/delete",
		securityURL:   "https://www.tumblr.com/settings/account",
		foundEvidence: "Signup validator said this email is already registered.",
		missEvidence:  "Signup validator accepted this email and rejected only the password.",
	}.result(status, detail, elapsed)
}

func (s *tumblr) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, _, body, err := get(ctx, c, "https://www.tumblr.com/register", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	match := tumblrTokenPattern.FindSubmatch(body)
	if status != http.StatusOK || len(match) != 2 {
		return checker.StatusError, "register page did not include a token"
	}
	payload, err := json.Marshal(map[string]string{
		"email":     email,
		"password":  "x",
		"tumblelog": fmt.Sprintf("fp%d", time.Now().UnixNano()),
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("Authorization", "Bearer "+string(match[1]))
	reqHeader.Set("Origin", "https://www.tumblr.com")
	reqHeader.Set("Referer", "https://www.tumblr.com/register")
	status, _, body, err = postJSON(ctx, c, "https://www.tumblr.com/api/v2/register/account/validate", payload, reqHeader)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var resp struct {
		Response struct {
			Error string `json:"error"`
			Code  int    `json:"code"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	// A 200 would mean the one-character password passed validation.
	if status != http.StatusBadRequest {
		return unexpected()
	}
	message := strings.ToLower(resp.Response.Error)
	switch {
	case strings.Contains(message, "already exists") || strings.Contains(message, "already registered"):
		return checker.StatusFound, ""
	case strings.Contains(message, "password"):
		// The password is checked after the email, so the email was free.
		return checker.StatusNotFound, ""
	default:
		return unexpected()
	}
}
