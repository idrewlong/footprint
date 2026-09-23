package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&replit{}) }

// replit posts the email to the signup existence endpoint. The response
// is an exists boolean. A missing field is an error, not a miss.
type replit struct{}

func (replit) Name() string     { return "replit" }
func (replit) Domain() string   { return "replit.com" }
func (replit) Category() string { return "dev" }
func (replit) Method() string   { return "register" }

func (s *replit) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *replit) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "replit",
		domain:      "replit.com",
		category:    "dev",
		method:      "register",
		deleteURL:   "https://replit.com/account",
		securityURL: "https://replit.com/account",
	}.result(status, detail, elapsed)
}

func (s *replit) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("X-Requested-With", "XMLHttpRequest")
	header.Set("Origin", "https://replit.com")
	header.Set("Referer", "https://replit.com/signup")
	status, _, body, err := postJSON(ctx, c, "https://replit.com/data/user/exists", payload, header)
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
		Exists *bool `json:"exists"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Exists == nil {
		return unexpected()
	}
	if *resp.Exists {
		return checker.StatusFound, ""
	}
	return checker.StatusNotFound, ""
}
