package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&gumroad{}) }

// gumroad posts an incomplete registration so the form validator reports
// whether the email is already registered. The password is too short / known
// to HIBP to create an account, and the request does not ask Gumroad to send mail.
type gumroad struct{}

func (gumroad) Name() string     { return "gumroad" }
func (gumroad) Domain() string   { return "gumroad.com" }
func (gumroad) Category() string { return "shopping" }
func (gumroad) Method() string   { return "register" }

func (s *gumroad) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *gumroad) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "gumroad",
		domain:        "gumroad.com",
		category:      "shopping",
		method:        "register",
		deleteURL:     "https://gumroad.com/help/article/37-how-to-delete-your-gumroad-account",
		securityURL:   "https://gumroad.com/settings",
		foundEvidence: "Signup validator said this email is already registered.",
		missEvidence:  "Signup validator did not report this email as registered.",
	}.result(status, detail, elapsed)
}

func (s *gumroad) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]any{
		"user": map[string]string{
			"email":    email,
			"password": "x",
			"name":     "fp",
		},
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postJSON(ctx, c, "https://gumroad.com/users", payload, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var resp struct {
		Success *bool  `json:"success"`
		Error   string `json:"error_message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Success == nil {
		return unexpected()
	}
	// A success response would mean the incomplete form was accepted.
	if *resp.Success {
		return checker.StatusError, "unexpected account response"
	}
	message := strings.ToLower(resp.Error)
	switch {
	case strings.Contains(message, "already exists") || strings.Contains(message, "already registered"):
		return checker.StatusFound, ""
	case strings.Contains(message, "password") && (strings.Contains(message, "breach") || strings.Contains(message, "haveibeenpwned") || strings.Contains(message, "too short") || strings.Contains(message, "harder to guess")):
		// Password rejected after the email passed the uniqueness check.
		return checker.StatusNotFound, ""
	default:
		return unexpected()
	}
}
