package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&edx{}) }

// edx posts to the public registration validation endpoint. An empty
// email decision means the address can still be registered. A decision
// that says the email already belongs to an account is a hit. Other
// validation messages (invalid format, etc.) are errors, not misses.
type edx struct{}

func (edx) Name() string     { return "edx" }
func (edx) Domain() string   { return "edx.org" }
func (edx) Category() string { return "education" }
func (edx) Method() string   { return "register" }

func (s *edx) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *edx) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "edx",
		domain:        "edx.org",
		category:      "education",
		method:        "register",
		deleteURL:     "https://account.edx.org/",
		securityURL:   "https://account.edx.org/",
		foundEvidence: "Registration check said this email already belongs to an account.",
		missEvidence:  "Registration check said this email can still be registered.",
	}.result(status, detail, elapsed)
}

func (s *edx) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postJSON(ctx, c, "https://courses.edx.org/api/user/v1/validation/registration", payload, header)
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
		ValidationDecisions struct {
			Email *string `json:"email"`
		} `json:"validation_decisions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.ValidationDecisions.Email == nil {
		return unexpected()
	}
	decision := strings.TrimSpace(*resp.ValidationDecisions.Email)
	if decision == "" {
		return checker.StatusNotFound, ""
	}
	lower := strings.ToLower(decision)
	switch {
	case strings.Contains(lower, "already associated") ||
		strings.Contains(lower, "belongs to an existing") ||
		strings.Contains(lower, "existing account"):
		return checker.StatusFound, ""
	case strings.Contains(lower, "valid email") || strings.Contains(lower, "invalid"):
		return checker.StatusError, "invalid email"
	default:
		return unexpected()
	}
}
