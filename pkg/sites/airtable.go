package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&airtable{}) }

// airtable reads the public signup email availability check. isAvailable
// true is a miss; false with EMAIL_ALREADY_IN_USE is a hit. Other error
// types stay errors. The request does not send mail.
type airtable struct{}

func (airtable) Name() string     { return "airtable" }
func (airtable) Domain() string   { return "airtable.com" }
func (airtable) Category() string { return "productivity" }
func (airtable) Method() string   { return "register" }

func (s *airtable) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *airtable) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "airtable",
		domain:        "airtable.com",
		category:      "productivity",
		method:        "register",
		deleteURL:     "https://airtable.com/account",
		securityURL:   "https://airtable.com/account",
		foundEvidence: "Signup endpoint said this email is already in use.",
		missEvidence:  "Signup endpoint said this email is available.",
	}.result(status, detail, elapsed)
}

func (s *airtable) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://airtable.com/checkEmailAvailability?address=" + url.QueryEscape(email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
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
		Available *bool  `json:"isAvailable"`
		ErrorType string `json:"errorType"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Available == nil {
		return unexpected()
	}
	if *resp.Available {
		return checker.StatusNotFound, ""
	}
	switch strings.ToUpper(resp.ErrorType) {
	case "EMAIL_ALREADY_IN_USE", "SSO_REQUIRED":
		return checker.StatusFound, ""
	case "INVALID_EMAIL":
		return checker.StatusError, "invalid email"
	default:
		return unexpected()
	}
}
