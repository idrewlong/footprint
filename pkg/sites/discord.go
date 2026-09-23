package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&discord{}) }

// discord posts an incomplete registration so the form validator reports
// whether the email is already registered. The password is too short to
// create an account, and the request does not ask Discord to send mail.
type discord struct{}

func (discord) Name() string     { return "discord" }
func (discord) Domain() string   { return "discord.com" }
func (discord) Category() string { return "social" }
func (discord) Method() string   { return "register" }

func (s *discord) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *discord) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "discord",
		domain:        "discord.com",
		category:      "social",
		method:        "register",
		deleteURL:     "https://support.discord.com/hc/en-us/articles/212500837",
		securityURL:   "https://discord.com/settings/account",
		foundEvidence: "Signup validator said this email is already registered.",
		missEvidence:  "Signup validator did not report this email as registered.",
	}.result(status, detail, elapsed)
}

func (s *discord) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]any{
		"email":         email,
		"username":      "fp",
		"password":      "x",
		"date_of_birth": "",
		"consent":       true,
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postJSON(ctx, c, "https://discord.com/api/v9/auth/register", payload, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	// A success response would mean the incomplete form was accepted.
	// That is not a "not registered" answer, and it must not be treated as one.
	if status == http.StatusOK || status == http.StatusCreated {
		return checker.StatusError, "unexpected account response"
	}
	var resp struct {
		Errors struct {
			Email struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"_errors"`
			} `json:"email"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	for _, item := range resp.Errors.Email.Errors {
		code := strings.ToUpper(item.Code)
		message := strings.ToLower(item.Message)
		if code == "EMAIL_ALREADY_REGISTERED" || strings.Contains(message, "already") {
			return checker.StatusFound, ""
		}
		if item.Code != "" || item.Message != "" {
			return unexpected()
		}
	}
	if status == http.StatusBadRequest && len(resp.Errors.Email.Errors) == 0 {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}
