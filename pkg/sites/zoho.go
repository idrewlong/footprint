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

func init() { Register(&zoho{}) }

// zoho reads the sign-in lookup used before a password is entered.
// U401 / "does not exist" is a miss. A 2xx lookup that includes a digest
// is a hit (password step). The request does not send mail.
type zoho struct{}

func (zoho) Name() string     { return "zoho" }
func (zoho) Domain() string   { return "zoho.com" }
func (zoho) Category() string { return "productivity" }
func (zoho) Method() string   { return "login" }

func (s *zoho) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *zoho) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "zoho",
		domain:        "zoho.com",
		category:      "productivity",
		method:        "login",
		deleteURL:     "https://help.zoho.com/portal/en/kb/accounts/manage-your-zoho-account/articles/delete-your-zoho-account",
		securityURL:   "https://accounts.zoho.com/home#security/securitypwd",
		foundEvidence: "Sign-in lookup said this email is already registered.",
		missEvidence:  "Sign-in lookup said this email does not exist.",
	}.result(status, detail, elapsed)
}

func (s *zoho) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	status, header, body, err := get(ctx, c, "https://accounts.zoho.com/signin", nil)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	token := csrfCookie(header, "iamcsr")
	if token == "" {
		return unexpected()
	}
	form := url.Values{}
	form.Set("mode", "primary")
	form.Set("cli_time", "0")
	form.Set("servicename", "VirtualOffice")
	form.Set("service_language", "en")
	endpoint := "https://accounts.zoho.com/signin/v2/lookup/" + url.PathEscape(email)
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("Referer", "https://accounts.zoho.com/signin")
	reqHeader.Set("X-ZCSRF-TOKEN", "iamcsrcoo="+token)
	reqHeader.Set("Cookie", "iamcsr="+token)
	status, _, body, err = postForm(ctx, c, endpoint, form, reqHeader)
	if err != nil {
		return fromErr(err)
	}
	return interpretZoho(status, body)
}

func interpretZoho(status int, body []byte) (checker.Status, string) {
	if limited(status, body) {
		return finishLimited()
	}
	if htmlPage(body) {
		return unexpected()
	}
	var resp struct {
		StatusCode int `json:"status_code"`
		Lookup     *struct {
			Digest string `json:"digest"`
		} `json:"lookup"`
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.StatusCode == 0 {
		return unexpected()
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		if resp.Lookup != nil && strings.TrimSpace(resp.Lookup.Digest) != "" {
			return checker.StatusFound, ""
		}
		return unexpected()
	}
	for _, item := range resp.Errors {
		code := strings.ToUpper(item.Code)
		message := strings.ToLower(item.Message)
		if code == "U401" || strings.Contains(message, "does not exist") {
			return checker.StatusNotFound, ""
		}
	}
	if strings.Contains(strings.ToLower(resp.Message), "does not exist") {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}
