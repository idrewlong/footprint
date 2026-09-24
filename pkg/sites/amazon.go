package sites

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&amazon{}) }

// amazon submits only the email step of the identifier-first sign-in form.
// A known account gets the password step. An unknown one is redirected to
// the claim/intent page that offers to create an account. No password is
// sent and no mail is sent.
type amazon struct{}

func (amazon) Name() string     { return "amazon" }
func (amazon) Domain() string   { return "amazon.com" }
func (amazon) Category() string { return "shopping" }
func (amazon) Method() string   { return "login" }

const amazonSignin = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0" +
	"&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F" +
	"&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select" +
	"&openid.assoc_handle=usflex&openid.mode=checkid_setup" +
	"&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select" +
	"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"

// amazonAccept is the browser's Accept header. Amazon answers a bare
// "text/html" on the form post with 406 Not Acceptable.
const amazonAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func (s *amazon) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *amazon) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "amazon",
		domain:        "amazon.com",
		category:      "shopping",
		method:        "login",
		deleteURL:     "https://www.amazon.com/privacy/data-deletion",
		securityURL:   "https://www.amazon.com/ax/account/manage",
		foundEvidence: "Sign-in asked for a password after this email.",
		missEvidence:  "Sign-in offered to create an account for this email.",
	}.result(status, detail, elapsed)
}

func (s *amazon) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	page, cookies, status, detail := s.signinForm(ctx, c)
	if status != "" {
		return status, detail
	}
	action, form, ok := amazonForm(page)
	if !ok {
		return checker.StatusError, "sign-in page did not include the email form"
	}
	form.Set("email", email)
	header := make(http.Header)
	header.Set("Accept", amazonAccept)
	header.Set("Referer", amazonSignin)
	if cookies != "" {
		header.Set("Cookie", cookies)
	}
	code, respHeader, body, err := postForm(ctx, c, action, form, header)
	if err != nil {
		return fromErr(err)
	}
	return interpretAmazon(code, respHeader, body)
}

// signinForm follows the redirect from ap/signin to the claim page by hand,
// because the shared client does not follow redirects.
func (s *amazon) signinForm(ctx context.Context, c *http.Client) ([]byte, string, checker.Status, string) {
	target := amazonSignin
	var headers []http.Header
	for range 3 {
		header := make(http.Header)
		header.Set("Accept", amazonAccept)
		if cookies := cookiePairs(headers...); cookies != "" {
			header.Set("Cookie", cookies)
		}
		code, respHeader, body, err := get(ctx, c, target, header)
		if err != nil {
			status, detail := fromErr(err)
			return nil, "", status, detail
		}
		headers = append(headers, respHeader)
		if amazonLimited(code, body) {
			status, detail := finishLimited()
			return nil, "", status, detail
		}
		if code == http.StatusOK {
			return body, cookiePairs(headers...), "", ""
		}
		next, ok := resolveAmazon(respHeader.Get("Location"))
		if code < 300 || code > 399 || !ok {
			status, detail := unexpected()
			return nil, "", status, detail
		}
		target = next
	}
	return nil, "", checker.StatusError, "too many redirects"
}

func amazonForm(page []byte) (string, url.Values, bool) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(page))
	if err != nil {
		return "", nil, false
	}
	sel := doc.Find(`form[name="signIn"]`).First()
	rawAction, ok := sel.Attr("action")
	if !ok {
		return "", nil, false
	}
	action, ok := resolveAmazon(rawAction)
	if !ok {
		return "", nil, false
	}
	form := url.Values{}
	sel.Find(`input[type="hidden"]`).Each(func(_ int, input *goquery.Selection) {
		if name, ok := input.Attr("name"); ok && name != "" {
			value, _ := input.Attr("value")
			form.Set(name, value)
		}
	})
	return action, form, true
}

// resolveAmazon keeps redirects and form actions on www.amazon.com.
func resolveAmazon(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	base, _ := url.Parse("https://www.amazon.com/")
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "https" || resolved.Host != "www.amazon.com" {
		return "", false
	}
	return resolved.String(), true
}

func interpretAmazon(status int, header http.Header, body []byte) (checker.Status, string) {
	if amazonLimited(status, body) {
		return finishLimited()
	}
	if status >= 300 && status <= 399 {
		location, ok := resolveAmazon(header.Get("Location"))
		if ok && strings.Contains(location, "/ax/claim/intent") {
			return checker.StatusNotFound, ""
		}
		return unexpected()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	text := string(body)
	if strings.Contains(text, "new to Amazon") {
		return checker.StatusNotFound, ""
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return unexpected()
	}
	if doc.Find(`form[name="signIn"] input[name="password"]`).Length() > 0 {
		return checker.StatusFound, ""
	}
	return unexpected()
}

// amazonLimited treats a 503 as a block. Amazon serves its robot-check
// page with a 503 when it throttles a client.
func amazonLimited(status int, body []byte) bool {
	return status == http.StatusServiceUnavailable || limited(status, body) || amazonChallenge(body)
}

// amazonChallenge reports the image or puzzle captcha that Amazon shows
// instead of the next sign-in step.
func amazonChallenge(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "auth-captcha") ||
		strings.Contains(text, "enter the characters you see") ||
		strings.Contains(text, "solve this puzzle") ||
		strings.Contains(text, "/errors/validatecaptcha")
}
