package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&huggingface{}) }

// huggingface reads the public user overview. "This user does not exist"
// is a miss. A full name on a 200 is the public display name. A redirect
// that only changes the username's case is requested once; other
// redirects are an error.
type huggingface struct{}

func (huggingface) Name() string     { return "huggingface" }
func (huggingface) Domain() string   { return "huggingface.co" }
func (huggingface) Category() string { return "dev" }
func (huggingface) Method() string   { return "profile" }

func (s *huggingface) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail, canonical := s.lookup(ctx, c, username)
	name := username
	if canonical != "" {
		name = canonical
	}
	return profileResult("huggingface", "huggingface.co", "dev", profileURL("https://huggingface.co/", name), status, detail, time.Since(start))
}

func (s *huggingface) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string, string) {
	status, header, body, err := get(ctx, c, profileURL("https://huggingface.co/api/users/", username)+"/overview")
	if err != nil {
		st, detail := fromErr(err)
		return st, detail, ""
	}
	if limited(status, body) {
		st, detail := finishLimited()
		return st, detail, ""
	}
	canonical := ""
	if next, ok := huggingfaceCanonical(header.Get("Location"), username); ok && isRedirect(status) {
		canonical = next
		status, _, body, err = get(ctx, c, profileURL("https://huggingface.co/api/users/", next)+"/overview")
		if err != nil {
			st, detail := fromErr(err)
			return st, detail, ""
		}
		if limited(status, body) {
			st, detail := finishLimited()
			return st, detail, ""
		}
	}
	if status == http.StatusNotFound && strings.Contains(strings.ToLower(string(body)), "does not exist") {
		return checker.StatusNotFound, "", ""
	}
	if status != http.StatusOK {
		st, detail := unexpected()
		return st, detail, ""
	}
	var resp struct {
		Fullname string `json:"fullname"`
		ID       string `json:"_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.ID == "" {
		st, detail := unexpected()
		return st, detail, ""
	}
	return checker.StatusFound, resp.Fullname, canonical
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// huggingfaceCanonical accepts a redirect only when it points at the same
// overview path with different letter case.
func huggingfaceCanonical(location, username string) (string, bool) {
	if location == "" || username == "" {
		return "", false
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	if parsed.Host != "" && !strings.EqualFold(parsed.Host, "huggingface.co") {
		return "", false
	}
	const prefix = "/api/users/"
	const suffix = "/overview"
	path := parsed.EscapedPath()
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	name, err := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix))
	if err != nil || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	if name == username || !strings.EqualFold(name, username) {
		return "", false
	}
	return name, true
}
