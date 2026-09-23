package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&duolingo{}) }

// duolingo reads the public user lookup used by signup. An empty users
// list means the address is not registered. The request is a GET and
// does not send mail.
type duolingo struct{}

func (duolingo) Name() string     { return "duolingo" }
func (duolingo) Domain() string   { return "duolingo.com" }
func (duolingo) Category() string { return "education" }
func (duolingo) Method() string   { return "register" }

func (s *duolingo) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *duolingo) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "duolingo",
		domain:      "duolingo.com",
		category:    "education",
		method:      "register",
		deleteURL:   "https://www.duolingo.com/settings/account",
		securityURL: "https://www.duolingo.com/settings/account",
	}.result(status, detail, elapsed)
}

func (s *duolingo) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://www.duolingo.com/2017-06-30/users?email=" + url.QueryEscape(email)
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
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return unexpected()
	}
	raw, ok := envelope["users"]
	if !ok {
		return unexpected()
	}
	var users []json.RawMessage
	if err := json.Unmarshal(raw, &users); err != nil {
		return unexpected()
	}
	if len(users) == 0 {
		return checker.StatusNotFound, ""
	}
	return checker.StatusFound, ""
}
