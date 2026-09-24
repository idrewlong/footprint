package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&deezer{}) }

// deezer reads the public signup emailCheck gateway. availability true with
// a valid domain is a miss; availability false with a valid domain is a hit.
// An invalid domain is an error. The request does not send mail.
type deezer struct{}

func (deezer) Name() string     { return "deezer" }
func (deezer) Domain() string   { return "deezer.com" }
func (deezer) Category() string { return "entertainment" }
func (deezer) Method() string   { return "register" }

func (s *deezer) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *deezer) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "deezer",
		domain:        "deezer.com",
		category:      "entertainment",
		method:        "register",
		deleteURL:     "https://www.deezer.com/account",
		securityURL:   "https://www.deezer.com/account",
		foundEvidence: "Signup email check said this email is already registered.",
		missEvidence:  "Signup email check said this email is available.",
	}.result(status, detail, elapsed)
}

func (s *deezer) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, "https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var boot struct {
		Results struct {
			CheckForm string `json:"checkForm"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &boot); err != nil || boot.Results.CheckForm == "" {
		return unexpected()
	}
	payload, err := json.Marshal(map[string]string{"EMAIL": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	endpoint := "https://www.deezer.com/ajax/gw-light.php?method=deezer.emailCheck&input=3&api_version=1.0&api_token=" + boot.Results.CheckForm
	postHeader := make(http.Header)
	postHeader.Set("Accept", "application/json")
	status, _, body, err = postJSON(ctx, c, endpoint, payload, postHeader)
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
		Results struct {
			Availability   *bool `json:"availability"`
			DomainValidity *bool `json:"domain_validity"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Results.Availability == nil || resp.Results.DomainValidity == nil {
		return unexpected()
	}
	if !*resp.Results.DomainValidity {
		return checker.StatusError, "invalid email"
	}
	if *resp.Results.Availability {
		return checker.StatusNotFound, ""
	}
	return checker.StatusFound, ""
}
