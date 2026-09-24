package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

// catalogFunc selects sites by category and name, as sites.Select does.
type catalogFunc func(categories, names []string) ([]checker.Site, error)

// config is fixed when the server starts. The operator sets it on the
// command line; the model calling the tools cannot change it. That keeps
// the choices with legal or privacy weight (alerting the subject, where
// traffic exits, which case a save belongs to) with the person running it.
type config struct {
	version     string
	catalog     catalogFunc
	transport   http.RoundTripper
	concurrency int
	timeout     time.Duration
	allowNotify bool
	save        bool
	caseDir     string
	caseID      string
	authority   string
	operator    string
}

// newServer registers the three tools against cfg.
func newServer(cfg config) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "footprint", Version: cfg.version}, nil)
	openWorld := true
	notDestructive := false

	mcp.AddTool(server, &mcp.Tool{
		Name:         "scan_email",
		OutputSchema: outputSchema[scanEmailOutput](),
		Title:        "Scan an email address",
		Description: "Check which supported sites have an account for an email address, using public signup, login, and breach signals. " +
			"Returns summary counts plus one result per site. `complete` is false when any check was rate limited, errored, or skipped; " +
			"report those as unchecked, never as 'no account'. Checks that would email the address run only if the operator started the server with --allow-notify.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &openWorld, DestructiveHint: &notDestructive},
	}, cfg.scanEmail)

	mcp.AddTool(server, &mcp.Tool{
		Name:         "check_site",
		OutputSchema: outputSchema[checkSiteOutput](),
		Title:        "Check one site",
		Description:  "Check a single site for an email address. Useful for retrying a site that was rate limited in scan_email.",
		Annotations:  &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &openWorld, DestructiveHint: &notDestructive},
	}, cfg.checkSite)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_sites",
		Title:       "List supported sites",
		Description: "List the sites footprint can check, with category, method, and whether the check can email the address.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, cfg.listSites)

	return server
}

// outputSchema derives T's JSON schema with checker.Result described as it
// is actually encoded. Result writes duration_ms from an in-memory Duration
// through a custom MarshalJSON, so reflection alone would reject its output.
func outputSchema[T any]() *jsonschema.Schema {
	result, err := jsonschema.For[checker.Result](nil)
	if err != nil {
		panic(err)
	}
	result.Properties["duration_ms"] = &jsonschema.Schema{Type: "integer", Description: "how long the check took, in milliseconds"}
	result.Required = append(result.Required, "duration_ms")
	schema, err := jsonschema.For[T](&jsonschema.ForOptions{
		TypeSchemas: map[reflect.Type]*jsonschema.Schema{reflect.TypeFor[checker.Result](): result},
	})
	if err != nil {
		panic(err)
	}
	return schema
}

type scanEmailInput struct {
	Email      string   `json:"email" jsonschema:"email address to check"`
	Categories []string `json:"categories,omitempty" jsonschema:"only check these categories (see list_sites)"`
	OnlyFound  bool     `json:"only_found,omitempty" jsonschema:"return only found rows; summary still counts every check"`
}

// Summary counts every check that ran. Skipped counts checks that were not
// run because they would email the address.
type Summary struct {
	Found       int `json:"found"`
	NotFound    int `json:"not_found"`
	RateLimited int `json:"rate_limited"`
	Error       int `json:"error"`
	Skipped     int `json:"skipped"`
}

type scanEmailOutput struct {
	Email string `json:"email"`
	// Complete is true only when every selected check ran and returned a
	// definite found or not_found.
	Complete bool    `json:"complete"`
	Summary  Summary `json:"summary"`
	// Note says in words what Complete means for this run, so a model
	// relaying the result has the caveat in front of it.
	Note      string           `json:"note"`
	Skipped   []string         `json:"skipped,omitempty"`
	Results   []checker.Result `json:"results"`
	SavedTo   string           `json:"saved_to,omitempty"`
	AuditHead string           `json:"audit_head,omitempty"`
}

func (cfg config) scanEmail(ctx context.Context, _ *mcp.CallToolRequest, in scanEmailInput) (*mcp.CallToolResult, scanEmailOutput, error) {
	email, ok := normalizeEmail(in.Email)
	if !ok {
		return nil, scanEmailOutput{}, errors.New("email address is not valid")
	}
	selected, err := cfg.catalog(in.Categories, nil)
	if err != nil {
		return nil, scanEmailOutput{}, err
	}
	var skipped []string
	if !cfg.allowNotify {
		kept := selected[:0:0]
		for _, site := range selected {
			if checker.Notifies(site.Method()) {
				skipped = append(skipped, site.Name())
				continue
			}
			kept = append(kept, site)
		}
		selected = kept
	}
	if len(selected) == 0 {
		return nil, scanEmailOutput{}, errors.New("no sites matched without checks that would email the address")
	}

	start := time.Now()
	results := cfg.run(ctx, email, selected)
	elapsed := time.Since(start)
	if err := ctx.Err(); err != nil {
		return nil, scanEmailOutput{}, fmt.Errorf("scan cancelled: %w", err)
	}

	full := report.Build(email, results, false)
	report.ScoreConfidence(&full)
	out := scanEmailOutput{
		Email: email,
		Summary: Summary{
			Found:       full.Summary.Found,
			NotFound:    full.Summary.NotFound,
			RateLimited: full.Summary.RateLimited,
			Error:       full.Summary.Error,
			Skipped:     len(skipped),
		},
		Skipped: skipped,
		Results: full.Results,
	}
	out.Complete = out.Summary.RateLimited == 0 && out.Summary.Error == 0 && out.Summary.Skipped == 0
	out.Note = note(out.Summary)
	if in.OnlyFound {
		doc := report.Build(email, results, true)
		report.ScoreConfidence(&doc)
		out.Results = doc.Results
	}
	if out.Results == nil {
		out.Results = []checker.Result{}
	}

	if cfg.save {
		path, err := casefile.Save(cfg.caseDir, casefile.Saved{
			Version:   cfg.version,
			RanAt:     start,
			ElapsedMS: elapsed.Milliseconds(),
			Kind:      "identity",
			CaseID:    cfg.caseID,
			Authority: cfg.authority,
			Operator:  cfg.operator,
			Report:    full,
		})
		if err != nil {
			return nil, scanEmailOutput{}, fmt.Errorf("scan finished but saving the case failed: %w", err)
		}
		out.SavedTo = path
		out.AuditHead, _ = casefile.Head(cfg.caseDir)
	}
	return nil, out, nil
}

// note states the coverage of a run in one sentence.
func note(s Summary) string {
	checked := s.Found + s.NotFound + s.RateLimited + s.Error
	var gaps []string
	if s.RateLimited > 0 {
		gaps = append(gaps, fmt.Sprintf("%d rate limited", s.RateLimited))
	}
	if s.Error > 0 {
		gaps = append(gaps, fmt.Sprintf("%d errored", s.Error))
	}
	msg := fmt.Sprintf("%d of %d checks gave a definite answer: %d found, %d not found.", s.Found+s.NotFound, checked, s.Found, s.NotFound)
	if len(gaps) > 0 {
		msg += " Could not check " + strings.Join(gaps, " and ") + "; their accounts are unknown, not absent. check_site can retry them."
	}
	if s.Skipped > 0 {
		msg += fmt.Sprintf(" %d checks that would email the address were skipped; the operator must restart the server with --allow-notify to include them.", s.Skipped)
	}
	if len(gaps) == 0 && s.Skipped == 0 {
		msg += " Coverage is complete for the supported sites."
	}
	return msg
}

type checkSiteInput struct {
	Email string `json:"email" jsonschema:"email address to check"`
	Site  string `json:"site" jsonschema:"site name from list_sites"`
}

type checkSiteOutput struct {
	Result checker.Result `json:"result"`
}

func (cfg config) checkSite(ctx context.Context, _ *mcp.CallToolRequest, in checkSiteInput) (*mcp.CallToolResult, checkSiteOutput, error) {
	email, ok := normalizeEmail(in.Email)
	if !ok {
		return nil, checkSiteOutput{}, errors.New("email address is not valid")
	}
	name := strings.TrimSpace(in.Site)
	if name == "" {
		return nil, checkSiteOutput{}, errors.New("site is required")
	}
	selected, err := cfg.catalog(nil, []string{name})
	if err != nil {
		return nil, checkSiteOutput{}, err
	}
	site := selected[0]
	if checker.Notifies(site.Method()) && !cfg.allowNotify {
		return nil, checkSiteOutput{}, fmt.Errorf("%s uses a %s check that can email the address; the operator must restart the server with --allow-notify to run it", site.Name(), site.Method())
	}
	results := cfg.run(ctx, email, selected)
	if err := ctx.Err(); err != nil {
		return nil, checkSiteOutput{}, fmt.Errorf("check cancelled: %w", err)
	}
	doc := report.Build(email, results, false)
	report.ScoreConfidence(&doc)
	return nil, checkSiteOutput{Result: doc.Results[0]}, nil
}

type listSitesInput struct {
	Category string `json:"category,omitempty" jsonschema:"only list this category"`
}

type siteInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Category string `json:"category"`
	Method   string `json:"method"`
	// Notifies is true when the check can email the address.
	Notifies bool `json:"notifies"`
	// Enabled is false for a notifying check the server was not allowed to run.
	Enabled bool `json:"enabled"`
}

type listSitesOutput struct {
	Sites []siteInfo `json:"sites"`
}

func (cfg config) listSites(_ context.Context, _ *mcp.CallToolRequest, in listSitesInput) (*mcp.CallToolResult, listSitesOutput, error) {
	var categories []string
	if c := strings.TrimSpace(in.Category); c != "" {
		categories = []string{c}
	}
	selected, err := cfg.catalog(categories, nil)
	if err != nil {
		return nil, listSitesOutput{}, err
	}
	out := listSitesOutput{Sites: make([]siteInfo, 0, len(selected))}
	for _, site := range selected {
		notifies := checker.Notifies(site.Method())
		out.Sites = append(out.Sites, siteInfo{
			Name:     site.Name(),
			Domain:   site.Domain(),
			Category: site.Category(),
			Method:   site.Method(),
			Notifies: notifies,
			Enabled:  !notifies || cfg.allowNotify,
		})
	}
	return nil, out, nil
}

func (cfg config) run(ctx context.Context, email string, selected []checker.Site) []checker.Result {
	var results []checker.Result
	for res := range checker.Run(ctx, email, selected, checker.Options{
		Concurrency: cfg.concurrency,
		Timeout:     cfg.timeout,
		Transport:   cfg.transport,
	}) {
		results = append(results, res)
	}
	return results
}

// normalizeEmail accepts a bare address only, with a dotted domain. It
// matches the CLI's rule so both front ends accept the same subjects.
func normalizeEmail(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t<>") {
		return "", false
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", false
	}
	at := strings.LastIndex(addr.Address, "@")
	if at <= 0 || at == len(addr.Address)-1 {
		return "", false
	}
	domain := addr.Address[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	return addr.Address, true
}

// operator names who ran the server, for the audit log, as the CLI does.
func operator() string {
	for _, key := range []string{"FOOTPRINT_OPERATOR", "USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}
