package graph

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

func sampleDoc() report.Document {
	return report.Document{
		Email:    "ada@example.com",
		Username: "ada",
		Results: []checker.Result{
			{Site: "github", Domain: "github.com", Method: "register", Status: checker.StatusFound, Confidence: "high", SecurityURL: "https://github.com/settings/security"},
			{Site: "adobe", Domain: "adobe.com", Method: "login", Status: checker.StatusNotFound},
			{Site: "twitch", Domain: "twitch.tv", Method: "profile", Status: checker.StatusFound, ProfileURL: "https://twitch.tv/ada", Confidence: "medium"},
			{Site: "leakcheck", Domain: "leakcheck.io", Method: "breach", Status: checker.StatusFound, Detail: "Adobe", Breaches: []checker.BreachHit{{Name: "Adobe", Date: "2013-10"}}},
		},
	}
}

func TestBuildLinksSubjectsToFindings(t *testing.T) {
	g := Build(sampleDoc())
	ids := map[string]Node{}
	for _, n := range g.Nodes {
		ids[n.ID] = n
	}
	for _, want := range []string{"email:ada@example.com", "username:ada", "account:github", "profile:twitch", "breach:adobe", "domain:example.com"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("missing node %q; have %v", want, ids)
		}
	}
	// A not_found row must not appear.
	if _, ok := ids["account:adobe"]; ok {
		t.Fatal("a not_found account became a node")
	}
	// Profile ties to the username, account and breach to the email.
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.From+" "+e.Label+" "+e.To] = true
	}
	if !edges["email:ada@example.com has_account account:github"] {
		t.Fatalf("email->account edge missing: %v", edges)
	}
	if !edges["username:ada has_profile profile:twitch"] {
		t.Fatalf("username->profile edge missing: %v", edges)
	}
	if !edges["email:ada@example.com in_breach breach:adobe"] {
		t.Fatalf("email->breach edge missing: %v", edges)
	}
}

func TestGraphMLIsWellFormedAndCarriesNoSecrets(t *testing.T) {
	g := Build(sampleDoc())
	var buf bytes.Buffer
	if err := WriteGraphML(&buf, g); err != nil {
		t.Fatal(err)
	}
	// Must parse as XML.
	if err := xml.Unmarshal(buf.Bytes(), new(struct {
		XMLName xml.Name `xml:"graphml"`
	})); err != nil {
		t.Fatalf("graphml not well formed: %v", err)
	}
	if strings.Contains(buf.String(), "secret") || strings.Contains(strings.ToLower(buf.String()), "password") {
		t.Fatal("graphml carried a forbidden value")
	}
}

func TestNeo4jJSONShape(t *testing.T) {
	g := Build(sampleDoc())
	var buf bytes.Buffer
	if err := WriteNeo4j(&buf, g); err != nil {
		t.Fatal(err)
	}
	var doc neo4jDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("neo4j json invalid: %v", err)
	}
	if len(doc.Nodes) != len(g.Nodes) || len(doc.Relationships) != len(g.Edges) {
		t.Fatalf("neo4j counts: %d/%d nodes, %d/%d rels", len(doc.Nodes), len(g.Nodes), len(doc.Relationships), len(g.Edges))
	}
}

func TestSTIXBundleDeterministicAndTyped(t *testing.T) {
	g := Build(sampleDoc())
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var a, b bytes.Buffer
	if err := WriteSTIX(&a, g, fixed); err != nil {
		t.Fatal(err)
	}
	if err := WriteSTIX(&b, g, fixed); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("STIX export is not deterministic")
	}
	var bundle struct {
		Type    string           `json:"type"`
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(a.Bytes(), &bundle); err != nil {
		t.Fatalf("stix invalid: %v", err)
	}
	if bundle.Type != "bundle" {
		t.Fatalf("root type %q", bundle.Type)
	}
	var haveEmail, haveRel bool
	for _, o := range bundle.Objects {
		switch o["type"] {
		case "email-addr":
			haveEmail = true
		case "relationship":
			haveRel = true
		}
	}
	if !haveEmail || !haveRel {
		t.Fatalf("stix missing observable or relationship: %v", bundle.Objects)
	}
}

func TestMISPAndMaltego(t *testing.T) {
	g := Build(sampleDoc())
	var misp bytes.Buffer
	if err := WriteMISP(&misp, g, "case"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(misp.String(), `"email-src"`) || !strings.Contains(misp.String(), "ada@example.com") {
		t.Fatalf("misp missing email attribute:\n%s", misp.String())
	}
	var mal bytes.Buffer
	if err := WriteMaltegoCSV(&mal, g); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mal.String(), "maltego.EmailAddress") || !strings.Contains(mal.String(), "has_account") {
		t.Fatalf("maltego csv missing rows:\n%s", mal.String())
	}
}

func TestEmptyGraphExportsCleanly(t *testing.T) {
	g := Build(report.Document{})
	for _, fn := range []func() error{
		func() error { return WriteGraphML(new(bytes.Buffer), g) },
		func() error { return WriteNeo4j(new(bytes.Buffer), g) },
		func() error { return WriteSTIX(new(bytes.Buffer), g, time.Time{}) },
		func() error { return WriteMISP(new(bytes.Buffer), g, "x") },
		func() error { return WriteMaltegoCSV(new(bytes.Buffer), g) },
	} {
		if err := fn(); err != nil {
			t.Fatalf("empty graph export failed: %v", err)
		}
	}
}
