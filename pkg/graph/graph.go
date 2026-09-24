// Package graph turns a footprint report into a pivot graph and exports it in
// formats an analyst's tools read: GraphML, a Neo4j-friendly JSON, a STIX 2.1
// bundle, a MISP event, and Maltego entity CSV. It only restructures what the
// report already found; it never fetches anything or invents links, and it
// carries no password, hash, or other stolen value, only breach names and
// dates.
package graph

import (
	"sort"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

// NodeType names the kind of thing a node represents.
type NodeType string

const (
	NodeEmail    NodeType = "email"
	NodeUsername NodeType = "username"
	NodeAccount  NodeType = "account"
	NodeProfile  NodeType = "profile"
	NodeDomain   NodeType = "domain"
	NodeIP       NodeType = "ip"
	NodeOrg      NodeType = "org"
	NodeBreach   NodeType = "breach"
)

// Node is one entity in the pivot graph. ID is stable and unique within a
// graph. Attrs holds extra facts (a profile URL, a breach date, a confidence
// level) as strings so every exporter can render them.
type Node struct {
	ID    string
	Type  NodeType
	Label string
	Attrs map[string]string
}

// Edge is a directed link between two nodes, labeled with the relationship.
type Edge struct {
	From  string
	To    string
	Label string
}

// Graph is a set of nodes and edges. Nodes are unique by ID and edges by the
// (From, To, Label) triple, both in insertion order.
type Graph struct {
	Nodes []Node
	Edges []Edge
	byID  map[string]int
	byRel map[string]struct{}
}

func newGraph() *Graph {
	return &Graph{byID: map[string]int{}, byRel: map[string]struct{}{}}
}

// addNode inserts a node if its ID is new and merges attrs otherwise, so a
// later mention can fill a fact an earlier one lacked.
func (g *Graph) addNode(n Node) {
	if idx, ok := g.byID[n.ID]; ok {
		existing := g.Nodes[idx]
		if existing.Label == "" {
			existing.Label = n.Label
		}
		for k, v := range n.Attrs {
			if v == "" {
				continue
			}
			if existing.Attrs == nil {
				existing.Attrs = map[string]string{}
			}
			if existing.Attrs[k] == "" {
				existing.Attrs[k] = v
			}
		}
		g.Nodes[idx] = existing
		return
	}
	g.byID[n.ID] = len(g.Nodes)
	g.Nodes = append(g.Nodes, n)
}

func (g *Graph) addEdge(from, to, label string) {
	if from == "" || to == "" || from == to {
		return
	}
	if _, ok := g.byID[from]; !ok {
		return
	}
	if _, ok := g.byID[to]; !ok {
		return
	}
	key := from + "\x00" + to + "\x00" + label
	if _, ok := g.byRel[key]; ok {
		return
	}
	g.byRel[key] = struct{}{}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Label: label})
}

// Build turns a report document into a pivot graph. It connects the email and
// username subjects to the accounts, profiles, and breaches found for them,
// and to the domain, network, and organization the report describes. Only
// found rows become nodes; unknown and missed rows are left out.
func Build(doc report.Document) Graph {
	g := newGraph()

	emailID := ""
	if doc.Email != "" {
		emailID = "email:" + strings.ToLower(doc.Email)
		g.addNode(Node{ID: emailID, Type: NodeEmail, Label: doc.Email})
	}
	usernameID := ""
	if doc.Username != "" {
		usernameID = "username:" + strings.ToLower(doc.Username)
		g.addNode(Node{ID: usernameID, Type: NodeUsername, Label: doc.Username})
	}

	// The email's own domain is a pivot even before any DNS lookup.
	mailDomainID := ""
	if at := strings.LastIndex(doc.Email, "@"); at > 0 && at < len(doc.Email)-1 {
		d := strings.ToLower(doc.Email[at+1:])
		mailDomainID = "domain:" + d
		g.addNode(Node{ID: mailDomainID, Type: NodeDomain, Label: d})
		g.addEdge(emailID, mailDomainID, "uses_domain")
	}

	subjectDomainID := ""
	if doc.SubjectDomain != "" {
		subjectDomainID = "domain:" + strings.ToLower(doc.SubjectDomain)
		g.addNode(Node{ID: subjectDomainID, Type: NodeDomain, Label: doc.SubjectDomain})
	}
	ipID := ""
	if doc.SubjectIP != "" {
		ipID = "ip:" + doc.SubjectIP
		g.addNode(Node{ID: ipID, Type: NodeIP, Label: doc.SubjectIP})
		g.addEdge(subjectDomainID, ipID, "resolves_to")
	}
	if doc.SubjectEntity != "" {
		orgID := "org:" + strings.ToLower(doc.SubjectEntity)
		g.addNode(Node{ID: orgID, Type: NodeOrg, Label: doc.SubjectEntity})
	}

	for _, res := range doc.Results {
		if res.Status != checker.StatusFound {
			continue
		}
		switch res.Method {
		case "register", "login", "password_reset":
			id := "account:" + res.Site
			g.addNode(Node{ID: id, Type: NodeAccount, Label: res.Site, Attrs: accountAttrs(res)})
			g.addEdge(emailID, id, "has_account")
		case "profile":
			id := "profile:" + res.Site
			attrs := map[string]string{"domain": res.Domain}
			if res.ProfileURL != "" {
				attrs["url"] = res.ProfileURL
			}
			if res.Confidence != "" {
				attrs["confidence"] = res.Confidence
			}
			g.addNode(Node{ID: id, Type: NodeProfile, Label: res.Site, Attrs: attrs})
			// A profile is tied to the username when there is one, else to
			// the email that surfaced it.
			if usernameID != "" {
				g.addEdge(usernameID, id, "has_profile")
			} else {
				g.addEdge(emailID, id, "has_profile")
			}
		case "breach":
			for _, hit := range res.Breaches {
				name := strings.TrimSpace(hit.Name)
				if name == "" {
					continue
				}
				id := "breach:" + strings.ToLower(name)
				attrs := map[string]string{"source": res.Site}
				if hit.Date != "" {
					attrs["date"] = hit.Date
				}
				g.addNode(Node{ID: id, Type: NodeBreach, Label: name, Attrs: attrs})
				g.addEdge(emailID, id, "in_breach")
			}
		case "dns":
			// DNS rows describe the subject domain already added above.
		}
	}

	// Tie the email's domain to the subject domain when they are the same.
	if mailDomainID != "" && mailDomainID == subjectDomainID {
		// Same node; nothing to link.
	}
	return *g
}

func accountAttrs(res checker.Result) map[string]string {
	attrs := map[string]string{"domain": res.Domain, "method": res.Method}
	if res.Confidence != "" {
		attrs["confidence"] = res.Confidence
	}
	if res.SecurityURL != "" {
		attrs["security_url"] = res.SecurityURL
	}
	if res.DeleteURL != "" {
		attrs["delete_url"] = res.DeleteURL
	}
	return attrs
}

// sortedAttrKeys returns a node's attribute keys in a stable order so every
// exporter emits deterministic output.
func sortedAttrKeys(attrs map[string]string) []string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
