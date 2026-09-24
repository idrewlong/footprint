package graph

import (
	"encoding/json"
	"io"
)

// MISP event export. Each node becomes a MISP attribute of the right type
// (email-src, github-username, domain, ip-dst, target-org) under one event.
// Breach names go in as comments, never with stolen values. This is the
// lightweight "event with attributes" shape MISP's import accepts.

type mispAttribute struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Value    string `json:"value"`
	ToIDS    bool   `json:"to_ids"`
	Comment  string `json:"comment,omitempty"`
}

type mispEvent struct {
	Info          string          `json:"info"`
	Distribution  string          `json:"distribution"`
	Analysis      string          `json:"analysis"`
	ThreatLevelID string          `json:"threat_level_id"`
	Attribute     []mispAttribute `json:"Attribute"`
}

// WriteMISP writes a MISP event JSON for the graph. info is the event title.
func WriteMISP(w io.Writer, g Graph, info string) error {
	if info == "" {
		info = "footprint scan"
	}
	event := mispEvent{
		Info:          info,
		Distribution:  "0", // your organization only
		Analysis:      "0", // initial
		ThreatLevelID: "4", // undefined
	}
	for _, n := range g.Nodes {
		attr, ok := mispAttrFor(n)
		if !ok {
			continue
		}
		event.Attribute = append(event.Attribute, attr)
	}
	out := map[string]any{"Event": event}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func mispAttrFor(n Node) (mispAttribute, bool) {
	switch n.Type {
	case NodeEmail:
		return mispAttribute{Type: "email-src", Category: "Payload delivery", Value: n.Label, ToIDS: false}, true
	case NodeUsername:
		return mispAttribute{Type: "text", Category: "Attribution", Value: n.Label, Comment: "username"}, true
	case NodeAccount:
		return mispAttribute{Type: "text", Category: "Social network", Value: n.Attrs["domain"] + ": " + n.Label, Comment: "account found"}, true
	case NodeProfile:
		if url := n.Attrs["url"]; url != "" {
			return mispAttribute{Type: "url", Category: "Social network", Value: url, Comment: "public profile"}, true
		}
		return mispAttribute{Type: "text", Category: "Social network", Value: n.Label, Comment: "public profile"}, true
	case NodeDomain:
		return mispAttribute{Type: "domain", Category: "Network activity", Value: n.Label}, true
	case NodeIP:
		return mispAttribute{Type: "ip-dst", Category: "Network activity", Value: n.Label}, true
	case NodeOrg:
		return mispAttribute{Type: "target-org", Category: "Targeting data", Value: n.Label}, true
	case NodeBreach:
		comment := "breach"
		if d := n.Attrs["date"]; d != "" {
			comment = "breach " + d
		}
		return mispAttribute{Type: "text", Category: "Other", Value: n.Label, Comment: comment}, true
	default:
		return mispAttribute{}, false
	}
}
