package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// STIX 2.1 export. Each graph node becomes a Cyber Observable (email-addr,
// user-account, domain-name, ipv4-addr) or, for a breach, a note that names
// the breach without any stolen value. Edges become relationship objects.
// IDs are deterministic (derived from the node id) so re-exporting the same
// case yields the same bundle, which matters for evidence.

type stixObject map[string]any

// WriteSTIX writes a STIX 2.1 bundle for the graph. now sets the created and
// modified timestamps; pass a zero time to use the current UTC time.
func WriteSTIX(w io.Writer, g Graph, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	ts := now.UTC().Format(time.RFC3339)

	idFor := func(kind, nodeID string) string {
		sum := sha256.Sum256([]byte(kind + "\x00" + nodeID))
		return kind + "--" + uuidFromBytes(sum[:16])
	}

	objects := make([]stixObject, 0, len(g.Nodes)+len(g.Edges))
	stixID := map[string]string{} // graph node id -> stix id

	for _, n := range g.Nodes {
		var obj stixObject
		var sid string
		switch n.Type {
		case NodeEmail:
			sid = idFor("email-addr", n.ID)
			obj = stixObject{"type": "email-addr", "spec_version": "2.1", "id": sid, "value": n.Label}
		case NodeUsername, NodeAccount, NodeProfile:
			sid = idFor("user-account", n.ID)
			obj = stixObject{"type": "user-account", "spec_version": "2.1", "id": sid, "account_login": n.Label}
			if svc := n.Attrs["domain"]; svc != "" {
				obj["account_type"] = svc
			}
		case NodeDomain:
			sid = idFor("domain-name", n.ID)
			obj = stixObject{"type": "domain-name", "spec_version": "2.1", "id": sid, "value": n.Label}
		case NodeIP:
			sid = idFor("ipv4-addr", n.ID)
			obj = stixObject{"type": "ipv4-addr", "spec_version": "2.1", "id": sid, "value": n.Label}
		case NodeOrg:
			sid = idFor("identity", n.ID)
			obj = stixObject{"type": "identity", "spec_version": "2.1", "id": sid, "name": n.Label, "identity_class": "organization", "created": ts, "modified": ts}
		case NodeBreach:
			sid = idFor("note", n.ID)
			content := "Email appears in breach: " + n.Label
			if d := n.Attrs["date"]; d != "" {
				content += " (" + d + ")"
			}
			obj = stixObject{"type": "note", "spec_version": "2.1", "id": sid, "abstract": "breach", "content": content, "created": ts, "modified": ts}
		default:
			continue
		}
		stixID[n.ID] = sid
		objects = append(objects, obj)
	}

	for _, e := range g.Edges {
		from, ok1 := stixID[e.From]
		to, ok2 := stixID[e.To]
		if !ok1 || !ok2 {
			continue
		}
		rid := idFor("relationship", e.From+"|"+e.Label+"|"+e.To)
		objects = append(objects, stixObject{
			"type":              "relationship",
			"spec_version":      "2.1",
			"id":                rid,
			"relationship_type": stixRelType(e.Label),
			"source_ref":        from,
			"target_ref":        to,
			"created":           ts,
			"modified":          ts,
		})
	}

	bundle := stixObject{
		"type":    "bundle",
		"id":      idFor("bundle", bundleSeed(g)),
		"objects": objects,
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func stixRelType(label string) string {
	switch label {
	case "has_account", "has_profile":
		return "owns"
	case "in_breach":
		return "related-to"
	case "uses_domain", "resolves_to":
		return "resolves-to"
	default:
		return "related-to"
	}
}

func bundleSeed(g Graph) string {
	if len(g.Nodes) > 0 {
		return g.Nodes[0].ID
	}
	return "empty"
}

// uuidFromBytes formats 16 bytes as a UUID string. It is not a random UUID;
// it is a stable identifier so the same case exports identically.
func uuidFromBytes(b []byte) string {
	if len(b) < 16 {
		padded := make([]byte, 16)
		copy(padded, b)
		b = padded
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
