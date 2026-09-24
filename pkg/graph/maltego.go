package graph

import (
	"encoding/csv"
	"io"
)

// Maltego CSV export. Maltego imports a CSV as a table of entities and links;
// this writes one row per edge, naming the two entities, their Maltego types,
// and the link label. Rows for nodes with no edges are written as a single
// entity so an isolated finding is not lost. A full Maltego transform server
// is a larger, separate piece; this CSV is the practical import path.
//
// Columns: FromType, FromValue, LinkLabel, ToType, ToValue.
func WriteMaltegoCSV(w io.Writer, g Graph) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"FromType", "FromValue", "LinkLabel", "ToType", "ToValue"}); err != nil {
		return err
	}
	label := map[string]Node{}
	for _, n := range g.Nodes {
		label[n.ID] = n
	}
	linked := map[string]struct{}{}
	for _, e := range g.Edges {
		from, ok1 := label[e.From]
		to, ok2 := label[e.To]
		if !ok1 || !ok2 {
			continue
		}
		linked[e.From] = struct{}{}
		linked[e.To] = struct{}{}
		if err := cw.Write([]string{
			maltegoType(from.Type), from.Label, e.Label, maltegoType(to.Type), to.Label,
		}); err != nil {
			return err
		}
	}
	// Emit isolated nodes so nothing found is dropped.
	for _, n := range g.Nodes {
		if _, ok := linked[n.ID]; ok {
			continue
		}
		if err := cw.Write([]string{maltegoType(n.Type), n.Label, "", "", ""}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// maltegoType maps a node type to the closest built-in Maltego entity type.
func maltegoType(t NodeType) string {
	switch t {
	case NodeEmail:
		return "maltego.EmailAddress"
	case NodeUsername, NodeAccount, NodeProfile:
		return "maltego.Alias"
	case NodeDomain:
		return "maltego.Domain"
	case NodeIP:
		return "maltego.IPv4Address"
	case NodeOrg:
		return "maltego.Organization"
	case NodeBreach:
		return "maltego.Phrase"
	default:
		return "maltego.Unknown"
	}
}
