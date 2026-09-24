package graph

import (
	"encoding/json"
	"io"
	"strings"
)

// neo4jNode and neo4jRel are the shape apoc.import.json and most Neo4j
// loaders accept: a list of nodes with labels and properties, and a list of
// relationships referencing node ids.
type neo4jNode struct {
	ID         string            `json:"id"`
	Labels     []string          `json:"labels"`
	Properties map[string]string `json:"properties"`
}

type neo4jRel struct {
	Type       string            `json:"type"`
	Start      string            `json:"start"`
	End        string            `json:"end"`
	Properties map[string]string `json:"properties,omitempty"`
}

type neo4jDoc struct {
	Nodes         []neo4jNode `json:"nodes"`
	Relationships []neo4jRel  `json:"relationships"`
}

// WriteNeo4j writes the graph as JSON that Neo4j can import (for example with
// APOC). Each node keeps its type as a label and its attributes as string
// properties; each edge becomes a typed relationship.
func WriteNeo4j(w io.Writer, g Graph) error {
	out := neo4jDoc{
		Nodes:         make([]neo4jNode, 0, len(g.Nodes)),
		Relationships: make([]neo4jRel, 0, len(g.Edges)),
	}
	for _, n := range g.Nodes {
		props := map[string]string{"label": n.Label}
		for k, v := range n.Attrs {
			props[k] = v
		}
		out.Nodes = append(out.Nodes, neo4jNode{
			ID:         n.ID,
			Labels:     []string{neo4jLabel(n.Type)},
			Properties: props,
		})
	}
	for _, e := range g.Edges {
		out.Relationships = append(out.Relationships, neo4jRel{
			Type:  strings.ToUpper(e.Label),
			Start: e.From,
			End:   e.To,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// neo4jLabel turns a node type into a Neo4j label in PascalCase.
func neo4jLabel(t NodeType) string {
	s := string(t)
	if s == "" {
		return "Node"
	}
	if s == "ip" {
		return "IP"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
