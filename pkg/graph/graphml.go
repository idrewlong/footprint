package graph

import (
	"encoding/xml"
	"fmt"
	"io"
)

// WriteGraphML writes the graph as GraphML, which yEd, Gephi, and Neo4j's
// import tools read. Node type and label, and every attribute, become GraphML
// data keys so the graph carries its facts, not just its shape.
func WriteGraphML(w io.Writer, g Graph) error {
	// Collect every attribute key used, so each becomes a declared <key>.
	attrKeys := map[string]struct{}{}
	for _, n := range g.Nodes {
		for k := range n.Attrs {
			attrKeys[k] = struct{}{}
		}
	}
	var keyList []string
	for k := range attrKeys {
		keyList = append(keyList, k)
	}
	// Stable order.
	for i := 0; i < len(keyList); i++ {
		for j := i + 1; j < len(keyList); j++ {
			if keyList[j] < keyList[i] {
				keyList[i], keyList[j] = keyList[j], keyList[i]
			}
		}
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	bw := &errWriter{w: w}
	bw.printf(`<graphml xmlns="http://graphml.graphdrawing.org/xmlns">` + "\n")
	bw.printf(`  <key id="type" for="node" attr.name="type" attr.type="string"/>` + "\n")
	bw.printf(`  <key id="label" for="node" attr.name="label" attr.type="string"/>` + "\n")
	for _, k := range keyList {
		bw.printf(`  <key id="%s" for="node" attr.name="%s" attr.type="string"/>`+"\n", escapeAttr(k), escapeAttr(k))
	}
	bw.printf(`  <key id="relationship" for="edge" attr.name="relationship" attr.type="string"/>` + "\n")
	bw.printf(`  <graph edgedefault="directed">` + "\n")

	for _, n := range g.Nodes {
		bw.printf(`    <node id="%s">`+"\n", escapeAttr(n.ID))
		bw.printf(`      <data key="type">%s</data>`+"\n", escapeText(string(n.Type)))
		bw.printf(`      <data key="label">%s</data>`+"\n", escapeText(n.Label))
		for _, k := range sortedAttrKeys(n.Attrs) {
			bw.printf(`      <data key="%s">%s</data>`+"\n", escapeAttr(k), escapeText(n.Attrs[k]))
		}
		bw.printf("    </node>\n")
	}
	for i, e := range g.Edges {
		bw.printf(`    <edge id="e%d" source="%s" target="%s">`+"\n", i, escapeAttr(e.From), escapeAttr(e.To))
		bw.printf(`      <data key="relationship">%s</data>`+"\n", escapeText(e.Label))
		bw.printf("    </edge>\n")
	}
	bw.printf("  </graph>\n</graphml>\n")
	return bw.err
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func escapeText(s string) string {
	var b []byte
	buf := &sliceWriter{&b}
	_ = xml.EscapeText(buf, []byte(s))
	return string(b)
}

// escapeAttr escapes a value used inside a double-quoted XML attribute.
func escapeAttr(s string) string {
	return escapeText(s)
}

type sliceWriter struct{ b *[]byte }

func (s *sliceWriter) Write(p []byte) (int, error) {
	*s.b = append(*s.b, p...)
	return len(p), nil
}
