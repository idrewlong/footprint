package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
)

func matchCatalog(all func() []checker.Site) catalogFunc {
	return func(categories, names []string) ([]checker.Site, error) {
		return filterSites(all(), categories, names), nil
	}
}

func filterSites(all []checker.Site, categories, names []string) []checker.Site {
	catSet := make(map[string]struct{}, len(categories))
	for _, category := range categories {
		category = strings.ToLower(strings.TrimSpace(category))
		if category != "" {
			catSet[category] = struct{}{}
		}
	}
	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			nameSet[name] = struct{}{}
		}
	}
	var out []checker.Site
	for _, site := range all {
		if len(catSet) > 0 {
			if _, ok := catSet[strings.ToLower(site.Category())]; !ok {
				continue
			}
		}
		if len(nameSet) > 0 {
			if _, ok := nameSet[strings.ToLower(site.Name())]; !ok {
				continue
			}
		}
		out = append(out, site)
	}
	return out
}

func missingNames(names []string, groups ...[]checker.Site) []string {
	have := map[string]struct{}{}
	for _, group := range groups {
		for _, site := range group {
			have[strings.ToLower(site.Name())] = struct{}{}
		}
	}
	var missing []string
	seen := map[string]struct{}{}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if _, ok := have[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		missing = append(missing, name)
	}
	return missing
}

func runSites(args []string, stdout, stderr io.Writer, catalog catalogFunc) int {
	fs := flag.NewFlagSet("sites", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		asJSON     bool
		categories stringList
	)
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.Var(&categories, "category", "category to list")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"json": true,
		"h":    true,
		"help": true,
	}, map[string]bool{
		"category": true,
	})
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	selected, err := catalog(categories, nil)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	if asJSON {
		type row struct {
			Site     string `json:"site"`
			Domain   string `json:"domain"`
			Category string `json:"category"`
			Method   string `json:"method"`
		}
		rows := make([]row, 0, len(selected))
		for _, site := range selected {
			rows = append(rows, row{Site: site.Name(), Domain: site.Domain(), Category: site.Category(), Method: site.Method()})
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%-12s  %-16s  %-16s  %s\n", "SITE", "DOMAIN", "CATEGORY", "METHOD")
	for _, site := range selected {
		fmt.Fprintf(stdout, "%-12s  %-16s  %-16s  %s\n", site.Name(), site.Domain(), site.Category(), site.Method())
	}
	return 0
}
