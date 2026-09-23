package profiles

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/idrewlong/footprint/pkg/checker"
)

var (
	mu         sync.Mutex
	registered []checker.Site
)

// Register adds a username profile. A duplicate name is a programming error.
func Register(site checker.Site) {
	mu.Lock()
	defer mu.Unlock()
	for _, existing := range registered {
		if existing.Name() == site.Name() {
			panic("duplicate profile " + site.Name())
		}
	}
	registered = append(registered, site)
}

// All returns the registered profiles sorted by name.
func All() []checker.Site {
	mu.Lock()
	defer mu.Unlock()
	out := append([]checker.Site(nil), registered...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name() < out[j].Name()
	})
	return out
}

// Select filters by category and profile name. Empty filters match everything.
func Select(categories, names []string) ([]checker.Site, error) {
	all := All()
	catSet := setOf(categories)
	nameSet := setOf(names)
	knownCats := map[string]struct{}{}
	knownNames := map[string]struct{}{}
	for _, site := range all {
		knownCats[strings.ToLower(site.Category())] = struct{}{}
		knownNames[strings.ToLower(site.Name())] = struct{}{}
	}
	if err := unknown("category", catSet, knownCats); err != nil {
		return nil, err
	}
	if err := unknown("profile", nameSet, knownNames); err != nil {
		return nil, err
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
	if len(out) == 0 {
		return nil, fmt.Errorf("no profiles matched")
	}
	return out, nil
}

func setOf(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func unknown(kind string, wanted, known map[string]struct{}) error {
	var missing []string
	for value := range wanted {
		if _, ok := known[value]; !ok {
			missing = append(missing, value)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	var have []string
	for value := range known {
		have = append(have, value)
	}
	sort.Strings(have)
	return fmt.Errorf("unknown %s %q (have %s)", kind, strings.Join(missing, ", "), strings.Join(have, ", "))
}
