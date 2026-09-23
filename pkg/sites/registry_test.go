package sites

import "testing"

func TestSelectFilters(t *testing.T) {
	got, err := Select([]string{"dev"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, site := range got {
		names[site.Name()] = true
		if site.Category() != "dev" {
			t.Fatalf("%s category %s", site.Name(), site.Category())
		}
	}
	if !names["github"] || !names["replit"] {
		t.Fatalf("dev sites: %v", names)
	}
	if names["spotify"] {
		t.Fatal("spotify is not a dev site")
	}
}

func TestSelectUnknownCategory(t *testing.T) {
	if _, err := Select([]string{"news"}, nil); err == nil {
		t.Fatal("expected unknown category")
	}
}
