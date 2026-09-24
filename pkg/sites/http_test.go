package sites

import (
	"net/http"
	"reflect"
	"testing"
)

func TestCopyHeaderKeepsRepeatsAndOverrides(t *testing.T) {
	dst := http.Header{}
	dst.Set("Content-Type", "application/json")
	src := http.Header{}
	src.Add("Accept", "text/html")
	src.Add("Accept", "application/json")
	src.Set("Content-Type", "application/json; charset=utf-8")
	copyHeader(dst, src)
	if got := dst.Values("Accept"); !reflect.DeepEqual(got, []string{"text/html", "application/json"}) {
		t.Fatalf("accept %q", got)
	}
	if got := dst.Values("Content-Type"); !reflect.DeepEqual(got, []string{"application/json; charset=utf-8"}) {
		t.Fatalf("content-type %q", got)
	}
}
