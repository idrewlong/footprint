package sites

import (
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

func TestAmazon(t *testing.T) { testSite(t, "amazon") }

func TestAmazonRejectsOffsiteRedirect(t *testing.T) {
	raw := "HTTP/1.1 302 Found\nLocation: https://evil.example/ax/claim\n\n"
	testRaw(t, "amazon", raw, checker.StatusError)
}
