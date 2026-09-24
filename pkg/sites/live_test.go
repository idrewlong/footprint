//go:build live

package sites

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

// The live checks hit real sites and never run in the normal test suite.
// Run them with:
//
//	go test -tags live -run '^TestLive(UnregisteredAddress|Canary)$' -v ./pkg/sites/
//
// Each site is checked with a random address that has no account anywhere.
// found means the check is broken or too loose; error means the endpoint or
// its response changed. rate_limited is reported as skipped, since a CI
// runner's IP is often blocked, and it is never a pass.
//
// A random address cannot catch a check that always says not_found. For
// that, set FOOTPRINT_LIVE_CANARY_EMAIL to an address you control and
// FOOTPRINT_LIVE_CANARY_SITES to the sites it is registered on.
//
// Checks that can email the address are skipped unless
// FOOTPRINT_LIVE_ALLOW_NOTIFY=1.

func TestLiveUnregisteredAddress(t *testing.T) {
	email := randomAddress(t)
	t.Logf("random address %s", email)
	for _, site := range All() {
		t.Run(site.Name(), func(t *testing.T) {
			t.Parallel()
			skipUnlessRunnable(t, site)
			res := liveCheck(t, site, email)
			switch res.Status {
			case checker.StatusNotFound:
			case checker.StatusRateLimited:
				t.Skipf("rate limited: %s", res.Detail)
			case checker.StatusFound:
				t.Errorf("an unregistered address was reported found (evidence %q): the check is broken or too loose", res.Evidence)
			default:
				t.Errorf("status %s: %s", res.Status, res.Detail)
			}
		})
	}
}

func TestLiveCanary(t *testing.T) {
	email := strings.TrimSpace(os.Getenv("FOOTPRINT_LIVE_CANARY_EMAIL"))
	names := strings.TrimSpace(os.Getenv("FOOTPRINT_LIVE_CANARY_SITES"))
	if email == "" || names == "" {
		t.Skip("FOOTPRINT_LIVE_CANARY_EMAIL and FOOTPRINT_LIVE_CANARY_SITES are not set")
	}
	selected, err := Select(nil, strings.Split(names, ","))
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range selected {
		t.Run(site.Name(), func(t *testing.T) {
			t.Parallel()
			skipUnlessRunnable(t, site)
			res := liveCheck(t, site, email)
			switch res.Status {
			case checker.StatusFound:
			case checker.StatusRateLimited:
				t.Skipf("rate limited: %s", res.Detail)
			case checker.StatusNotFound:
				t.Errorf("the canary account was reported not_found: the check may have stopped detecting accounts")
			default:
				t.Errorf("status %s: %s", res.Status, res.Detail)
			}
		})
	}
}

func skipUnlessRunnable(t *testing.T, site checker.Site) {
	t.Helper()
	if checker.Notifies(site.Method()) && os.Getenv("FOOTPRINT_LIVE_ALLOW_NOTIFY") != "1" {
		t.Skipf("%s check can email the address; set FOOTPRINT_LIVE_ALLOW_NOTIFY=1", site.Method())
	}
	if site.Name() == "hibp" && os.Getenv("HIBP_API_KEY") == "" {
		t.Skip("HIBP_API_KEY is not set")
	}
}

// liveCheck runs one site through the real engine, so timeouts and block
// detection behave as they do for users.
func liveCheck(t *testing.T, site checker.Site, email string) checker.Result {
	t.Helper()
	for res := range checker.Run(context.Background(), email, []checker.Site{site}, checker.Options{Concurrency: 1}) {
		return res
	}
	t.Fatal("no result")
	return checker.Result{}
}

// randomAddress is a 24-hex-character Gmail address. No one registers that
// by chance, and a well-known domain avoids signup forms that reject
// reserved domains such as example.com.
func randomAddress(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "fp" + hex.EncodeToString(b) + "@gmail.com"
}
