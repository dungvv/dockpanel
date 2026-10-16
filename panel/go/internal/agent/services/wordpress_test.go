package services

import (
	"encoding/json"
	"testing"
)

func TestWordpressPromotesThisVhostOwnPlainHttpUrl(t *testing.T) {
	if got, ok := WordpressHttpsPromotionTarget("http://example.com", "example.com"); !ok || got != "https://example.com" {
		t.Fatalf("got %q %v", got, ok)
	}
}

// wp-cli prints what is stored, after however many admin screens and migrations.
func TestWordpressToleratesTrailingSlashAndOddCasing(t *testing.T) {
	for _, s := range []string{"http://example.com/", "  http://example.com  ", "HTTP://EXAMPLE.COM"} {
		if _, ok := WordpressHttpsPromotionTarget(s, "example.com"); !ok {
			t.Errorf("%q not promoted", s)
		}
	}
}

func TestWordpressLeavesAnAlreadySecureUrlAlone(t *testing.T) {
	if _, ok := WordpressHttpsPromotionTarget("https://example.com", "example.com"); ok {
		t.Fatal("promoted an https URL")
	}
}

// Each is a working configuration somebody set on purpose; rewriting it would
// move a live site to an address the operator never picked.
func TestWordpressNeverRepointsAUrlTheOperatorChose(t *testing.T) {
	for _, s := range []string{"http://other-domain.com", "http://example.com/blog", "http://www.example.com", "http://sub.example.com", ""} {
		if _, ok := WordpressHttpsPromotionTarget(s, "example.com"); ok {
			t.Errorf("must not promote %q", s)
		}
	}
}

func TestWordpressASuffixLookalikeIsNotThisDomain(t *testing.T) {
	if _, ok := WordpressHttpsPromotionTarget("http://example.com.attacker.net", "example.com"); ok {
		t.Fatal("lookalike promoted")
	}
}

// The prefix collision that let one site strip another's security updates.
func TestWordpressAPrefixDomainCannotMatchALongerDomainsCronLine(t *testing.T) {
	victim := "0 3 * * * wp core update --path=/var/www/example.community/public " + wordpressAutoUpdateMarker("example.community")
	if !wordpressLineMarkedFor(victim, wordpressAutoUpdateMarker("example.community")) {
		t.Fatal("own marker not matched")
	}
	if wordpressLineMarkedFor(victim, wordpressAutoUpdateMarker("example.com")) {
		t.Fatal("prefix domain matched a longer domain's line")
	}
	short := "0 3 * * * wp core update --path=/var/www/a.co/public " + wordpressAutoUpdateMarker("a.co")
	if wordpressLineMarkedFor(short, wordpressAutoUpdateMarker("a.com")) {
		t.Fatal("longer marker matched a shorter domain's line")
	}
}

func TestWordpressTrailingWhitespaceDoesNotHideTheMarker(t *testing.T) {
	if !wordpressLineMarkedFor("0 3 * * * wp core update "+wordpressAutoUpdateMarker("a.com")+"   ", wordpressAutoUpdateMarker("a.com")) {
		t.Fatal("marker hidden by trailing whitespace")
	}
}

// Wire shape of serde's snake_case externally tagged enum, and comparability.
func TestWordpressCanonicalUrlOutcomeJSON(t *testing.T) {
	for _, c := range []struct {
		o    WordpressCanonicalUrlOutcome
		want string
	}{
		{WordpressCanonicalUrlUntouched, `"untouched"`},
		{WordpressCanonicalUrlPromoted, `"promoted"`},
		{WordpressCanonicalUrlFailed(`read siteurl: "x"`), `{"failed":"read siteurl: \"x\""}`},
	} {
		b, err := json.Marshal(c.o)
		if err != nil || string(b) != c.want {
			t.Errorf("got %s %v, want %s", b, err, c.want)
		}
	}
	if msg, ok := WordpressCanonicalUrlFailed("boom").Failure(); !ok || msg != "boom" {
		t.Fatal("Failure()")
	}
	if _, ok := WordpressCanonicalUrlPromoted.Failure(); ok || (WordpressCanonicalUrlOutcome{}) != WordpressCanonicalUrlUntouched {
		t.Fatal("zero value must be Untouched and not a failure")
	}
}
