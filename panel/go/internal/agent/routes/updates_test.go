package routes

import "testing"

// A real `dnf check-update` line, Rocky/RHEL 9 shape.
func TestUpdatesParsesARealDnfCheckUpdateLine(t *testing.T) {
	p, ok := updatesParseRpmUpdateLine("bash.x86_64    5.1.8-4.el9_2    baseos")
	if !ok || p.Name != "bash" || p.NewVersion != "5.1.8-4.el9_2" || p.Repo != "baseos" {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
}

// Epoch-qualified version — same 3-token shape.
func TestUpdatesParsesAYumLineWithAnEpochQualifiedVersion(t *testing.T) {
	p, ok := updatesParseRpmUpdateLine("kernel.x86_64    3:5.14.0-284.11.1.el9_2    baseos")
	if !ok || p.Name != "kernel" || p.NewVersion != "3:5.14.0-284.11.1.el9_2" {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
}

// check-update's own section headers and refresh banner are not packages.
func TestUpdatesSkipsSectionHeadersAndTheMetadataBanner(t *testing.T) {
	for _, noise := range []string{
		"",
		"Last metadata expiration check: 0:12:34 ago on Mon 04 Sep 2026.",
		"Obsoleting Packages",
		"Security: 3 patches",
	} {
		if _, ok := updatesParseRpmUpdateLine(noise); ok {
			t.Errorf("must not parse as a package: %q", noise)
		}
	}
}

// The digit-in-version guard is a per-line decision, not an exit-code one.
func TestUpdatesAThreeWordLineWithNoDigitInTheMiddleTokenIsNotAPackage(t *testing.T) {
	if _, ok := updatesParseRpmUpdateLine("word.one word two"); ok {
		t.Error("parsed")
	}
}

// name.arch splits on the LAST dot so a dotted package name stays intact.
func TestUpdatesStripsOnlyTheTrailingArchNotADottedPackageName(t *testing.T) {
	p, ok := updatesParseRpmUpdateLine("python3.11-libs.x86_64    3.11.7-1.el9    appstream")
	if !ok || p.Name != "python3.11-libs" {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
}
