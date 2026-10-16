package routes

import "testing"

func TestSystemParsePort(t *testing.T) {
	for in, want := range map[string]bool{"80": true, "+80": true, "65535": true, "0": false, "65536": false, "": false, "-1": false, "++1": false, "abc": false} {
		if _, ok := systemParsePort(in); ok != want {
			t.Errorf("systemParsePort(%q) ok=%v, want %v", in, ok, want)
		}
	}
}

func TestSystemParseDiskstatsCountsOnlyWholeDevices(t *testing.T) {
	in := "   8       0 sda 1 0 100 0 2 0 200 0 0 0 0 0 0 0\n" +
		"   8       1 sda1 1 0 50 0 2 0 60 0 0 0 0 0 0 0\n" +
		" 259       0 nvme0n1 1 0 10 0 2 0 20 0 0 0 0 0 0 0\n" +
		" 259       1 nvme0n1p1 1 0 5 0 2 0 6 0 0 0 0 0 0 0\n"
	r, w := systemParseDiskstats(in)
	if r != 110 || w != 220 {
		t.Fatalf("got %d/%d, want 110/220", r, w)
	}
}

func TestSystemValidHostname(t *testing.T) {
	if !systemValidHostname("web-1.example") || systemValidHostname("") || systemValidHostname("a b") || systemValidHostname("x;rm") {
		t.Fatal("hostname validation")
	}
}
