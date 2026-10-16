package routes

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseLogLineSizeExtractsTheResponseSizeField(t *testing.T) {
	if v, ok := nginxParseLogLineSize(`1.2.3.4 - - [08/Sep/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 4521 "-" "curl/8.0"`); !ok || v != 4521 {
		t.Fatal(v, ok)
	}
	if _, ok := nginxParseLogLineSize("not a log line"); ok {
		t.Fatal("accepted a line with no quoted request")
	}
	if _, ok := nginxParseLogLineSize(`1.2.3.4 - - [x] "GET / HTTP/1.1" 200 not-a-number "-" "-"`); ok {
		t.Fatal("accepted a non-numeric size")
	}
}

func trafficLine(size int) string {
	return "1.2.3.4 - - [08/Sep/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 " + strconv.Itoa(size) + " \"-\" \"-\"\n"
}

func trafficTemp(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(p, []byte(content), 0o644)
	return p
}

func TestReadAndAdvanceSumsCompleteLinesFromTheGivenOffset(t *testing.T) {
	l1, l2 := trafficLine(100), trafficLine(250)
	p := trafficTemp(t, l1+l2)
	sum, off := nginxReadAndAdvance(p, 0)
	if sum != 350 || off != uint64(len(l1+l2)) {
		t.Fatal(sum, off)
	}
	if s2, o2 := nginxReadAndAdvance(p, off); s2 != 0 || o2 != off {
		t.Fatal(s2, o2)
	}
	if s3, o3 := nginxReadAndAdvance(p, uint64(len(l1))); s3 != 250 || o3 != uint64(len(l1+l2)) {
		t.Fatal(s3, o3)
	}
}

// nginx can be mid-write: the partial line stays unconsumed until complete.
func TestReadAndAdvanceLeavesAPartialTrailingLineUnconsumed(t *testing.T) {
	complete := trafficLine(100)
	p := trafficTemp(t, complete+`5.6.7.8 - - [x] "GET /still-writing HTTP/1.1" 200 99`)
	if sum, off := nginxReadAndAdvance(p, 0); sum != 100 || off != uint64(len(complete)) {
		t.Fatal(sum, off)
	}
}

func TestReadAndAdvanceOnAMissingFileReturnsZeroAndTheSameOffset(t *testing.T) {
	if sum, off := nginxReadAndAdvance("/nonexistent/dockpanel-test-path.log", 42); sum != 0 || off != 42 {
		t.Fatal(sum, off)
	}
}

func TestModsecEventParsing(t *testing.T) {
	evt, ok := nginxParseModsecEvent("--abc-A--\n[17/Oct/2026:10:00:00 +0000] x\nGET /wp-login.php HTTP/1.1\n[msg \"SQLi\"] [severity \"CRITICAL\"] client: 1.2.3.4, server\nAction: Intercepted (phase 2)\n--abc-Z--\n")
	if !ok || evt["uri"] != "/wp-login.php" || evt["rule_message"] != "SQLi" || evt["severity"] != "CRITICAL" ||
		evt["action"] != "blocked" || evt["client_ip"] != "1.2.3.4" {
		t.Fatalf("%v", evt)
	}
	if _, ok := nginxParseModsecEvent("nothing here\n"); ok {
		t.Fatal("empty event accepted")
	}
}
