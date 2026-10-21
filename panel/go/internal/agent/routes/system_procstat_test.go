package routes

import "testing"

// A real /proc/<pid>/stat line (dockpanel-agent): utime 15123, stime 7240, rss 5678 pages.
const procStatAgent = "1441486 (dockpanel-agent) S 1 1441486 1441486 0 -1 4194560 52345 0 3 0 15123 7240 0 0 20 0 22 0 23756345 1341880320 5678 18446744073709551615 1 1 0 0 0 0 0 0 2143420159 0 0 0 17 7 0 0 0 0 0 0 0 0 0 0 0 0 0"

func TestProcParseStatReadsCommTicksAndRss(t *testing.T) {
	s, ok := procParseStat(procStatAgent)
	if !ok || s.name != "dockpanel-agent" || s.ticks != 15123+7240 || s.rssPages != 5678 {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
}

// comm may contain spaces and ')' — fields must be counted from the LAST ')'.
func TestProcParseStatHandlesParenthesesAndSpacesInComm(t *testing.T) {
	line := "77 (Web Content (x)) R 1 77 77 0 -1 0 0 0 0 0 9 1 0 0 20 0 1 0 100 1000 42 0"
	s, ok := procParseStat(line)
	if !ok || s.name != "Web Content (x)" || s.ticks != 10 || s.rssPages != 42 {
		t.Fatalf("got %+v ok=%v", s, ok)
	}
}

func TestProcParseStatRejectsTruncatedLines(t *testing.T) {
	if _, ok := procParseStat("12 (bash) S 1 2 3"); ok {
		t.Fatal("short line accepted")
	}
	if _, ok := procParseStat("garbage"); ok {
		t.Fatal("line without comm accepted")
	}
}
