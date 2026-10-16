package services

import "testing"

func TestParseHTTPStatus(t *testing.T) {
	if s := backupDrillParseHTTPStatus("Connecting to localhost\n  HTTP/1.1 404 Not Found\n"); s == nil || *s != 404 {
		t.Fatalf("got %v", s)
	}
	if s := backupDrillParseHTTPStatus("wget: can't connect to remote host"); s != nil {
		t.Fatalf("got %v", *s)
	}
}

func TestParseVolumeProbe(t *testing.T) {
	if f, b := backupDrillParseVolumeProbe("FILES=12 BYTES=3456\n"); f != 12 || b != 3456 {
		t.Fatalf("got %d %d", f, b)
	}
	if f, b := backupDrillParseVolumeProbe("garbage"); f != 0 || b != 0 {
		t.Fatalf("got %d %d", f, b)
	}
}
