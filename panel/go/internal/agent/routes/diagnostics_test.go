package routes

import "testing"

func TestDiagnosticsParseFreeM(t *testing.T) {
	out := "               total        used        free      shared  buff/cache   available\nMem:            7951        2345        1234          56        4371        5300\nSwap:              0           0           0\n"
	total, avail := diagnosticsParseFreeM(out)
	if total != 7951 || avail != 5300 {
		t.Fatalf("got %d %d", total, avail)
	}
	if total, avail := diagnosticsParseFreeM(""); total != 0 || avail != 0 {
		t.Fatalf("empty: got %d %d", total, avail)
	}
}

func TestDiagnosticsPhpPool(t *testing.T) {
	mc, mem := diagnosticsPhpPool("[www]\npm.max_children = 12\nphp_admin_value[memory_limit] = 128M\n")
	if mc != 12 || mem != 128 {
		t.Fatalf("got %d %d", mc, mem)
	}
	// Defaults; only the first matching line counts even if unparseable.
	mc, mem = diagnosticsPhpPool("pm.max_children = x\npm.max_children = 9\n")
	if mc != 5 || mem != 256 {
		t.Fatalf("defaults: got %d %d", mc, mem)
	}
}

func TestDiagnosticsNginxWorkers(t *testing.T) {
	for conf, want := range map[string]uint32{
		"  # worker_processes 8;\nworker_processes 4;\n": 4,
		"worker_processes auto;\n":                       0,
		"events {}\n":                                    0,
	} {
		if got := diagnosticsNginxWorkers(conf); got != want {
			t.Errorf("%q: got %d want %d", conf, got, want)
		}
	}
}
