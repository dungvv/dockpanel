package api

import (
	"strings"
	"testing"
)

func TestPrometheusExporterEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`a"b\c`:        `a\"b\\c`,
		"line1\nline2": `line1\nline2`,
		"my-server-01": "my-server-01",
	} {
		var s strings.Builder
		prometheusExporterPushEscaped(&s, in)
		if s.String() != want {
			t.Errorf("%q → %q, want %q", in, s.String(), want)
		}
	}
}

func TestPrometheusExporterCertRenewalsRenderEmitsCounterWithBothLabels(t *testing.T) {
	AutoHealerSslRenewalsSuccess.Store(7)
	AutoHealerSslRenewalsFailure.Store(2)
	defer func() {
		AutoHealerSslRenewalsSuccess.Store(0)
		AutoHealerSslRenewalsFailure.Store(0)
	}()
	var s strings.Builder
	prometheusExporterRenderCertRenewals(&s)
	out := s.String()
	for _, want := range []string{
		"# TYPE dockpanel_cert_renewals_total counter",
		`dockpanel_cert_renewals_total{result="success"} 7`,
		`dockpanel_cert_renewals_total{result="failure"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestPrometheusExporterF32MatchesRustDisplay(t *testing.T) {
	for v, want := range map[float32]string{3: "3", 12.5: "12.5", 0.1: "0.1", 45.7: "45.7"} {
		if got := prometheusExporterF32(v); got != want {
			t.Errorf("%v → %q, want %q", v, got, want)
		}
	}
}
