package services

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func ssrfMust(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestSsrfGuardV4InternalRanges(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		// extra
		"0.0.0.0", "255.255.255.255", "172.16.0.1", "172.31.255.255", "127.255.255.254", "100.127.255.255"} {
		if !ssrfGuardV4IsInternal(ssrfMust(s).As4()) {
			t.Errorf("%s should be internal", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "140.82.112.3", "172.32.0.1", "100.128.0.1", "192.169.0.1"} {
		if ssrfGuardV4IsInternal(ssrfMust(s).As4()) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestSsrfGuardV6InternalRanges(t *testing.T) {
	for _, s := range []string{"::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1",
		// extra: unspecified, ULA fd, mapped metadata, hex-mapped, NAT64, v4-compat, 6to4
		"::", "fd12::1", "::ffff:169.254.169.254", "::ffff:7f00:1", "64:ff9b::a00:1", "::10.0.0.1", "2002:c0a8:101::1",
		"febf::1"} {
		if !ssrfGuardIPIsInternal(ssrfMust(s)) {
			t.Errorf("%s should be internal", s)
		}
	}
	for _, s := range []string{"2001:4860:4860::8888", "::ffff:8.8.8.8", "2002:808:808::1", "64:ff9b::808:808"} {
		if ssrfGuardIPIsInternal(ssrfMust(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestSsrfGuardRepoURLAuthorityParsesEveryShape(t *testing.T) {
	for _, c := range []struct {
		in   string
		host string
		port uint16
	}{
		{"https://github.com/owner/repo.git", "github.com", 443},
		{"ssh://git@10.0.0.1:2222/owner/repo.git", "10.0.0.1", 2222},
		{"git@github.com:owner/repo.git", "github.com", 22},
		{"http://example.com/x.git", "example.com", 80},
		{"ssh://git@example.com/x.git", "example.com", 22},
		{"https://[::1]:8443/x.git", "::1", 8443},
	} {
		h, p, err := ssrfGuardRepoURLAuthority(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Errorf("%s: got %q %d %v", c.in, h, p, err)
		}
	}
	for _, in := range []string{"", "not a url", "https://example.com:99999/x", "git@:x"} {
		if _, _, err := ssrfGuardRepoURLAuthority(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestSsrfGuardLiteralInternalIPRepoURLsRejectedAcrossEveryShape(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1/x.git", "https://169.254.169.254/x.git", "ssh://git@10.0.0.1/x.git", "git@192.168.1.1:owner/repo.git",
		// extra: unspecified, IPv6 forms, mapped, legacy numeric forms, localhost names, userinfo confusion, case
		"http://0.0.0.0/x.git", "http://[::]/x.git", "http://[::1]/x.git", "http://[::ffff:127.0.0.1]/x.git",
		"http://[::ffff:169.254.169.254]/x.git", "http://[fe80::1%25eth0]/x.git",
		"http://2130706433/x.git", "http://0177.0.0.1/x.git", "http://0x7f.1/x.git", "http://127.1/x.git",
		"http://127.0.0.1./x.git", "http://0x7f000001/x.git", "http://2852039166/x.git", // = 169.254.169.254
		"http://localhost/x.git", "http://LOCALHOST/x.git", "http://foo.localhost/x.git",
		"https://github.com@127.0.0.1/x.git", "http://127.0.0.%31/x.git", "git@[::1]:x",
	} {
		if err := SsrfGuardValidateRepoURLNotInternal(u); err == nil {
			t.Errorf("expected %s to be rejected", u)
		}
	}
}

func TestSsrfGuardMalformedAndUnresolvableAreRejected(t *testing.T) {
	old := ssrfGuardLookup
	defer func() { ssrfGuardLookup = old }()
	ssrfGuardLookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	for _, u := range []string{"", "ftp://example.com/x.git", "https://this-host-does-not-exist.invalid/x.git"} {
		if err := SsrfGuardValidateRepoURLNotInternal(u); err == nil {
			t.Errorf("expected %q to be rejected", u)
		}
	}
	ssrfGuardLookup = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	if err := SsrfGuardValidateRepoURLNotInternal("https://empty.example/x.git"); err == nil || err.Error() != "Host could not be resolved" {
		t.Errorf("empty answer: %v", err)
	}
}

// DNS-level attacks: a name (e.g. a CNAME chain) landing on a private or
// metadata address, or mixing one private address among public ones.
func TestSsrfGuardResolvedPrivateAddressesRejected(t *testing.T) {
	old := ssrfGuardLookup
	defer func() { ssrfGuardLookup = old }()
	for _, set := range [][]string{
		{"10.0.0.5"}, {"169.254.169.254"}, {"8.8.8.8", "192.168.0.1"}, {"::ffff:127.0.0.1"}, {"fd00::1"},
	} {
		ssrfGuardLookup = func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, s := range set {
				out = append(out, ssrfMust(s))
			}
			return out, nil
		}
		if err := SsrfGuardValidateRepoURLNotInternal("https://cname-to-private.example/x.git"); err == nil ||
			err.Error() != "Host resolves to a private/internal address" {
			t.Errorf("%v: got %v", set, err)
		}
	}
	ssrfGuardLookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{ssrfMust("140.82.112.3"), ssrfMust("2606:50c0:8000::153")}, nil
	}
	if err := SsrfGuardValidateRepoURLNotInternal("https://github.com/o/r.git"); err != nil {
		t.Errorf("public host rejected: %v", err)
	}
}

func TestSsrfGuardParseLegacyIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"2130706433": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "0x7f.1": "127.0.0.1", "127.1": "127.0.0.1",
		"127.0.0.1.": "127.0.0.1", "10.65535": "10.0.255.255", "0": "0.0.0.0",
	} {
		got, ok := ssrfGuardParseLegacyIPv4(in)
		if !ok || got.String() != want {
			t.Errorf("%q: got %v %v, want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"github.com", "", "1.2.3.4.5", "256.1.1.1", "1.2.3.256", "08", "1..2", "4294967296"} {
		if _, ok := ssrfGuardParseLegacyIPv4(in); ok {
			t.Errorf("%q parsed", in)
		}
	}
}
