package cli

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUntaggedScalar(t *testing.T) {
	tests := []struct {
		in   string
		want any
	}{
		{"", nil},
		{"~", nil},
		{"Null", nil},
		{"true", true},
		{"FALSE", false},
		{"yes", "yes"}, // YAML 1.2: not a bool
		{"3000", json.Number("3000")},
		{"+5", json.Number("5")},
		{"0x1F", json.Number("31")},
		{"0o17", json.Number("15")},
		{"0b101", json.Number("5")},
		{"-42", json.Number("-42")},
		{"-0x10", json.Number("-16")},
		{"017", "017"}, // leading zero digits stay a string
		{"-017", "-017"},
		{"8.3", json.Number("8.3")},
		{"3000.0", json.Number("3000.0")},
		{"1e3", json.Number("1000.0")},
		{".inf", nil},
		{"1_000", "1_000"},
		{"0x1p3", "0x1p3"},
		{"example.com", "example.com"},
	}
	for _, tt := range tests {
		if got := untaggedScalar(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("untaggedScalar(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestNeedsQuotes(t *testing.T) {
	tests := map[string]bool{
		"": true, "null": true, "true": true, "8.3": true, "5432": true, "007": true,
		"-1": true, ".nan": true, "18446744073709551616": true,
		"static": false, "yes": false, "example.com": false, "8.3-fpm": false, "infinity": false,
	}
	for in, want := range tests {
		if got := needsQuotes(in); got != want {
			t.Errorf("needsQuotes(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestToYAML(t *testing.T) {
	data, err := parseJSON([]byte(`{
		"sites": [{"domain": "a.com", "runtime": "php", "php_version": "8.3", "ssl": true, "proxy_port": null}],
		"databases": [],
		"crons": [{"id": "c1", "schedule": "*/5 * * * *", "command": "echo: hi\nbye"}],
		"firewall": {"rules": [{"port": 22, "from": ""}]},
		"load": 1.5
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := toYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	want := `crons:
- command: |-
    echo: hi
    bye
  id: c1
  schedule: '*/5 * * * *'
databases: []
firewall:
  rules:
  - from: ''
    port: 22
load: 1.5
sites:
- domain: a.com
  php_version: '8.3'
  proxy_port: null
  runtime: php
  ssl: true
`
	if got != want {
		t.Errorf("toYAML mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}

	// Round trip back through apply's parser.
	back, err := parseYAML([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, data) {
		t.Errorf("round trip mismatch:\n%#v\n%#v", back, data)
	}
}

func TestParseYAMLTypes(t *testing.T) {
	v, err := parseYAML([]byte("sites:\n  - domain: x.com\n    proxy_port: 3000.0\n    php_version: 8.3\n    root: '017'\n"))
	if err != nil {
		t.Fatal(err)
	}
	site := get(v, "sites").([]any)[0]
	if _, ok := u64(get(site, "proxy_port")); ok {
		t.Error("3000.0 must not read as an integer port")
	}
	if _, ok := str(get(site, "php_version")); ok {
		t.Error("unquoted 8.3 must be a number, not a string")
	}
	if s, _ := str(get(site, "root")); s != "017" {
		t.Errorf("quoted root = %q", s)
	}
	if v, err := parseYAML(nil); err != nil || v != nil {
		t.Errorf("empty document = %v, %v; want nil, nil", v, err)
	}
}
