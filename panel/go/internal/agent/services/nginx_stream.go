package services

// TCP proxying through nginx's `stream` context.
//
// `stream` is a top-level sibling of `http`; managed proxies are one file each
// under NginxStreamDir, included by the `stream {}` block setup.sh/update.sh
// wire into nginx.conf. Two consumers: database remote access (proxy_pass to
// a managed DB container's existing loopback-only binding — never republished
// publicly) and generic TCP proxies (a validated operator host:port).
//
// Write lifecycle = the vhost writers' contract: validate everything, publish
// atomically, `nginx -t`, reload, and roll back when either refuses.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/moby/moby/client"
)

// NginxStreamDir is where the top-level `stream { include … }` points. The
// agent refuses to write when the include is not wired: a dropped file would
// sit inert while the panel reported a proxy that does not exist.
const NginxStreamDir = "/etc/nginx/dockpanel-streams"

// Public TCP listen ports come only from this range (allocated by the backend,
// verified free here), clear of Docker's ephemeral range and panel listeners.
const (
	NginxStreamListenPortMin uint16 = 40000
	NginxStreamListenPortMax uint16 = 44999
)

// NginxStreamTlsPaths are registry-resolved cert/key paths, referenced in
// place — key material is never copied into the stream directory.
type NginxStreamTlsPaths struct {
	Cert string
	Key  string
}

// NginxStreamAvailableAt reports whether nginx.conf wires the managed include.
func NginxStreamAvailableAt(nginxConf string) bool {
	b, err := os.ReadFile(nginxConf)
	return err == nil && strings.Contains(string(b), "dockpanel-streams")
}

// NginxStreamAvailable reports whether stream proxies can be written here.
func NginxStreamAvailable() bool { return NginxStreamAvailableAt("/etc/nginx/nginx.conf") }

// NginxStreamValidateProxyName: names double as filenames, so the alphabet is
// a lowercase slug — `../evil` and `a b` never reach the filesystem.
func NginxStreamValidateProxyName(name string) error {
	if name == "" || len(name) > 48 {
		return errors.New("proxy name must be 1-48 characters")
	}
	ok := !strings.HasPrefix(name, "-") && !strings.HasSuffix(name, "-")
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			ok = false
		}
	}
	if !ok {
		return fmt.Errorf("invalid proxy name '%s' — use lowercase letters, digits and '-'", name)
	}
	return nil
}

// NginxStreamValidateListenPort confines public ports to the managed range,
// so a proxy can never shadow an HTTP listener, the panel, or Docker.
func NginxStreamValidateListenPort(port uint16) error {
	if port >= NginxStreamListenPortMin && port <= NginxStreamListenPortMax {
		return nil
	}
	return fmt.Errorf("listen port %d is outside the managed TCP proxy range %d-%d",
		port, NginxStreamListenPortMin, NginxStreamListenPortMax)
}

// NginxStreamNormalizeUpstreamHost validates a proxy_pass host. Anything nginx
// would read as more than one token is an injection into a root-run config,
// so only an IP literal (IPv6 bracketed) or a plain hostname passes.
func NginxStreamNormalizeUpstreamHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") && len(h) >= 2 {
		inner := h[1 : len(h)-1]
		if a, err := netip.ParseAddr(inner); err == nil && a.Is6() && a.Zone() == "" {
			return "[" + inner + "]", nil
		}
		return "", fmt.Errorf("invalid IPv6 upstream '%s'", h)
	}
	if a, err := netip.ParseAddr(h); err == nil && a.Is4() {
		return h, nil
	}
	// A digits-and-dots name that is not a valid IPv4 literal is not a hostname
	// either — nginx would fail loudly at config load, a worse failure.
	if strings.Trim(h, "0123456789.") == "" {
		return "", fmt.Errorf("invalid IPv4 upstream '%s'", h)
	}
	valid := h != "" && len(h) <= 253 &&
		!strings.HasPrefix(h, ".") && !strings.HasPrefix(h, "-") &&
		!strings.HasSuffix(h, ".") && !strings.HasSuffix(h, "-") && !strings.Contains(h, "..")
	for _, c := range h {
		if !nginxIsASCIIAlnum(c) && c != '.' && c != '-' && c != '_' {
			valid = false
		}
	}
	if !valid {
		return "", fmt.Errorf("invalid upstream host '%s'", host)
	}
	return h, nil
}

// NginxStreamNormalizeUpstream returns the validated `host:port`.
func NginxStreamNormalizeUpstream(host string, port uint16) (string, error) {
	h, err := NginxStreamNormalizeUpstreamHost(host)
	if err != nil {
		return "", err
	}
	if port == 0 {
		return "", errors.New("upstream port must be 1-65535")
	}
	return fmt.Sprintf("%s:%d", h, port), nil
}

// NginxStreamNormalizeAllowEntry validates one IP or ip/bits CIDR. The output
// is re-rendered from the parsed address, so nothing typed reaches the config
// verbatim.
func NginxStreamNormalizeAllowEntry(entry string) (string, error) {
	e := strings.TrimSpace(entry)
	bad := fmt.Errorf("invalid allow entry '%s' — use an IP or CIDR like 203.0.113.0/24", e)
	ipStr, bitsStr, hasBits := strings.Cut(e, "/")
	bits := -1
	if hasBits {
		// Rust's u8::from_str accepts one leading '+'.
		b, err := strconv.ParseUint(strings.TrimPrefix(bitsStr, "+"), 10, 8)
		if err != nil {
			return "", bad
		}
		bits = int(b)
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || ip.Zone() != "" {
		return "", bad
	}
	if bits < 0 {
		return ip.String(), nil
	}
	maxBits := 128
	if ip.Is4() {
		maxBits = 32
	}
	if bits > maxBits {
		return "", bad
	}
	return fmt.Sprintf("%s/%d", ip, bits), nil
}

// NginxStreamConfigPath is the one file a proxy lives in.
func NginxStreamConfigPath(name string) string {
	return fmt.Sprintf("%s/%s.conf", NginxStreamDir, name)
}

// NginxStreamContainerLoopbackPort reads the loopback port a managed database
// container is bound to — from the container itself, never from the wire.
// Refuses an unmanaged container (a forward into it would be a read primitive
// on loopback-bound services) and one with no 127.0.0.1/::1 binding (this code
// never adds a public binding).
func NginxStreamContainerLoopbackPort(ctx context.Context, docker *client.Client, containerID string) (uint16, error) {
	info, err := docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("cannot inspect container '%s': %v", containerID, err)
	}
	c := info.Container
	if c.Config == nil || c.Config.Labels["dockpanel.managed"] != "true" {
		return 0, fmt.Errorf("container '%s' is not panel-managed — refusing to proxy to it", containerID)
	}
	if c.HostConfig != nil {
		for _, bindings := range c.HostConfig.PortBindings {
			for _, b := range bindings {
				if !b.HostIP.IsValid() {
					continue
				}
				if ip := b.HostIP.String(); ip == "127.0.0.1" || ip == "::1" {
					if p, err := strconv.ParseUint(b.HostPort, 10, 16); err == nil {
						return uint16(p), nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("container '%s' has no loopback port binding — refusing to guess an upstream", containerID)
}

// NginxStreamRenderServer renders one stream `server {}`. Everything
// interpolated has already passed the validators.
func NginxStreamRenderServer(listenPort uint16, upstream string, tls *NginxStreamTlsPaths, allow []string) string {
	var b strings.Builder
	b.WriteString("# Managed by DockPanel — do not edit; rewritten by the agent.\nserver {\n")
	if tls != nil {
		fmt.Fprintf(&b, "    listen %d ssl;\n", listenPort)
		fmt.Fprintf(&b, "    ssl_certificate %s;\n", tls.Cert)
		fmt.Fprintf(&b, "    ssl_certificate_key %s;\n", tls.Key)
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	} else {
		fmt.Fprintf(&b, "    listen %d;\n", listenPort)
	}
	// Empty means open to anyone; otherwise only listed sources get through.
	if len(allow) > 0 {
		for _, a := range allow {
			fmt.Fprintf(&b, "    allow %s;\n", a)
		}
		b.WriteString("    deny all;\n")
	}
	fmt.Fprintf(&b, "    proxy_pass %s;\n", upstream)
	// DB sessions idle far past nginx's 10m default ("remote access drops
	// after a coffee break"), so the timeout is generous; connect stays tight.
	b.WriteString("    proxy_connect_timeout 10s;\n    proxy_timeout 1h;\n}\n")
	return b.String()
}

// NginxStreamListenPortFree: can the port be bound right now? The backend's
// allocation is authoritative, but a stale row or manual binding must never
// produce a config nginx cannot start.
func NginxStreamListenPortFree(port uint16) bool {
	l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// NginxStreamWriteProxy creates a managed stream proxy and returns its path.
func NginxStreamWriteProxy(name string, listenPort uint16, upstreamHost string, upstreamPort uint16,
	tls *NginxStreamTlsPaths, allow []string) (string, error) {
	if err := NginxStreamValidateProxyName(name); err != nil {
		return "", err
	}
	if err := NginxStreamValidateListenPort(listenPort); err != nil {
		return "", err
	}
	upstream, err := NginxStreamNormalizeUpstream(upstreamHost, upstreamPort)
	if err != nil {
		return "", err
	}
	normAllow := make([]string, 0, len(allow))
	for _, a := range allow {
		n, err := NginxStreamNormalizeAllowEntry(a)
		if err != nil {
			return "", err
		}
		normAllow = append(normAllow, n)
	}
	if !NginxStreamAvailable() {
		return "", errors.New("nginx stream module/include is not wired on this box — run update.sh or enable " +
			"the stream module, then retry")
	}
	if !NginxStreamListenPortFree(listenPort) {
		return "", fmt.Errorf("port %d is already bound on this host", listenPort)
	}
	// `nginx -t` is whole-server: writing into an already-broken config would
	// pin someone else's defect on this proxy.
	if out, err := NginxTestConfig(); err == nil && !out.Success {
		return "", fmt.Errorf("nginx config is already failing `nginx -t` — refusing to write a stream "+
			"proxy on top of a broken configuration: %s", strings.TrimSpace(out.Stderr))
	}

	path := NginxStreamConfigPath(name)
	body := NginxStreamRenderServer(listenPort, upstream, tls, normAllow)
	if err := os.MkdirAll(NginxStreamDir, 0o755); err != nil {
		return "", fmt.Errorf("cannot create %s: %v", NginxStreamDir, err)
	}
	// Create never overwrites: a second create for a live name (double click,
	// app_db/app-db slug collision) used to replace the live file, and the
	// panel's rollback then deleted it. A hard link publishes atomically AND
	// fails if the name is taken; the per-call temp name keeps concurrent
	// writers off each other's bytes.
	tmp := fmt.Sprintf("%s.%s.tmp", path, uuid.NewString())
	err = os.WriteFile(tmp, []byte(body), 0o644)
	if err == nil {
		err = os.Link(tmp, path)
	}
	_ = os.Remove(tmp)
	if errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("stream proxy '%s' already exists", name)
	}
	if err != nil {
		return "", fmt.Errorf("failed to write %s: %v", path, nginxIOErr(err))
	}

	out, err := NginxTestConfig()
	switch {
	case err != nil:
		NginxRestoreOrRemove(path, nil)
		return "", fmt.Errorf("nginx -t could not run: %v", err)
	case !out.Success:
		NginxRestoreOrRemove(path, nil)
		return "", fmt.Errorf("nginx -t rejected the stream config: %s", strings.TrimSpace(out.Stderr))
	}
	// A reload failing after `nginx -t` passed must not leave the file: the
	// panel records no row on error, so it would be an orphan listener the
	// next reload silently brings up.
	if err := NginxReload(); err != nil {
		NginxRestoreOrRemove(path, nil)
		return "", err
	}
	return path, nil
}

// NginxStreamRemoveProxy removes a managed proxy. Idempotent: a missing file
// is success (no such listener is already true).
func NginxStreamRemoveProxy(name string) error {
	if err := NginxStreamValidateProxyName(name); err != nil {
		return err
	}
	path := NginxStreamConfigPath(name)
	if !nginxExists(path) {
		return nil
	}
	var previous *string
	if b, err := os.ReadFile(path); err == nil {
		s := string(b)
		previous = &s
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove %s: %v", path, nginxIOErr(err))
	}
	out, err := NginxTestConfig()
	if err != nil {
		NginxRestoreOrRemove(path, previous)
		return fmt.Errorf("nginx -t could not run: %v", err)
	}
	if !out.Success {
		restored := NginxRestoreOrRemove(path, previous)
		return fmt.Errorf("nginx -t failed after removing %s: %s%s", name, strings.TrimSpace(out.Stderr), NginxRestoreNote(restored))
	}
	return NginxReload()
}

// NginxStreamListProxies returns (name, "listen -> upstream") for each stream
// file nginx reads, sorted.
func NginxStreamListProxies() [][2]string {
	var out [][2]string
	entries, err := os.ReadDir(NginxStreamDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		stem, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok {
			continue
		}
		b, err := os.ReadFile(NginxStreamDir + "/" + e.Name())
		if err != nil {
			continue
		}
		upstream, listen := "", ""
		upFound, listenFound := false, false
		for _, l := range nginxLines(string(b)) {
			t := strings.TrimSpace(l)
			if !upFound {
				if rest, ok := strings.CutPrefix(t, "proxy_pass "); ok {
					upstream, upFound = strings.TrimRight(rest, ";"), true
				}
			}
			if !listenFound {
				if rest, ok := strings.CutPrefix(t, "listen "); ok {
					if f := strings.Fields(strings.TrimRight(rest, ";")); len(f) > 0 {
						listen, listenFound = f[0], true
					}
				}
			}
		}
		out = append(out, [2]string{stem, listen + " -> " + upstream})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}
