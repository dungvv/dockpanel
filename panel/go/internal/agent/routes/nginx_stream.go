package routes

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

type nginxStreamProxyRequest struct {
	Name       string `json:"name"`
	ListenPort uint16 `json:"listen_port"`
	// Generic proxies name the upstream; database proxies send ContainerID
	// instead — the upstream is then read off the container's own loopback
	// binding, never trusted from the wire.
	UpstreamHost *string  `json:"upstream_host"`
	UpstreamPort *uint16  `json:"upstream_port"`
	ContainerID  *string  `json:"container_id"`
	Tls          bool     `json:"tls"`
	CertPath     *string  `json:"cert_path"`
	KeyPath      *string  `json:"key_path"`
	AllowCidrs   []string `json:"allow_cidrs"` // empty = anyone
}

// nginxStreamCertRoots: cert/key paths must already live under the managed
// roots — anywhere else would let a caller make nginx read (and log)
// arbitrary files at reload.
var nginxStreamCertRoots = []string{"/etc/dockpanel/ssl-registry/", "/etc/dockpanel/ssl/", "/etc/letsencrypt/"}

func nginxStreamValidateCertPath(path, field string) error {
	under := false
	for _, root := range nginxStreamCertRoots {
		if strings.HasPrefix(path, root) {
			under = true
		}
	}
	fi, err := os.Stat(path)
	if under && !strings.Contains(path, "..") && err == nil && fi.Mode().IsRegular() {
		return nil
	}
	return fmt.Errorf("%s '%s' is not a file under the managed certificate roots", field, path)
}

// nginxStreamCreate: POST /nginx/streams.
func nginxStreamCreate(st *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b nginxStreamProxyRequest
		if !nginxDecodeStrict(w, r, &b, "name", "listen_port") {
			return
		}
		// Two shapes, never both: an explicit host:port, or a container whose
		// binding the agent reads itself.
		var host string
		var port uint16
		if b.ContainerID != nil {
			p, err := services.NginxStreamContainerLoopbackPort(r.Context(), st.Docker, *b.ContainerID)
			if err != nil {
				nginxPlain(w, http.StatusBadRequest, err.Error())
				return
			}
			host, port = "127.0.0.1", p
		} else {
			if b.UpstreamHost == nil {
				nginxPlain(w, http.StatusBadRequest, "missing upstream_host")
				return
			}
			if b.UpstreamPort == nil {
				nginxPlain(w, http.StatusBadRequest, "missing upstream_port")
				return
			}
			host, port = *b.UpstreamHost, *b.UpstreamPort
		}

		var tls *services.NginxStreamTlsPaths
		if b.Tls {
			if b.CertPath == nil {
				nginxPlain(w, http.StatusBadRequest, "tls requires cert_path")
				return
			}
			if b.KeyPath == nil {
				nginxPlain(w, http.StatusBadRequest, "tls requires key_path")
				return
			}
			for _, c := range [][2]string{{*b.CertPath, "cert_path"}, {*b.KeyPath, "key_path"}} {
				if err := nginxStreamValidateCertPath(c[0], c[1]); err != nil {
					nginxPlain(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			tls = &services.NginxStreamTlsPaths{Cert: *b.CertPath, Key: *b.KeyPath}
		}

		path, err := services.NginxStreamWriteProxy(b.Name, b.ListenPort, host, port, tls, b.AllowCidrs)
		if err != nil {
			nginxPlain(w, http.StatusBadRequest, err.Error())
			return
		}
		// The listener exists now — open the firewall. false = no manager or
		// a failed rule; the port is then already open, not an error.
		if !services.FirewallAddPort(fmt.Sprint(b.ListenPort), "tcp") {
			slog.Warn(fmt.Sprintf("firewall rule for tcp/%d not added — no firewall manager or rule failed", b.ListenPort))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "name": b.Name, "path": path, "listen_port": b.ListenPort,
			"upstream": fmt.Sprintf("%s:%d", host, port),
		})
	}
}

// nginxStreamList: GET /nginx/streams.
func nginxStreamList(w http.ResponseWriter, _ *http.Request) {
	proxies := []map[string]any{}
	for _, p := range services.NginxStreamListProxies() {
		proxies = append(proxies, map[string]any{"name": p[0], "listen_upstream": p[1]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": services.NginxStreamAvailable(), "proxies": proxies})
}

// nginxStreamDelete: DELETE /nginx/streams/{name}?listen_port=.
func nginxStreamDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	port, ok := nginxQueryUint(w, r, "listen_port", 16)
	if !ok {
		return
	}
	if err := services.NginxStreamRemoveProxy(name); err != nil {
		nginxPlain(w, http.StatusInternalServerError, err.Error())
		return
	}
	if port != nil {
		services.FirewallRemovePort(fmt.Sprint(*port), "tcp")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// registerNginxStream mounts src/routes/nginx_stream.rs.
func registerNginxStream(r *Router) {
	r.Handle("GET /nginx/streams", nginxStreamList)
	r.Handle("POST /nginx/streams", nginxStreamCreate(r.State))
	r.Handle("DELETE /nginx/streams/{name}", nginxStreamDelete)
}
