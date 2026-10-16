package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	socketPath     = "/var/run/dockpanel/agent.sock"
	agentTokenPath = "/etc/dockpanel/agent.token"
)

func loadAgentToken() (string, error) {
	t, err := readUTF8(agentTokenPath)
	if err != nil {
		return "", fmt.Errorf("Cannot read agent token at %s: %s\nAre you running as root?", agentTokenPath, ioErr(err))
	}
	return strings.TrimSpace(t), nil
}

// readUTF8 mirrors Rust's fs::read_to_string, which also rejects non-UTF-8.
func readUTF8(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errors.New("stream did not contain valid UTF-8")
	}
	return string(b), nil
}

// ioErr renders an OS error the way Rust's io::Error does
// ("No such file or directory (os error 2)") so messages match the Rust CLI.
func ioErr(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno != 0 {
		s := errno.Error()
		return strings.ToUpper(s[:1]) + s[1:] + fmt.Sprintf(" (os error %d)", int(errno))
	}
	return err.Error()
}

// agentRequest speaks raw HTTP/1.1 over the agent's Unix socket. A nil body
// means "no body" (agent_post_empty / GET / DELETE).
func agentRequest(method, path string, body any, token string) (any, error) {
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("Agent socket not found at %s\nIs dockpanel-agent running? Check: systemctl status dockpanel-agent", socketPath)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot connect to agent: %s", ioErr(err))
	}
	defer conn.Close()

	var bodyBytes []byte
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nConnection: close\r\n", method, path, token)
	if body != nil {
		bodyBytes = compactJSON(body)
		req += fmt.Sprintf("Content-Type: application/json\r\nContent-Length: %d\r\n", len(bodyBytes))
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("Failed to send request: %s", ioErr(err))
	}
	if body != nil {
		if _, err := conn.Write(bodyBytes); err != nil {
			return nil, fmt.Errorf("Failed to send body: %s", ioErr(err))
		}
	}

	buf, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response: %s", ioErr(err))
	}
	sep := bytes.Index(buf, []byte("\r\n\r\n"))
	if sep < 0 {
		return nil, errors.New("Invalid HTTP response: no header/body separator")
	}
	headers := strings.ToValidUTF8(string(buf[:sep]), "�")
	raw := buf[sep+4:]
	firstLine, _, _ := strings.Cut(headers, "\n")
	firstLine = strings.TrimSuffix(firstLine, "\r")
	chunked := strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked")
	payload := raw
	if chunked {
		payload = decodeChunked(raw)
	}

	if !strings.Contains(firstLine, "200") && !strings.Contains(firstLine, "201") {
		if v, err := parseJSON(payload); err == nil {
			if msg, ok := str(get(v, "error")); ok {
				return nil, errors.New(msg)
			}
			if msg, ok := str(get(v, "message")); ok {
				return nil, errors.New(msg)
			}
		}
		return nil, fmt.Errorf("Agent returned: %s", firstLine)
	}

	if len(payload) == 0 {
		return map[string]any{"success": true}, nil
	}
	v, err := parseJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("Invalid JSON from agent: %s\nBody: %s", err, lossyPrefix(payload, 200))
	}
	return v, nil
}

func agentGet(path, token string) (any, error) { return agentRequest("GET", path, nil, token) }
func agentPost(path string, body any, token string) (any, error) {
	return agentRequest("POST", path, body, token)
}
func agentPostEmpty(path, token string) (any, error) { return agentRequest("POST", path, nil, token) }
func agentPut(path string, body any, token string) (any, error) {
	return agentRequest("PUT", path, body, token)
}
func agentDelete(path, token string) (any, error) { return agentRequest("DELETE", path, nil, token) }

func decodeChunked(data []byte) []byte {
	var out []byte
	pos := 0
	for {
		end := bytes.Index(data[pos:], []byte("\r\n"))
		if end < 0 {
			break
		}
		end += pos
		size, err := strconv.ParseUint(strings.TrimSpace(string(data[pos:end])), 16, 64)
		if err != nil || size == 0 {
			break
		}
		start := end + 2
		stop := min(start+int(size), len(data))
		out = append(out, data[start:stop]...)
		pos = stop + 2
		if pos >= len(data) {
			break
		}
	}
	return out
}

func lossyPrefix(b []byte, n int) string {
	return strings.ToValidUTF8(string(b[:min(len(b), n)]), "�")
}

// ── JSON helpers: serde_json::Value-style access over decoded `any` ─────────
// Numbers decode as json.Number so integers vs floats keep their original
// text, which is what serde's as_u64/as_i64/as_f64 distinguish on.

func parseJSON(b []byte) (any, error) {
	if !json.Valid(b) {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		return nil, errors.New("trailing characters")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	err := d.Decode(&v)
	return v, err
}

func compactJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func pretty(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

func get(v any, key string) any {
	if m, ok := v.(map[string]any); ok {
		return m[key]
	}
	return nil
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func boolean(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func isTrue(v any) bool { b, ok := v.(bool); return ok && b }

func arr(v any) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok
}

func u64(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	return u, err == nil
}

func u64Or(v any, def uint64) uint64 {
	if u, ok := u64(v); ok {
		return u
	}
	return def
}

func i64Or(v any, def int64) int64 {
	if n, ok := v.(json.Number); ok {
		if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
			return i
		}
	}
	return def
}

func f64Or(v any, def float64) float64 {
	if n, ok := v.(json.Number); ok {
		if f, err := strconv.ParseFloat(string(n), 64); err == nil {
			return f
		}
	}
	return def
}

// shortID is Rust's &s[..s.len().min(12)].
func shortID(s string) string { return s[:min(len(s), 12)] }

// containsFold is the CLI's case-insensitive substring filter.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
