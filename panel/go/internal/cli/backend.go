package cli

// A second client, alongside agent.go, for the ONE class of operation the
// agent structurally cannot do: anything needing the panel's own database —
// site/database ownership, credentials, and (the reason this file exists) a
// restore that must load a database dump as well as replace files. agent.go
// talks to the agent over its local Unix socket with the agent's own token;
// this one talks to the panel API over HTTP with a separate, admin-minted
// `dp_`-prefixed key. On a single box that key authorizes no more than
// agent.token already does; on a fleet it reaches every server the minting
// admin registered — no narrower scope exists yet.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	apiEnvPath       = "/etc/dockpanel/api.env"
	backendTokenPath = "/etc/dockpanel/backend.token"
)

func loadBackendToken() (string, error) {
	notConfigured := fmt.Errorf("No panel API key configured at %s.\nMint one from the panel (Settings → API Keys), then save it to %s (root:root, mode 600).\nAre you running as root?", backendTokenPath, backendTokenPath)
	raw, err := readUTF8(backendTokenPath)
	if err != nil {
		return "", notConfigured
	}
	// An empty (or whitespace-only) file must read as "not configured" too —
	// otherwise a leftover file routes every restore into a panel-API call
	// that 401s instead of falling back to the agent-only path.
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", notConfigured
	}
	return token, nil
}

// backendBaseURL resolves the panel API from the SAME LISTEN_ADDR its systemd
// unit's EnvironmentFile= feeds it. Deliberately NOT BASE_URL: that is the
// panel's public address behind nginx/Cloudflare, which a CLI running on the
// box has no need to round-trip through.
func backendBaseURL() (string, error) {
	env, err := readUTF8(apiEnvPath)
	if err != nil {
		return "", fmt.Errorf("Cannot read %s: %s\nAre you running as root?", apiEnvPath, ioErr(err))
	}
	for _, l := range strings.Split(env, "\n") {
		if addr, ok := strings.CutPrefix(strings.TrimSpace(l), "LISTEN_ADDR="); ok {
			return "http://" + strings.TrimSpace(addr), nil
		}
	}
	return "", fmt.Errorf("%s has no LISTEN_ADDR — cannot reach the panel API", apiEnvPath)
}

// backendDo sends a request; error text mirrors reqwest's Display.
func backendDo(method, url, token string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(compactJSON(body))
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, fmt.Errorf("Cannot reach the panel API at %s: builder error", url)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cannot reach the panel API at %s: error sending request for url (%s)", url, url)
	}
	return resp, nil
}

func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return fmt.Sprintf("%d %s", code, t)
	}
	return fmt.Sprintf("%d <unknown status code>", code)
}

func backendRequest(method, path, token string) (any, error) {
	base, err := backendBaseURL()
	if err != nil {
		return nil, err
	}
	resp, err := backendDo(method, base+path, token, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	text := strings.ToValidUTF8(string(b), "�")

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if v, err := parseJSON([]byte(text)); err == nil {
			if msg, ok := str(get(v, "error")); ok {
				return nil, errors.New(msg)
			}
		}
		return nil, fmt.Errorf("Panel API returned %s: %s", statusText(resp.StatusCode), text)
	}
	if text == "" {
		return map[string]any{}, nil
	}
	v, err := parseJSON([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("Invalid JSON from panel API: %s\nBody: %s", err, lossyPrefix([]byte(text), 200))
	}
	return v, nil
}

func backendGet(path, token string) (any, error)       { return backendRequest("GET", path, token) }
func backendPostEmpty(path, token string) (any, error) { return backendRequest("POST", path, token) }

// followProgress consumes the panel's provisioning-log SSE stream until a
// `step == "complete"` event or the connection ends, printing each step.
//
// Pass/fail is decided ONLY by the terminal "complete" event's own status,
// matching the panel UI (ProvisionLog.tsx) — the restore handler emits a
// non-fatal advisory with status "error" for a files-only archive restored
// onto a DB-attached site and still finishes "done"; latching on any error
// step would report a failure the app itself does not consider one.
//
// Frames are `data: <json>` lines separated by a blank line; keep-alive
// comments (`: ping`) are skipped. Raw BYTES are buffered and a frame is only
// UTF-8-decoded once its terminating "\n\n" arrived, so a multi-byte character
// split across reads never turns into a replacement character.
func followProgress(installID, token string) error {
	base, err := backendBaseURL()
	if err != nil {
		return err
	}
	resp, err := backendDo("GET", base+"/api/services/install/"+installID+"/log", token, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Panel API refused the progress stream: %s", strings.ToValidUTF8(string(b), "�"))
	}

	var buf []byte
	chunk := make([]byte, 8192)
	for {
		n, rerr := resp.Body.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			pos := bytes.Index(buf, []byte("\n\n"))
			if pos < 0 {
				break
			}
			frame := strings.ToValidUTF8(string(buf[:pos+2]), "�")
			buf = buf[pos+2:]
			for _, line := range strings.Split(frame, "\n") {
				data, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "data: ")
				if !ok {
					continue
				}
				step, err := parseJSON([]byte(data))
				if err != nil {
					continue
				}
				status := strOr(get(step, "status"), "")
				icon := "\x1b[33m…\x1b[0m"
				switch status {
				case "done":
					icon = "\x1b[32m✓\x1b[0m"
				case "error":
					icon = "\x1b[31m✗\x1b[0m"
				}
				fmt.Printf("  %s %s\n", icon, strOr(get(step, "label"), ""))
				if msg, ok := str(get(step, "message")); ok {
					fmt.Printf("      %s\n", msg)
				}
				if strOr(get(step, "step"), "") == "complete" {
					if status == "error" {
						return errors.New("Restore failed — see the messages above.")
					}
					return nil
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("Progress stream error: %s", rerr)
		}
	}
	return errors.New("Progress stream ended before the restore completed.")
}
