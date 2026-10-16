package routes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ovexro/dockpanel/panel/go/internal/agent/safecmd"
	"github.com/ovexro/dockpanel/panel/go/internal/agent/services"
)

func registerDeploy(r *Router) {
	r.Handle("POST /deploy/run", deployRunDeploy)
	r.Handle("POST /deploy/atomic", deployAtomic)
	r.Handle("GET /deploy/releases/{domain}", deployListReleases)
	r.Handle("POST /deploy/activate", deployActivateRelease)
	r.Handle("POST /deploy/keygen", deployKeygen)
	r.Handle("POST /sites/{domain}/laravel-migrate", deployLaravelMigrate)
}

type deployRequest struct {
	Domain       string  `json:"domain"`
	RepoURL      string  `json:"repo_url"`
	Branch       string  `json:"branch"`
	DeployScript *string `json:"deploy_script"`
	KeyPath      *string `json:"key_path"`
}

// deployValidateRepo checks repo_url and branch; "" when valid.
func deployValidateRepo(repoURL, branch string) string {
	if repoURL == "" || strings.HasPrefix(repoURL, "-") {
		return "Invalid repo_url"
	}
	if !strings.HasPrefix(repoURL, "https://") && !strings.HasPrefix(repoURL, "http://") &&
		!strings.HasPrefix(repoURL, "git@") && !strings.HasPrefix(repoURL, "ssh://") {
		return "repo_url must use https://, http://, ssh://, or git@ protocol"
	}
	if branch == "" || strings.HasPrefix(branch, "-") || strings.Contains(branch, "..") {
		return "Invalid branch name"
	}
	return ""
}

// deployRunDeploy: POST /deploy/run — clone/pull, then the optional script.
func deployRunDeploy(w http.ResponseWriter, r *http.Request) {
	var b deployRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "repo_url", "branch") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if msg := deployValidateRepo(b.RepoURL, b.Branch); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	slog.Info(fmt.Sprintf("Deploying %s from %s (%s)", b.Domain, gitBuildRedactURL(b.RepoURL), b.Branch))
	ctx := context.WithoutCancel(r.Context())

	res, err := services.DeployCloneOrPull(ctx, b.Domain, b.RepoURL, b.Branch, b.KeyPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !res.Success {
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false, "output": res.Output, "commit_hash": res.CommitHash,
			"duration_ms": res.DurationMs, "stage": "git",
		})
		return
	}
	output := res.Output
	if b.DeployScript != nil && strings.TrimSpace(*b.DeployScript) != "" {
		output += "\n--- Deploy Script ---\n"
		ok, scriptOut, err := services.DeployRunScript(ctx, b.Domain, *b.DeployScript)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		output += scriptOut
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false, "output": output, "commit_hash": res.CommitHash,
				"duration_ms": res.DurationMs, "stage": "script",
			})
			return
		}
	}
	commit := "None"
	if res.CommitHash != nil {
		commit = fmt.Sprintf("Some(%q)", *res.CommitHash)
	}
	slog.Info(fmt.Sprintf("Deploy complete for %s (commit: %s)", b.Domain, commit))
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "output": output, "commit_hash": res.CommitHash, "duration_ms": res.DurationMs,
	})
}

type deployKeygenRequest struct {
	Domain string `json:"domain"`
}

// deployKeygen: POST /deploy/keygen — generate an SSH deploy key pair.
func deployKeygen(w http.ResponseWriter, r *http.Request) {
	var b deployKeygenRequest
	if !nginxDecodeStrict(w, r, &b, "domain") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	pub, path, err := services.DeployGenerateDeployKey(r.Context(), b.Domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_key": pub, "key_path": path})
}

type deployAtomicRequest struct {
	Domain       string    `json:"domain"`
	RepoURL      string    `json:"repo_url"`
	Branch       string    `json:"branch"`
	DeployScript *string   `json:"deploy_script"`
	KeyPath      *string   `json:"key_path"`
	KeepReleases *uint32   `json:"keep_releases"`
	SharedDirs   *[]string `json:"shared_dirs"`
}

// deployAtomic: POST /deploy/atomic — zero-downtime deploy via symlink swap.
func deployAtomic(w http.ResponseWriter, r *http.Request) {
	var b deployAtomicRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "repo_url", "branch") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if msg := deployValidateRepo(b.RepoURL, b.Branch); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	keep := uint32(5)
	if b.KeepReleases != nil {
		keep = *b.KeepReleases
	}
	keep = min(max(keep, 2), 20)
	// Default shared paths for PHP sites (WordPress-compatible).
	shared := []string{"wp-content/uploads", ".env"}
	if b.SharedDirs != nil {
		shared = *b.SharedDirs
	}
	for _, s := range shared {
		if strings.Contains(s, "..") || strings.HasPrefix(s, "/") {
			writeErr(w, http.StatusBadRequest, "Shared paths must not contain '..' or start with '/'")
			return
		}
	}
	slog.Info(fmt.Sprintf("Atomic deploy %s from %s (%s) keep=%d", b.Domain, gitBuildRedactURL(b.RepoURL), b.Branch, keep))
	res, err := services.DeployAtomic(context.WithoutCancel(r.Context()), b.Domain, b.RepoURL, b.Branch, b.KeyPath, b.DeployScript, keep, shared)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": res.Success, "output": res.Output, "commit_hash": res.CommitHash, "duration_ms": res.DurationMs,
	})
}

// deployListReleases: GET /deploy/releases/{domain}.
func deployListReleases(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	releases, err := services.DeployListReleases(r.Context(), domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, releases)
}

type deployActivateRequest struct {
	Domain    string `json:"domain"`
	ReleaseID string `json:"release_id"`
}

// deployActivateRelease: POST /deploy/activate — roll back to a release.
func deployActivateRelease(w http.ResponseWriter, r *http.Request) {
	var b deployActivateRequest
	if !nginxDecodeStrict(w, r, &b, "domain", "release_id") {
		return
	}
	if !isValidDomain(b.Domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	if err := services.DeployActivateRelease(b.Domain, b.ReleaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info(fmt.Sprintf("Activated release %s for %s", b.ReleaseID, b.Domain))
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": fmt.Sprintf("Release %s activated", b.ReleaseID)})
}

// deployLaravelMigrate: POST /sites/{domain}/laravel-migrate — argv only, no
// shell interpolation.
func deployLaravelMigrate(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomain(domain) {
		writeErr(w, http.StatusBadRequest, "Invalid domain")
		return
	}
	siteDir := "/var/www/" + domain
	if _, err := os.Stat(siteDir); err != nil {
		writeErr(w, http.StatusNotFound, "Site directory not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	cmd := safecmd.Command(ctx, "php", "artisan", "migrate", "--force")
	cmd.Dir = siteDir
	out, err := safecmd.Run(ctx, cmd)
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "Migration timed out")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("Migration failed: %v", err))
		return
	}
	stdout, stderr := strings.ToValidUTF8(string(out.Stdout), "�"), strings.ToValidUTF8(string(out.Stderr), "�")
	if !out.Success() {
		slog.Warn(fmt.Sprintf("Laravel migrations failed for %s: %s", domain, stderr))
		writeErr(w, http.StatusInternalServerError, "Migration failed: "+stderr)
		return
	}
	slog.Info("Laravel migrations completed for " + domain)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "output": stdout})
}
