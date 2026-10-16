package services

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const filesWebroot = "/var/www"

// FilesEntry is one row of a directory listing.
type FilesEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	Size     uint64 `json:"size"`
	Modified string `json:"modified"`
}

// FilesContent is a text file read for the editor.
type FilesContent struct {
	Content  string `json:"content"`
	Size     uint64 `json:"size"`
	Modified string `json:"modified"`
}

// FilesResolveSafePath resolves a user path inside /var/www/{domain}/,
// preventing traversal. The site root itself is permitted (listing it is the
// file manager's default view).
func FilesResolveSafePath(domain, relativePath string) (string, error) {
	return filesResolveWithin(filesWebroot+"/"+domain, relativePath)
}

// FilesResolveSafeChild resolves a path that must name something INSIDE the
// site root — never the root itself. `.`, "" and `/` all canonicalise to the
// webroot and pass the containment check, so a destructive verb handed one
// would erase the whole site and report success.
func FilesResolveSafeChild(domain, relativePath string) (string, error) {
	base := filesWebroot + "/" + domain
	resolved, err := filesResolveWithin(base, relativePath)
	if err != nil {
		return "", err
	}
	canonBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("Site root does not exist: %s", base)
	}
	if resolved == canonBase {
		return "", errors.New("Refusing to operate on the site root itself")
	}
	return resolved, nil
}

// filesComponents splits an absolute path the way Rust's Path::components
// does: empty and interior "." components vanish, ".." stays.
func filesComponents(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

func filesJoin(comps []string) string { return "/" + strings.Join(comps, "/") }

// filesWithin is Rust's component-wise Path::starts_with.
func filesWithin(p, base string) bool {
	return p == base || base == "/" || strings.HasPrefix(p, base+"/")
}

// filesResolveWithin is the core of FilesResolveSafePath, parameterised on the
// base so it is testable. It guarantees the result is inside base AND that no
// symlink sits in the to-be-created part of the path: a create/upload sink
// opens O_CREAT and follows a final symlink, which would write OUTSIDE the
// site root as root. A LIVE escaping symlink is caught by canonicalisation +
// the containment check; a DANGLING one is invisible to stat (it follows the
// link to an absent target) but visible to lstat, so it is refused explicitly.
func filesResolveWithin(base, relativePath string) (string, error) {
	// Rust let a NUL through to the syscall that then failed; refusing here
	// is the same outcome, earlier.
	if strings.ContainsRune(relativePath, 0) {
		return "", errors.New("Invalid path")
	}
	cleaned := strings.TrimLeft(relativePath, "/")
	candidate := base + "/" + cleaned

	canonBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("Site root does not exist: %s", base)
	}

	var canon string
	if _, err := os.Stat(candidate); err == nil {
		// Existing target: full symlink resolution, then the containment check.
		if canon, err = filepath.EvalSymlinks(candidate); err != nil {
			return "", fmt.Errorf("Path error: %v", nginxIOErr(err))
		}
	} else {
		// Not there yet (create/write/upload): walk up to the first existing ancestor.
		existing := filesComponents(candidate)
		var trail []string
		for {
			if _, err := os.Stat(filesJoin(existing)); err == nil {
				break
			}
			if len(existing) == 0 || existing[len(existing)-1] == ".." {
				return "", errors.New("Invalid path")
			}
			trail = append(trail, existing[len(existing)-1])
			existing = existing[:len(existing)-1]
		}
		// stat follows symlinks, so a dangling link read as "absent" and became
		// a trailing component. Re-check each with lstat and refuse ANY symlink.
		real := filesJoin(existing)
		for i := len(trail) - 1; i >= 0; i-- {
			real = strings.TrimSuffix(real, "/") + "/" + trail[i]
			if fi, err := os.Lstat(real); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("Path traversal denied (symlink in target path)")
			}
		}
		// Build the result on the CANONICAL ancestor so containment is symlink-free.
		resolved, err := filepath.EvalSymlinks(filesJoin(existing))
		if err != nil {
			return "", fmt.Errorf("Path resolution error: %v", nginxIOErr(err))
		}
		for i := len(trail) - 1; i >= 0; i-- {
			resolved = strings.TrimSuffix(resolved, "/") + "/" + trail[i]
		}
		canon = resolved
	}

	if !filesWithin(canon, canonBase) {
		return "", errors.New("Path traversal denied")
	}
	return canon, nil
}

// (`ensure_site_root` used to create /var/www/<domain> as root when listing a
// domain this host does not serve, answering 200 with an empty listing and
// unblocking writes into a directory no vhost serves. It is gone on purpose:
// every verb now fails loudly with "Site root does not exist".)

func filesModified(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

// FilesListDirectory lists path. With siteRoot set, entry paths are relative
// to it (canonicalised, in case /var/www is a symlink) so server paths never
// leak; a strip that misses fails CLOSED to the bare name.
func FilesListDirectory(path string, siteRoot string) ([]FilesEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("Cannot read directory: %v", nginxIOErr(err))
	}
	canonRoot := ""
	if siteRoot != "" {
		if canonRoot, err = filepath.EvalSymlinks(siteRoot); err != nil {
			canonRoot = siteRoot
		}
	}
	out := make([]FilesEntry, 0, len(entries))
	for _, e := range entries {
		fe := FilesEntry{Name: e.Name(), Path: e.Name()}
		if info, err := e.Info(); err == nil {
			fe.IsDir = info.IsDir()
			fe.Size = uint64(info.Size())
			fe.Modified = filesModified(info.ModTime())
		}
		abs := path + "/" + e.Name()
		if canonRoot != "" && filesWithin(abs, canonRoot) && abs != canonRoot {
			fe.Path = strings.TrimPrefix(strings.TrimPrefix(abs, canonRoot), "/")
		}
		out = append(out, fe)
	}
	// Directories first, then alphabetical.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// FilesReadFile reads a text file (max 2MB).
func FilesReadFile(path string) (FilesContent, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FilesContent{}, fmt.Errorf("File not found: %v", nginxIOErr(err))
	}
	if info.Size() > 2*1024*1024 {
		return FilesContent{}, errors.New("File too large (max 2MB)")
	}
	b, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(b) {
		return FilesContent{}, errors.New("File is binary or not readable as text")
	}
	return FilesContent{Content: string(b), Size: uint64(info.Size()), Modified: filesModified(info.ModTime())}, nil
}

// FilesWriteFile writes content atomically, creating parent directories. The
// temp is a collision-free sibling of FIXED short length: replacing the
// extension could clobber a real sibling (report.php → report.tmp), and
// embedding the name could exceed NAME_MAX for a long legal basename.
func FilesWriteFile(path, content string) error {
	parent := filepath.Dir(path)
	if !nginxExists(parent) {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("Failed to create directory: %v", nginxIOErr(err))
		}
	}
	tmp := filepath.Join(parent, ".dptmp."+uuid.NewString())
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("Failed to write: %v", nginxIOErr(err))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("Failed to finalize write: %v", nginxIOErr(err))
	}
	return nil
}

// FilesCreateEntry creates a file or directory.
func FilesCreateEntry(path string, isDir bool) error {
	if nginxExists(path) {
		return errors.New("Path already exists")
	}
	if isDir {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("Failed to create directory: %v", nginxIOErr(err))
		}
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		return fmt.Errorf("Failed to create file: %v", nginxIOErr(err))
	}
	return nil
}

// FilesRenameEntry renames/moves an entry.
func FilesRenameEntry(from, to string) error {
	if !nginxExists(from) {
		return errors.New("Source does not exist")
	}
	if nginxExists(to) {
		return errors.New("Destination already exists")
	}
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("Rename failed: %v", nginxIOErr(err))
	}
	return nil
}

// FilesDeleteEntry deletes a file or directory.
func FilesDeleteEntry(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.New("Path does not exist")
	}
	if info.IsDir() {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("Failed to delete directory: %v", nginxIOErr(err))
		}
		return nil
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("Failed to delete file: %v", nginxIOErr(err))
	}
	return nil
}
