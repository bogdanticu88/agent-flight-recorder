package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Acquisition copies each artifact exactly once into a private snapshot
// directory, hashing while copying. Parsing, hashing and raw inclusion all use
// those snapshot bytes, so the bundle describes what was actually analysed.
//
// Ordinary file copies are not atomic. Each source is stat'ed before and after
// copying; a change in size or modification time is retried and, if it keeps
// changing, reported. That detects most concurrent writes but cannot prove the
// absence of one (a same-size rewrite within the clock resolution is invisible).

// acquireHook, when set by tests, runs after each file is copied and before
// it is re-checked, so tests can simulate a concurrent writer.
var acquireHook func(path string)

// beforeOpenHook, when set by tests, runs after the containment check and
// just before a file is opened, so tests can swap a path for a symlink.
var beforeOpenHook func(path string)

// ErrOutsideRoots marks a path that resolves outside the acquisition roots.
var ErrOutsideRoots = errors.New("outside the acquisition roots")

// Scope limits which paths acquisition may read: everything under the
// examined profile, explicit workspaces, and the image root when one is set.
type Scope struct {
	Root  string   // mounted image root ("" = the running system)
	Bases []string // resolved directories reads must stay inside
}

func resolveDir(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	return filepath.Clean(p)
}

func within(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Check resolves p (following symlinks) and confirms the target is a regular
// file or directory inside one of the bases. It never follows a link out.
func (s Scope) Check(p string) (string, os.FileInfo, error) {
	lst, err := os.Lstat(p)
	if err != nil {
		return "", nil, err
	}
	real := p
	if lst.Mode()&os.ModeSymlink != 0 {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return "", nil, fmt.Errorf("symlink %s cannot be resolved: %w", p, err)
		}
		real = r
	}
	real = resolveDir(real)
	ok := false
	for _, b := range s.Bases {
		if within(real, b) {
			ok = true
			break
		}
	}
	if !ok {
		return "", nil, fmt.Errorf("%s resolves to %s, %w; not read", p, real, ErrOutsideRoots)
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", nil, err
	}
	if !st.Mode().IsRegular() && !st.IsDir() {
		return "", nil, fmt.Errorf("%s is not a regular file or directory (mode %s); not read", p, st.Mode())
	}
	return real, st, nil
}

var winDrive = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// MapPath turns a path recorded on the evidence host (for example a session's
// cwd) into a path on the analysis host. On the running system it is used as
// is. Under an image root, absolute POSIX and drive-letter paths are re-rooted
// into the image; anything else (relative, UNC, device paths) has no safe
// mapping and is rejected.
func (s Scope) MapPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if s.Root == "" {
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("relative path %q has no defined location", p)
		}
		return filepath.Clean(p), nil
	}
	var rel string
	switch {
	case strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//"):
		return "", fmt.Errorf("UNC or device path %q cannot be mapped into the image", p)
	case winDrive.MatchString(p):
		rel = strings.ReplaceAll(p[3:], `\`, "/")
	case strings.HasPrefix(p, "/"):
		rel = p
	default:
		return "", fmt.Errorf("relative path %q has no defined location in the image", p)
	}
	// Clean as a rooted path first, so ".." can never climb above the image root.
	rel = path.Clean("/" + rel)
	return filepath.Join(s.Root, filepath.FromSlash(rel)), nil
}

type statSig struct {
	size int64
	mod  time.Time
}

func sig(p string) (statSig, bool) {
	st, err := os.Stat(p)
	if err != nil {
		return statSig{}, false
	}
	return statSig{st.Size(), st.ModTime()}, true
}

// copyHash copies src to dst and returns the SHA-256 and byte count of what
// was written. With a scope, the file actually opened is checked after the
// open: its path must still resolve inside the roots, and the resolved file
// must be the same file (device and inode, or volume and file index) as the
// open handle. A path swapped for a link between the containment check and
// the open is therefore rejected rather than followed. Hard links to files
// outside the roots are not detectable this way.
func copyHash(src, dst string, scope *Scope) (string, int64, error) {
	if beforeOpenHook != nil {
		beforeOpenHook(src)
	}
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	if scope != nil {
		opened, err := in.Stat()
		if err != nil {
			return "", 0, err
		}
		real, st, err := scope.Check(src)
		if err != nil {
			return "", 0, fmt.Errorf("after opening: %w", err)
		}
		if !os.SameFile(opened, st) {
			return "", 0, fmt.Errorf("%s changed between the containment check and the open (now %s); not read", src, real)
		}
		if !opened.Mode().IsRegular() {
			return "", 0, fmt.Errorf("%s is not a regular file; not read", src)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// acquireSet copies a group of files that must be read together (a SQLite
// database with its -wal and -shm, or a single file). It retries while any
// member changes during the copy. Missing optional members are skipped.
func acquireSet(members []string, roles []string, dstDir string, scope *Scope) ([]FileEvidence, []string, error) {
	const attempts = 3
	var notes []string
	for attempt := 1; attempt <= attempts; attempt++ {
		for _, m := range members {
			_ = os.Remove(filepath.Join(dstDir, filepath.Base(m)))
		}
		var ev []FileEvidence
		before := map[string]statSig{}
		for _, m := range members {
			if s, ok := sig(m); ok {
				before[m] = s
			}
		}
		changed := false
		for i, m := range members {
			if _, ok := before[m]; !ok {
				if i == 0 {
					return nil, notes, fmt.Errorf("%s disappeared before it could be read", m)
				}
				continue
			}
			sum, n, err := copyHash(m, filepath.Join(dstDir, filepath.Base(m)), scope)
			if err != nil {
				if i > 0 && errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, notes, fmt.Errorf("reading %s: %w", m, err)
			}
			if acquireHook != nil {
				acquireHook(m)
			}
			after, _ := sig(m)
			c := after != before[m] || n != before[m].size
			changed = changed || c
			ev = append(ev, FileEvidence{Path: m, Role: roles[i], Size: n, ModTime: before[m].mod.UTC().Format(time.RFC3339Nano), SHA256: sum, Changed: c})
		}
		if !changed {
			if attempt > 1 {
				notes = append(notes, fmt.Sprintf("files changed during acquisition; stable copy obtained on attempt %d", attempt))
			}
			return ev, notes, nil
		}
		if attempt == attempts {
			notes = append(notes, fmt.Sprintf("files kept changing during acquisition (%d attempts); the snapshot may be internally inconsistent", attempts))
			return ev, notes, nil
		}
	}
	return nil, notes, errors.New("unreachable")
}

// acquireDir copies every regular file under dir, without following links,
// and returns per-file evidence. Links and special files are listed as
// skipped; files that could not be read, or kept changing, are counted in
// failed so the caller can mark the collection partial.
func acquireDir(dir, dstDir string, scope *Scope) ([]FileEvidence, []string, int, error) {
	var ev []FileEvidence
	var notes []string
	count, failed := 0, 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			failed++
			notes = append(notes, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			notes = append(notes, fmt.Sprintf("%s: link or special file, not followed", rel))
			return nil
		}
		count++
		if count > maxDirFiles {
			return fmt.Errorf("more than %d files under %s", maxDirFiles, dir)
		}
		fe, n2, err := acquireSet([]string{p}, []string{"child"}, filepath.Join(dstDir, filepath.Dir(rel)), scope)
		for _, n := range n2 {
			notes = append(notes, rel+": "+n)
		}
		if err != nil {
			failed++
			notes = append(notes, fmt.Sprintf("%s: %v", rel, err))
			return nil
		}
		if anyChanged(fe) {
			failed++
		}
		ev = append(ev, fe...)
		return nil
	})
	sort.Slice(ev, func(i, j int) bool { return ev[i].Path < ev[j].Path })
	return ev, notes, failed, err
}

// anyChanged reports whether any member was still changing on the last attempt.
func anyChanged(fe []FileEvidence) bool {
	for _, f := range fe {
		if f.Changed {
			return true
		}
	}
	return false
}

// digestFiles is a stable digest over per-file evidence, used as the single
// hash of a directory source.
func digestFiles(ev []FileEvidence) string {
	h := sha256.New()
	for _, f := range ev {
		fmt.Fprintf(h, "%s\t%s\t%d\n", filepath.ToSlash(f.Path), f.SHA256, f.Size)
	}
	return hex.EncodeToString(h.Sum(nil))
}
