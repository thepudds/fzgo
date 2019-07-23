package fuzz

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// CacheDir returns <GOPATH>/pkg/fuzz/<GOOS_GOARCH>/<hash>/<package_fuzzfunc>/
func CacheDir(hash, pkgName, fuzzName string) string {
	gp := os.Getenv("GOPATH")
	if gp == "" {
		gp = build.Default.GOPATH
	}
	s := strings.Split(gp, string(os.PathListSeparator))
	if len(s) > 1 {
		gp = s[0]
	}
	return filepath.Join(gp, "pkg", "fuzz", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH),
		hash, fuzzName)
}

// Hash returns a string representing the hash of the files in a package, its dependencies,
// as well as the fuzz func name, the version of go and the go-fuzz-build binary.
func Hash(pkgPath, funcName, trimPrefix string, env []string, verbose bool) (string, error) {
	report := func(err error) (string, error) {
		return "", fmt.Errorf("fzgo cache hash: %v", err)
	}
	h := sha256.New()

	// hash the contents of our package and dependencies
	dirs, err := goListDeps(pkgPath, env)
	if err != nil {
		return report(err)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		hd, err := hashDir(dir, trimPrefix)
		if err != nil {
			return report(err)
		}

		fmt.Fprintf(h, "%s  %s\n", hd, strings.TrimPrefix(dir, trimPrefix))
		if verbose {
			fmt.Printf("%s  %s\n", hd, dir)
		}
	}

	// hash the go-fuzz-build binary.
	// first, check if go-fuzz seems to be installed.
	err = checkGoFuzz()
	if err != nil {
		// err here suggests running 'go get' for go-fuzz
		return report(err)
	}
	path, err := exec.LookPath("go-fuzz-build")
	if err != nil {
		return report(err)
	}
	f, err := os.Open(path)
	if err != nil {
		return report(err)
	}
	defer f.Close()
	hf := sha256.New()
	_, err = io.Copy(hf, f)
	if err != nil {
		return report(err)
	}
	s := hf.Sum(nil)
	fmt.Fprintf(h, "%x  %s\n", s, "go-fuzz-build")
	if verbose {
		fmt.Printf("%x  %s\n", s, "go-fuzz-build")
	}

	// hash the fuzz func name
	fmt.Fprintf(h, "%s fuzzfunc\n", funcName)

	// hash the go version
	fmt.Fprintf(h, "%s go version\n", runtime.Version())

	return fmt.Sprintf("%x", h.Sum(nil)[:10]), nil
}

// hashDir hashes files without descending into subdirectories.
func hashDir(dir, trimPrefix string) (string, error) {

	var absFiles []string
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.IsDir() || !file.Mode().IsRegular() {
			continue
		}
		filename := file.Name()
		abs, err := filepath.Abs(filepath.Join(dir, filename))
		if err != nil {
			return "", err
		}
		absFiles = append(absFiles, abs)

	}

	return hashFiles(absFiles, trimPrefix)
}

// Adapted from dirhash.Hash1. The largest difference is
// the filenames within a trimPrefix directory won't use
// the trimPrefix string as part of the hash.
// The file contents are still hashed.
func hashFiles(files []string, trimPrefix string) (string, error) {
	h := sha256.New()
	files = append([]string(nil), files...)
	sort.Strings(files)
	for _, file := range files {
		if strings.Contains(file, "\n") {
			return "", errors.New("filenames with newlines are not supported")
		}
		r, err := os.Open(file)
		if err != nil {
			return "", err
		}
		hf := sha256.New()
		_, err = io.Copy(hf, r)
		r.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%x  %s\n", hf.Sum(nil), strings.TrimPrefix(file, trimPrefix))
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// goListDeps returns a []string of dirs for all dependencies of pkg
func goListDeps(pkg string, env []string) ([]string, error) {
	if len(env) == 0 {
		env = os.Environ()
	}

	cmd := exec.Command("go", "list", "-deps", "-f", "{{.Dir}}", buildTagsArg, pkg)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	results := []string{}
	for scanner.Scan() {
		results = append(results, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
