package fuzz

import (
	"bufio"
	"crypto/sha256"
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

	"github.com/rogpeppe/go-internal/dirhash"
)

// CacheDir returns <GOPATH>/pkg/fuzz/<GOOS_GOARCH>/<hash>/<package_fuzzfunc>/
func CacheDir(hash, pkgName, fuzzName string) string {
	gp := os.Getenv("GOPATH")
	if gp == "" {
		gp = build.Default.GOPATH
	}
	return filepath.Join(gp, "pkg", "fuzz", fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH),
		hash, fuzzName)
}

// Hash returns a string representing the hash of the files in a package, its dependencies,
// as well as the fuzz func name, the version of go and the go-fuzz-build binary.
func Hash(pkgPath, funcName string, verbose bool) (string, error) {
	h := sha256.New()

	// hash the contents of our package and dependencies
	dirs, err := goListDeps(pkgPath)
	if err != nil {
		return "", err
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		hd, err := hashDir(dir)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s  %s\n", hd, dir)
		if verbose {
			fmt.Printf("%s  %s\n", hd, dir)
		}
	}

	// hash the go-fuzz-build binary.
	// first, check if go-fuzz seems to be installed.
	err = checkGoFuzz()
	if err != nil {
		// err here suggests running 'go get' for go-fuzz
		return "", err
	}
	path, err := exec.LookPath("go-fuzz-build")
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hf := sha256.New()
	_, err = io.Copy(hf, f)
	if err != nil {
		return "", err
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
func hashDir(dir string) (string, error) {

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

	osOpen := func(name string) (io.ReadCloser, error) {
		return os.Open(name)
	}
	return dirhash.Hash1(absFiles, osOpen)
}

// goListDeps returns a []string of dirs for all dependencies of pkg
func goListDeps(pkg string) ([]string, error) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.Dir}}", buildTagsArg, pkg).Output()
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
