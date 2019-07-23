package fuzz

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ErrGoTestFailed indicates that a 'go test' invocation failed,
// most likely because the test had a legitimate failure.
var ErrGoTestFailed = errors.New("go test failed")

// VerifyCorpus runs all of the files in a corpus directory as subtests.
// The approach is to create a temp dir, then create a synthetic corpus_test.go
// file with a TestCorpus(t *testing.T) func that loads all the files from the corpus,
// and passes them to the Fuzz function in a t.Run call.
// A standard 'go test .' is then invoked within that temporary directory.
// The inputs used are all deterministic (without generating new fuzzing-based inputs).
// The names used with t.Run mean a 'fzgo test -run=TestCorpus/<corpus-file-name>' works.
// One way to see the file names or otherwise verify execution is to run 'fzgo test -v <pkg>'.
func VerifyCorpus(function Func, workDir string, nonPkgArgs []string) error {

	corpusDir := filepath.Join(workDir, "corpus")
	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		// No corpus to validate.
		// TODO: a future real 'go test' invocation should be silent in this case,
		// given the proposed intent is to always check for a corpus for normal 'go test' invocations.
		// However, maybe fzgo should warn? or warn if -v is passed? or always be silent?
		return nil
	}

	// create temp dir to work in
	tempDir, err := ioutil.TempDir("", "fzgo-verify-corpus")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// cd to our temp dir to simplify invoking 'go test'
	oldWd, err := os.Getwd()
	if err != nil {
		return err
	}
	err = os.Chdir(tempDir)
	if err != nil {
		return err
	}
	defer func() { os.Chdir(oldWd) }()

	// write out temporary corpus_test.go file
	src := fmt.Sprintf(corpusTestSrc,
		function.PkgPath,
		corpusDir,
		function.FuncName)
	err = ioutil.WriteFile(filepath.Join(tempDir, "corpus_test.go"), []byte(src), 0700)
	if err != nil {
		return fmt.Errorf("failed to create temporary corpus_test.go: %v", err)
	}

	// actually run 'go test .' now!
	runArgs := []string{
		"test",
		buildTagsArg,
		".",
	}
	runArgs = append(runArgs, nonPkgArgs...)
	err = ExecGo(runArgs)
	if err != nil {
		// we will guess for now at least that this was due to a test failure.
		// the 'go' command should have already printed the details on the failure.
		// return a sentinel error here so that a caller can exit with non-zero exit code
		// without printing any additional error beyond what the 'go' command printed.
		return ErrGoTestFailed
	}
	return nil
}

// corpusTestTemplate provides a test function that runs
// all of the files in a corpus directory as subtests.
// This template needs three string variables to be supplied:
//   1. an import path to the fuzzer, such as:
//        github.com/dvyukov/go-fuzz-corpus/png
//   2. the directory path to the corpus, such as:
//        /tmp/gopath/src/github.com/dvyukov/go-fuzz-corpus/png/testdata/fuzz/png.Fuzz/corpus/
//   3. the fuzz function name, such as:
//        Fuzz
var corpusTestSrc = `package corpustest

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	fuzzer "%s"
)

var corpusPath = ` + "`%s`" + `

// TestCorpus executes a fuzzing function against each file in a corpus directory
// as subtests.
func TestCorpus(t *testing.T) {

	files, err := ioutil.ReadDir(corpusPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			dat, err := ioutil.ReadFile(filepath.Join(corpusPath, file.Name()))
			if err != nil {
				t.Error(err)
			}
			fuzzer.%s(dat)
		})

	}
}
`
