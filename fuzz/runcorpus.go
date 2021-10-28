package fuzz

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
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
func VerifyCorpus(function Func, workDir string, run string, verbose bool) error {
	corpusDir := filepath.Join(workDir, "corpus")
	return verifyFiles(function, corpusDir, run, "TestCorpus", verbose)
}

// VerifyCrashers is similar to VerifyCorpus, but runs the crashers. It
// can be useful to pass -v to what is causing a crash, such as 'fzgo test -v -fuzz=. -run=TestCrashers'
func VerifyCrashers(function Func, workDir string, run string, verbose bool) error {
	crashersDir := filepath.Join(workDir, "crashers")
	return verifyFiles(function, crashersDir, run, "TestCrashers", verbose)
}

// verifyFiles implements the heart of VerifyCorpus and VerifyCrashers
func verifyFiles(function Func, filesDir string, run string, testFunc string, verbose bool) error {
	report := func(err error) error {
		if err == ErrGoTestFailed {
			return err
		}
		return fmt.Errorf("verify corpus for %s: %v", function.FuzzName(), err)
	}

	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		// No corpus to validate.
		// TODO: a future real 'go test' invocation should be silent in this case,
		// given the proposed intent is to always check for a corpus for normal 'go test' invocations.
		// However, maybe fzgo should warn? or warn if -v is passed? or always be silent?
		// Right now, main.go is making the decision to skip calling VerifyCorpus if workDir is not found.
		return nil
	}

	// Check if we have a regex match for -run regexp for this testFunc
	// TODO: add test for TestCorpus/fced9f7db3881a5250d7e287ab8c33f2952f0e99-8
	//    cd fzgo/examples
	//    fzgo test -fuzz=FuzzWithBasicTypes -run=TestCorpus/fced9f7db3881a5250d7e287ab8c33f2952f0e99-8 ./...  -v
	// Doesn't print anything?
	if run == "" {
		report(fmt.Errorf("invalid empty run argument"))
	}
	runFields := strings.SplitN(run, "/", 2)
	re1 := runFields[0]
	ok, err := regexp.MatchString(re1, testFunc)
	if err != nil {
		report(fmt.Errorf("invalid regexp %q for -run: %v", run, err))
	}
	if !ok {
		// Nothing to do. Return now to avoid 'go test' saying nothing to do.
		return nil
	}

	// Do a light test to see if there are any files in the filesDir.
	// This avoids 'go test' from reporting 'no tests' (and does not need to be perfect check).
	re2 := "."
	matchedFile := false
	if len(runFields) > 1 {
		re2 = runFields[1]
	}
	entries, err := ioutil.ReadDir(filesDir)
	if err != nil {
		report(err)
	}
	for i := range entries {
		ok, err := regexp.MatchString(re2, entries[i].Name())
		if err != nil {
			report(fmt.Errorf("invalid regexp %q for -run: %v", run, err))
		}
		if ok {
			matchedFile = true
			break
		}
	}
	if !matchedFile {
		return nil
	}

	// check if we have a plain data []byte signature, vs. a rich signature
	plain, err := IsPlainSig(function.TypesFunc)
	if err != nil {
		return report(err)
	}

	var target Target
	if plain {
		// create our initial target struct using the actual func supplied by the user.
		target = Target{UserFunc: function}
	} else {
		info("detected rich signature for %v.%v", function.PkgName, function.FuncName)
		// create a wrapper function to handle the rich signature.
		// if both -v and -run is set (presumaly to some corpus file),
		// as a convinience also print the deserialized arguments
		printArgs := verbose && run != ""

		target, err = CreateRichSigWrapper(function, printArgs)
		if err != nil {
			return report(err)
		}
		// CreateRichSigWrapper was successful, which means it populated the temp dir with the wrapper func.
		// By the time we leave our current function, we are done with the temp dir
		// that CreateRichSigWrapper created, so delete via a defer.
		// (We can't delete it immediately because we haven't yet run go-fuzz-build on it).
		defer os.RemoveAll(target.wrapperTempDir)

		// TODO: consider moving gopath setup into richsig, store on Target
		// also set up a second entry in GOPATH to include our temporary directory containing the rich sig wrapper.
	}

	// create temp dir to work in.
	// this is where we will create a corpus test wrapper suitable for running a normal 'go test'.
	tempDir, err := ioutil.TempDir("", "fzgo-verify-corpus")
	if err != nil {
		return report(fmt.Errorf("failed to create temp dir: %v", err))
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

	var pkgPath, funcName string
	var env []string
	if target.hasWrapper {
		pkgPath = target.wrapperFunc.PkgPath
		funcName = target.wrapperFunc.FuncName
		env = target.wrapperEnv
	} else {
		pkgPath = target.UserFunc.PkgPath
		funcName = target.UserFunc.FuncName
		env = nil
	}

	// write out temporary corpus_test.go file
	vals := map[string]string{"pkgPath": pkgPath, "filesDir": filesDir, "testFunc": testFunc, "funcName": funcName}
	buf := new(bytes.Buffer)
	if err := corpusTestSrc.Execute(buf, vals); err != nil {
		report(fmt.Errorf("could not execute template: %v", err))
	}
	// return buf.Bytes()
	// src := fmt.Sprintf(corpusTestSrc,
	// 	pkgPath,
	// 	filesDir,
	// 	testFunc,
	// 	testFunc,
	// 	funcName)
	// err = ioutil.WriteFile(filepath.Join(tempDir, "corpus_test.go"), []byte(src), 0700)
	err = ioutil.WriteFile(filepath.Join(tempDir, "corpus_test.go"), buf.Bytes(), 0700)
	if err != nil {
		return report(fmt.Errorf("failed to create temporary corpus_test.go: %v", err))
	}

	// actually run 'go test .' now!
	runArgs := []string{
		"test",
		buildTagsArg,
		".",
	}
	// formerly, we passed through nonPkgArgs here from fzgo flag parsing.
	// now, we choose which flags explicitly to pass on (currently -run and -v).
	// we could return to passing through everything, but would need to strip things like -fuzzdir
	// that 'go test' does not understand.
	if run != "" {
		runArgs = append(runArgs, fmt.Sprintf("-run=%s", run))
	}
	if verbose {
		runArgs = append(runArgs, "-v")
	}

	err = ExecGo(runArgs, env)
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
var corpusTestSrc = template.Must(template.New("CorpusTest").Parse(`
package corpustest

import (
	"io/ioutil"
	"path/filepath"
	{{if eq .testFunc "TestCrashers"}}
	"strings"
	{{end}}
	"testing"

	fuzzer "{{.pkgPath}}"
)

var corpusPath = ` + "`{{.filesDir}}`" + `

// %s executes a fuzzing function against each file in a corpus directory
// as subtests.
func {{.testFunc}}(t *testing.T) {

	files, err := ioutil.ReadDir(corpusPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		{{if eq .testFunc "TestCrashers"}}
		// exclude auxillary files that reside in the crashers directory.
		if strings.HasSuffix(file.Name(), ".output") || strings.HasSuffix(file.Name(), ".quoted") {
			continue
		}
		{{end}}

		t.Run(file.Name(), func(t *testing.T) {
			dat, err := ioutil.ReadFile(filepath.Join(corpusPath, file.Name()))
			if err != nil {
				t.Error(err)
			}
			fuzzer.{{.funcName}}(dat)
		})

	}
}
`))
