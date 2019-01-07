package fuzz

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const zipName = "fuzz.zip"

// Instrument builds the instrumented binary and fuzz.zip if they do not already
// exist in the fzgo cache. If instead there is a cache hit, Instrument prints to stderr
// that the cached is being used.
// cacheDir is the location for the instrumented binary, and would typically be something like:
//     GOPATH/pkg/fuzz/linux_amd64/619f7d77e9cd5d7433f8/fmt.FuzzFmt
func Instrument(cacheDir string, function Func) error {
	report := func(err error) error {
		return fmt.Errorf("instrument %s.%s error: %v", function.PkgName, function.FuncName, err)
	}

	// check if go-fuzz and go-fuzz-build seem to be in our path
	err := checkGoFuzz()
	if err != nil {
		return err
	}

	if function.FuncName == "" || function.PkgDir == "" || function.PkgPath == "" {
		return report(fmt.Errorf("unexpected fuzz function: %#v", function))
	}

	// set up our cache directory if needed
	err = os.MkdirAll(cacheDir, os.ModePerm)
	if err != nil {
		return report(fmt.Errorf("cache dir failed: %v", err))
	}

	// check if our instrumented zip already exists in our cache (in which case we trust it).
	finalFile := filepath.Join(cacheDir, zipName)
	if _, err = os.Stat(finalFile); os.IsNotExist(err) {
		info("building instrumented binary for %v.%v", function.PkgName, function.FuncName)
		outFile := filepath.Join(cacheDir, "fuzz.zip.partial")
		args := []string{
			"-func=" + function.FuncName,
			"-o=" + outFile,
			buildTagsArg,
			function.PkgPath,
		}

		err = execCmd("go-fuzz-build", args, 0)
		if err != nil {
			return report(fmt.Errorf("go-fuzz-build failed with args %q: %v", args, err))
		}

		err = os.Rename(outFile, finalFile)
		if err != nil {
			return report(err)
		}
	} else {
		info("using cached instrumented binary for %v.%v", function.PkgName, function.FuncName)
	}
	return nil
}

// Start begins fuzzing by invoking 'go-fuzz'.
// cacheDir contains the instrumented binary, and would typically be something like:
//     GOPATH/pkg/fuzz/linux_amd64/619f7d77e9cd5d7433f8/fmt.FuzzFmt
// workDir contains the corpus, and would typically be something like:
//     GOPATH/src/github.com/user/proj/testdata/fuzz/fmt.FuzzFmt
func Start(cacheDir, workDir string, maxDuration time.Duration, parallel int, funcTimeout time.Duration, v bool) error {
	info("starting fuzzing")
	info("output in %s", workDir)

	// check if go-fuzz and go-fuzz-build seem to be in our path
	err := checkGoFuzz()
	if err != nil {
		return err
	}

	// prepare our args
	if funcTimeout < 1*time.Second {
		return fmt.Errorf("minimum allowed func timeout value is 1 second")
	}
	verboseLevel := 0
	if v {
		verboseLevel = 1
	}

	runArgs := []string{
		fmt.Sprintf("-bin=%s", filepath.Join(cacheDir, zipName)),
		fmt.Sprintf("-workdir=%s", workDir),
		fmt.Sprintf("-procs=%d", parallel),
		fmt.Sprintf("-timeout=%d", int(funcTimeout.Seconds())), // this is not total run time
		fmt.Sprintf("-v=%d", verboseLevel),
	}
	return execCmd("go-fuzz", runArgs, maxDuration)
}

// ExecGo invokes the go command. The intended use case is fzgo operating in
// pass-through mode, where an invocation like 'fzgo env GOPATH'
// gets passed to the 'go' tool as 'go env GOPATH'. args typically would be
// os.Args[1:]
func ExecGo(args []string) error {
	_, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("failed to find \"go\" command in path. error: %v", err)
	}
	return execCmd("go", args, 0)
}

// A maxDuration of 0 means no max time is enforced.
func execCmd(name string, args []string, maxDuration time.Duration) error {
	report := func(err error) error { return fmt.Errorf("exec %v error: %v", name, err) }

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if maxDuration == 0 {
		// invoke cmd and let it run until it returns
		err := cmd.Run()
		if err != nil {
			return report(err)
		}
		return nil
	}

	// we have a maxDuration specified.
	// start and then manually kill cmd after maxDuration if it doesn't exit on its own.
	err := cmd.Start()
	if err != nil {
		return report(err)
	}
	timer := time.AfterFunc(maxDuration, func() {
		err := cmd.Process.Signal(os.Interrupt)
		if err != nil {
			// os.Interrupt expected to fail in some cases (e.g., not implemented on Windows)
			_ = cmd.Process.Kill()
		}
	})
	err = cmd.Wait()
	if timer.Stop() && err != nil {
		// timer.Stop() returned true, which means our kill func never ran, so return this error
		return report(err)
	}
	return nil
}

// checkGoFuzz lightly validates that dvyukov/go-fuzz seems to have been properly installed
func checkGoFuzz() error {
	for _, cmdName := range []string{"go-fuzz", "go-fuzz-build"} {
		_, err := exec.LookPath(cmdName)
		if err != nil {
			return fmt.Errorf("failed to find %q command in path. please run \"go get -u github.com/dvyukov/go-fuzz/...\" and verify your path settings. error: %v",
				cmdName, err)
		}
	}
	return nil
}

func info(s string, args ...interface{}) {
	// Related comment from https://golang.org/cmd/go/#hdr-Test_packages
	//    All test output and summary lines are printed to the go command's standard output,
	//    even if the test printed them to its own standard error.
	//    (The go command's standard error is reserved for printing errors building the tests.)
	fmt.Println("fzgo:", fmt.Sprintf(s, args...))
}
