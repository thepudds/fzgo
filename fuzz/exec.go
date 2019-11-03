package fuzz

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Instrument builds the instrumented binary and fuzz.zip if they do not already
// exist in the fzgo cache. If instead there is a cache hit, Instrument prints to stderr
// that the cached is being used.
// cacheDir is the location for the instrumented binary, and would typically be something like:
//     GOPATH/pkg/fuzz/linux_amd64/619f7d77e9cd5d7433f8/fmt.FuzzFmt
func Instrument(function Func, verbose bool) (Target, error) {
	report := func(err error) (Target, error) {
		return Target{}, fmt.Errorf("instrument %s.%s error: %v", function.PkgName, function.FuncName, err)
	}

	// check if go-fuzz and go-fuzz-build seem to be in our path
	err := checkGoFuzz()
	if err != nil {
		return report(err)
	}

	if function.FuncName == "" || function.PkgDir == "" || function.PkgPath == "" {
		return report(fmt.Errorf("unexpected fuzz function: %#v", function))
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
		// When fuzzing, we do not want to print our arguments.
		printArgs := false
		target, err = CreateRichSigWrapper(function, printArgs)
		if err != nil {
			return report(err)
		}
		// CreateRichSigWrapper was successful, which means it populated the temp dir with the wrapper func.
		// By the time we leave our current function, we are done with the temp dir
		// that CreateRichSigWrapper created, so delete via a defer.
		// (We can't delete it immediately because we haven't yet run go-fuzz-build on it).
		defer os.RemoveAll(target.wrapperTempDir)
	}

	// Determine where our cacheDir is.
	// This includes calculating a hash covering the package, its dependencies, and some other items.
	cacheDir, err := target.cacheDir(verbose)
	if err != nil {
		return report(fmt.Errorf("getting cache dir failed: %v", err))
	}

	// set up our cache directory if needed
	err = os.MkdirAll(cacheDir, os.ModePerm)
	if err != nil {
		return report(fmt.Errorf("creating cache dir failed: %v", err))
	}

	// check if our instrumented zip already exists in our cache (in which case we trust it).
	finalZipPath, err := target.zipPath(verbose)
	if err != nil {
		return report(fmt.Errorf("zip path failed: %v", err))
	}
	if _, err = os.Stat(finalZipPath); os.IsNotExist(err) {
		// TODO: resume here ###########################################################################
		// clean up the functions running around. switch to target.
		// also, delete the temp dir. probably with a defer just after target returns successfully
		info("building instrumented binary for %v.%v", function.PkgName, function.FuncName)
		outFile := filepath.Join(cacheDir, "fuzz.zip.partial")
		var args []string
		if !target.hasWrapper {
			args = []string{
				"-func=" + target.UserFunc.FuncName,
				"-o=" + outFile,
				// "-race", // TODO: make a flag
				buildTagsArg,
				target.UserFunc.PkgPath,
			}
		} else {
			args = []string{
				"-func=" + target.wrapperFunc.FuncName,
				"-o=" + outFile,
				// "-race", // TODO: make a flag
				buildTagsArg,
				target.wrapperFunc.PkgPath,
			}
		}

		err = execCmd("go-fuzz-build", args, target.wrapperEnv, 0)
		if err != nil {
			return report(fmt.Errorf("go-fuzz-build failed with args %q: %v", args, err))
		}

		err = os.Rename(outFile, finalZipPath)
		if err != nil {
			return report(err)
		}
	} else {
		info("using cached instrumented binary for %v.%v", function.PkgName, function.FuncName)
	}
	return target, nil
}

// Start begins fuzzing by invoking 'go-fuzz'.
// cacheDir contains the instrumented binary, and would typically be something like:
//     GOPATH/pkg/fuzz/linux_amd64/619f7d77e9cd5d7433f8/fmt.FuzzFmt
// workDir contains the corpus, and would typically be something like:
//     GOPATH/src/github.com/user/proj/testdata/fuzz/fmt.FuzzFmt
func Start(target Target, workDir string, maxDuration time.Duration, parallel int, funcTimeout time.Duration, v bool) error {
	report := func(err error) error {
		return fmt.Errorf("start fuzzing %s error: %v", target.FuzzName(), err)
	}

	info("starting fuzzing %s", target.FuzzName())
	info("output in %s", workDir)

	// check if go-fuzz and go-fuzz-build seem to be in our path
	err := checkGoFuzz()
	if err != nil {
		return report(err)
	}

	// prepare our args
	if funcTimeout < 1*time.Second {
		return fmt.Errorf("minimum allowed func timeout value is 1 second")
	}
	verboseLevel := 0
	if v {
		verboseLevel = 1
	}

	zipPath, err := target.zipPath(v)
	if err != nil {
		return report(fmt.Errorf("zip path failed: %v", err))
	}

	runArgs := []string{
		fmt.Sprintf("-bin=%s", zipPath),
		fmt.Sprintf("-workdir=%s", workDir),
		fmt.Sprintf("-procs=%d", parallel),
		fmt.Sprintf("-timeout=%d", int(funcTimeout.Seconds())), // this is not total run time
		fmt.Sprintf("-v=%d", verboseLevel),
	}
	err = execCmd("go-fuzz", runArgs, nil, maxDuration)
	if err != nil {
		return report(err)
	}
	return nil
}

// Target tracks some metadata about each fuzz target, and is responsible
// for tracking a fuzz.Func found via go/packages and making it useful
// as a fuzz target, including determining where to cache the fuzz.zip
// and what the target's fuzzName should be.
type Target struct {
	UserFunc      Func   // the user's original function
	savedCacheDir string // the cacheDir relies on a content hash, so remember the answer

	hasWrapper     bool
	wrapperFunc    Func     // synthesized wrapper function, only used if user's func has rich signatures
	wrapperEnv     []string // env with GOPATH set up to include the temporary
	wrapperTempDir string
}

// FuzzName returns the '<pkg>.<OrigFuzzFunc>' string.
// For example, it might be 'fmt.FuzzFmt'. This is used
// in messages, as well it is part of the path when creating
// the corpus location under testdata.
func (t *Target) FuzzName() string {
	return t.UserFunc.FuzzName()
}

func (t *Target) zipPath(verbose bool) (string, error) {
	cacheDir, err := t.cacheDir(verbose)
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "fuzz.zip"), nil
}

func (t *Target) cacheDir(verbose bool) (string, error) {
	if t.savedCacheDir == "" {
		// generate a hash covering the package, its dependencies, and some items like go-fuzz-build binary and go version
		// TODO: pass verbose flag around?
		var err error
		var h string
		if !t.hasWrapper {
			// use everything directly from the original user function
			h, err = Hash(t.UserFunc.PkgPath, t.UserFunc.FuncName, t.UserFunc.PkgDir, nil, verbose)
		} else {
			// we have a wrapper function, so target that for our hash.
			h, err = Hash(t.wrapperFunc.PkgPath, t.wrapperFunc.FuncName, t.wrapperFunc.PkgDir, t.wrapperEnv, verbose)
		}
		if err != nil {
			return "", err
		}
		// the user facing location on disk is the friendly name (that is, from the original user function)
		t.savedCacheDir = CacheDir(h, t.UserFunc.PkgName, t.FuzzName())
	}

	return t.savedCacheDir, nil
}

// ExecGo invokes the go command. The intended use case is fzgo operating in
// pass-through mode, where an invocation like 'fzgo env GOPATH'
// gets passed to the 'go' tool as 'go env GOPATH'. args typically would be
// os.Args[1:]
func ExecGo(args []string, env []string) error {
	if len(env) == 0 {
		env = os.Environ()
	}

	_, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("failed to find \"go\" command in path. error: %v", err)
	}
	return execCmd("go", args, env, 0)
}

// A maxDuration of 0 means no max time is enforced.
func execCmd(name string, args []string, env []string, maxDuration time.Duration) error {
	report := func(err error) error { return fmt.Errorf("exec %v error: %v", name, err) }

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if len(env) > 0 {
		cmd.Env = env
	}

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

// checkGoFuzz lightly validates that dvyukov/go-fuzz seems to have been properly installed.
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


