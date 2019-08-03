// fzgo is a simple prototype of integrating dvyukov/go-fuzz into 'go test'.
//
// See the README at https://github.com/thepudds/fzgo for more details.
//
// There are three main directories used:
// 1. cacheDir is the location for the instrumented binary, and would typically be something like:
//      GOPATH/pkg/fuzz/linux_amd64/619f7d77e9cd5d7433f8/fmt.FuzzFmt
// 2. fuzzDir is the directory supplied via the -fuzzdir argument, and contains the workDir.
// 3. workDir is passed to go-fuzz-build and go-fuzz as the -workdir argument.
//      if -fuzzdir is not specified:  workDir is GOPATH/pkg/fuzz/corpus/<import-path>/<func>
//      if -fuzzdir is '/some/path':   workDir is /some/path/<import-path>/<func>
//      if -fuzzdir is 'testdata':     workDir is <pkg-dir>/testdata/fuzz/<func>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thepudds/fzgo/fuzz"
)

var (
	flagCompile  bool
	flagFuzzFunc string
	flagFuzzDir  string
	flagFuzzTime time.Duration
	flagParallel int
	flagTimeout  time.Duration
	flagVerbose  bool
	flagDebug    string
)

var flagDefs = []fuzz.FlagDef{
	{Name: "fuzz", Ptr: &flagFuzzFunc, Description: "fuzz at most one function matching `regexp`"},
	{Name: "fuzzdir", Ptr: &flagFuzzDir, Description: "store fuzz artifacts in `dir` (default pkgpath/testdata/fuzz)"},
	{Name: "fuzztime", Ptr: &flagFuzzTime, Description: "fuzz for duration `d` (default unlimited)"},
	{Name: "parallel", Ptr: &flagParallel, Description: "start `n` fuzzing operations (default GOMAXPROCS)"},
	{Name: "timeout", Ptr: &flagTimeout, Description: "fail an individual call to a fuzz function after duration `d` (default 10s, minimum 1s)"},
	{Name: "c", Ptr: &flagCompile, Description: "compile the instrumented code but do not run it"},
	{Name: "v", Ptr: &flagVerbose, Description: "verbose: print additional output"},
	{Name: "debug", Ptr: &flagDebug, Description: "comma separated list of debug options; currently only supports 'nomultifuzz'"},
}

// constants for status codes for os.Exit()
const (
	Success  = 0
	OtherErr = 1
	ArgErr   = 2
)

func main() {
	os.Exit(fzgoMain())
}

// fzgoMain implements main(), returning a status code usable by os.Exit() and the testscripts package.
// Success is status code 0.
func fzgoMain() int {

	// register our flags
	fs, err := fuzz.FlagSet("fzgo test -fuzz", flagDefs, usage)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}

	// print our fzgo-specific help for variations like 'fzgo', 'fzgo help', 'fzgo -h', 'fzgo --help', 'fzgo help foo'
	if len(os.Args) < 2 || os.Args[1] == "help" {
		fs.Usage()
		return ArgErr
	}
	if _, _, ok := fuzz.FindFlag(os.Args[1:2], []string{"h", "help"}); ok {
		fs.Usage()
		return ArgErr
	}

	if os.Args[1] != "test" {
		// pass through to 'go' command
		err = fuzz.ExecGo(os.Args[1:], nil)
		if err != nil {
			// ExecGo prints error if 'go' tool is not in path.
			// Other than that, we currently rely on the 'go' tool to print any errors itself.
			return OtherErr
		}
		return Success
	}

	// 'test' command is specified.
	// check to see if we have a -fuzz flag, and if so, parse the args we will interpret.
	pkgPattern, err := fuzz.ParseArgs(os.Args[2:], fs)
	if err == flag.ErrHelp {
		// if we get here, we already printed usage.
		return ArgErr
	} else if err != nil {
		fmt.Println("fzgo:", err)
		return ArgErr
	}

	if flagFuzzFunc == "" {
		// 'fzgo test', but no '-fuzz'. We have not been asked to generate new fuzz-based inputs.
		// instead, we do two things:
		// 1. we deterministically validate our corpus (if any),
		status := verifyCorpus(os.Args)
		if status != Success {
			return status
		}
		// 2. pass our arguments through to the normal 'go' command, which will run normal 'go test'.
		err = fuzz.ExecGo(os.Args[1:], nil)
		if err != nil {
			return OtherErr
		}
		return Success
	}

	// we now know we have been asked to do fuzzing.
	// gather the basic fuzzing settings from our flags.
	allowMultiFuzz := flagDebug != "nomultifuzz"
	parallel := flagParallel
	if parallel == 0 {
		parallel = runtime.GOMAXPROCS(0)
	}
	funcTimeout := flagTimeout
	if funcTimeout == 0 {
		funcTimeout = 10 * time.Second
	} else if funcTimeout < 1*time.Second {
		fmt.Printf("fzgo: fuzz function timeout value %s in -timeout flag is less than minimum of 1 second\n", funcTimeout)
		return ArgErr
	}

	// look for the functions we have been asked to fuzz.
	functions, err := fuzz.FindFunc(pkgPattern, flagFuzzFunc, nil, allowMultiFuzz)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	} else if len(functions) == 0 {
		fmt.Printf("fzgo: failed to find fuzz function for pattern %v and func %v\n", pkgPattern, flagFuzzFunc)
		return OtherErr
	}
	if flagVerbose {
		var names []string
		for _, function := range functions {
			names = append(names, function.String())
		}
		fmt.Printf("fzgo: found functions %s\n", strings.Join(names, ", "))
	}

	// build our instrumented code, or find if is is already built in the fzgo cache
	var targets []fuzz.Target
	for _, function := range functions {
		target, err := fuzz.Instrument(function, flagVerbose)
		if err != nil {
			fmt.Println("fzgo:", err)
			return OtherErr
		}
		targets = append(targets, target)
	}

	if flagCompile {
		fmt.Println("fzgo: finished instrumenting binaries")
		return Success
	}

	// run forever if flagFuzzTime was not set (that is, has default value of 0).
	loopForever := flagFuzzTime == 0
	timeQuantum := 5 * time.Second
	for {
		for _, target := range targets {
			// pull our last bit of info out of our arguments.
			workDir := determineWorkDir(target.UserFunc, flagFuzzDir)

			// seed our workDir with any other corpus that might exist from other known locations.
			// see comment for copyCachedCorpus for discussion of current behavior vs. desired behavior.
			if err = copyCachedCorpus(target.UserFunc, workDir); err != nil {
				fmt.Println("fzgo:", err)
				return OtherErr
			}

			// determine how long we will execute this particular fuzz invocation.
			var fuzzDuration time.Duration
			if !loopForever {
				fuzzDuration = flagFuzzTime
			} else {
				if len(targets) > 1 {
					fuzzDuration = timeQuantum
				} else {
					fuzzDuration = 0 // unlimited
				}
			}

			// fuzz!
			err = fuzz.Start(target, workDir, fuzzDuration, parallel, funcTimeout, flagVerbose)
			if err != nil {
				fmt.Println("fzgo:", err)
				return OtherErr
			}
			fmt.Println() // blank separator line at end of one target's fuzz run.
		}
		// run forever if flagFuzzTime was not set,
		// but otherwise break after fuzzing each target once for flagFuzzTime above.
		if !loopForever {
			break
		}
		timeQuantum *= 2
		if timeQuantum > 10*time.Minute {
			timeQuantum = 10 * time.Minute
		}

	}
	return Success
}

// verifyCorpus validates our corpus by executing any fuzz functions in our package pattern
// against any files in the corresponding corpus. This is an automatic form of regression test.
// args is os.Args
func verifyCorpus(args []string) int {
	// we do this by first searching for any fuzz func ("." regexp) in our package pattern.
	// TODO: move this elsewhere? Taken from fuzz.ParseArgs, but we can't use fuzz.ParseArgs as is.
	testPkgPatterns, nonPkgArgs, err := fuzz.FindPkgs(args[2:])
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}
	var testPkgPattern string
	if len(testPkgPatterns) > 1 {
		fmt.Printf("fzgo: more than one package pattern not allowed: %q", testPkgPatterns)
		return ArgErr
	} else if len(testPkgPatterns) == 0 {
		testPkgPattern = "."
	} else {
		testPkgPattern = testPkgPatterns[0]
	}

	functions, err := fuzz.FindFunc(testPkgPattern, ".", nil, true)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}
	// TODO: should we get -v? E.g., something like:
	// _, verbose := fuzz.FindTestFlag(os.Args[2:], []string{"v"})

	status := Success
	for _, function := range functions {

		// work through how many places we need to check based on
		// what the user specified in flagFuzzDir.
		var dirsToCheck []string

		// we always check the "testdata" dir if it exists.
		testdataWorkDir := determineWorkDir(function, "testdata")
		dirsToCheck = append(dirsToCheck, testdataWorkDir)

		// we also always check under  GOPATH/pkg/fuzz/corpus/... if it exists.
		gopathPkgWorkDir := determineWorkDir(function, "")
		dirsToCheck = append(dirsToCheck, gopathPkgWorkDir)

		// see if we need to check elsewhere as well.
		if flagFuzzDir == "" {
			// nothing else to do; the user did not specify a dir.
		} else if flagFuzzDir == "testdata" {
			// nothing else to do; we already added testdata dir.
		} else {
			// the user supplied a destination
			userWorkDir := determineWorkDir(function, flagFuzzDir)
			dirsToCheck = append(dirsToCheck, userWorkDir)
		}

		// we have 2 or 3 places to check
		for _, workDir := range dirsToCheck {
			if !fuzz.PathExists(workDir) {
				// this workDir does not exist, so skip
				continue
			}

			err := fuzz.VerifyCorpus(function, workDir, nonPkgArgs)
			if err == fuzz.ErrGoTestFailed {
				// 'go test' itself should have printed an informative error,
				// so here we just set a non-zero status code and continue.
				status = OtherErr
			} else if err != nil {
				fmt.Println("fzgo:", err)
				return OtherErr
			}
		}
	}

	return status
}

// determineWorkDir translates from the user's specified -fuzzdir to an actual
// location on disk, including the default location if the user does not specify a -fuzzdir.
func determineWorkDir(function fuzz.Func, requestedFuzzDir string) string {
	var workDir string
	importPathDirs := filepath.FromSlash(function.PkgPath) // convert import path into filepath
	if requestedFuzzDir == "" {
		// default to GOPATH/pkg/fuzz/corpus/import/path/<func>
		gp := fuzz.Gopath()
		workDir = filepath.Join(gp, "pkg", "fuzz", "corpus", importPathDirs, function.FuncName)
	} else if requestedFuzzDir == "testdata" {
		// place under the package of interest in the testdata directory.
		workDir = filepath.Join(function.PkgDir, "testdata", "fuzz", function.FuncName)
	} else {
		// requestedFuzzDir was specified to be an actual directory.
		// still use the import path to handle fuzzing multiple functions across multiple packages.
		workDir = filepath.Join(requestedFuzzDir, importPathDirs, function.FuncName)
	}
	return workDir
}

// copyCachedCorpus desired bheavior (or at least proposed-by-me behavior):
//     1. if destination corpus location doesn't exist, seed it from GOPATH/pkg/fuzz/corpus/import/path/<fuzzfunc>
//     2. related: fuzz while reading from all known locations that exist (e.g,. testdata if it exists, GOPATH/pkg/fuzz/corpus/...)
//
// However, 2. is not possible currently to do directly with dvyukov/go-fuzz for more than 1 corpus.
//
// Therefore, the current behavior of copyCachedCorpus approximates 1. and 2. like so:
//     1'. always copy all known corpus entries to the destination corpus location in all cases.
//
// Also, that current behavior could be reasonable for the proposed behavior in the sense that it is simple.
// Filenames that already exist in the destination are not updated.
// TODO: it is debatable if it should copy crashers and suppressions as well.
// For clarity, it only copies the corpus directory itself, and not crashers and supressions.
// This avoids making sometone think they have a new crasher after copying a crasher to a new location, for example,
// especially at this current prototype phase where the crasher reporting in
// go-fuzz does not know anything about multi-corpus locations.
func copyCachedCorpus(function fuzz.Func, dstWorkDir string) error {
	dstCorpusDir := filepath.Join(dstWorkDir, "corpus")

	gopathPkgWorkDir := determineWorkDir(function, "")
	testdataWorkDir := determineWorkDir(function, "testdata")

	for _, srcWorkDir := range []string{gopathPkgWorkDir, testdataWorkDir} {
		srcCorpusDir := filepath.Join(srcWorkDir, "corpus")
		if srcCorpusDir == dstCorpusDir {
			// nothing to do
			continue
		}
		if fuzz.PathExists(srcCorpusDir) {
			// copyDir will create dstDir if needed, and won't overwrite files
			// in dstDir that already exist.
			if err := fuzz.CopyDir(dstCorpusDir, srcCorpusDir); err != nil {
				return fmt.Errorf("failed seeding destination corpus: %v", err)
			}
		}
	}
	return nil
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Printf("\nfzgo is a simple prototype of integrating dvyukov/go-fuzz into 'go test'.\n\n")
		fmt.Printf("fzgo supports typical go commands such as 'fzgo build', 'fgzo test', or 'fzgo env', and also supports\n")
		fmt.Printf("the '-fuzz' flag and several other related flags proposed in https://golang.org/issue/19109.\n\n")
		fmt.Printf("Instrumented binaries are automatically cached in GOPATH/pkg/fuzz.\n\n")
		fmt.Printf("Sample usage:\n\n")
		fmt.Printf("   fzgo test                           # test the current package\n")
		fmt.Printf("   fzgo test -fuzz .                   # fuzz the current package with a function starting with 'Fuzz'\n")
		fmt.Printf("   fzgo test -fuzz FuzzFoo             # fuzz the current package with a function matching 'FuzzFoo'\n")
		fmt.Printf("   fzgo test ./... -fuzz FuzzFoo       # fuzz a package in ./... with a function matching 'FuzzFoo'\n")
		fmt.Printf("   fzgo test sample/pkg -fuzz FuzzFoo  # fuzz 'sample/pkg' with a function matching 'FuzzFoo'\n\n")
		fmt.Printf("The following flags work with 'fzgo test -fuzz':\n\n")

		for _, d := range flagDefs {
			f := fs.Lookup(d.Name)
			argname, usage := flag.UnquoteUsage(f)
			fmt.Printf("   -%s %s\n       %s\n", f.Name, argname, usage)
		}
		fmt.Println()
	}
}
