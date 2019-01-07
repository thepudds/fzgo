// fzgo is a simple prototype of integrating dvyukov/go-fuzz into 'go test'.
//
// See the README at https://github.com/thepudds/fzgo for more details.
package main

// sample invocation:
//   fzgo test github.com/thepudds/fzgo/examples/... -fuzz FuzzEmpty -fuzztime 10s

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
)

var flagDefs = []fuzz.FlagDef{
	{Name: "fuzz", Ptr: &flagFuzzFunc, Description: "fuzz at most one function matching `regexp`"},
	{Name: "fuzzdir", Ptr: &flagFuzzDir, Description: "store fuzz artifacts in `dir` (default pkgpath/testdata/fuzz)"},
	{Name: "fuzztime", Ptr: &flagFuzzTime, Description: "fuzz for duration `d` (default unlimited)"},
	{Name: "parallel", Ptr: &flagParallel, Description: "start `n` fuzzing operations (default GOMAXPROCS)"},
	{Name: "timeout", Ptr: &flagTimeout, Description: "fail an individual call to a fuzz function after duration `d` (default 10s, minimum 1s)"},
	{Name: "c", Ptr: &flagCompile, Description: "compile the instrumented code but do not run it"},
	{Name: "v", Ptr: &flagVerbose, Description: "verbose: print additional output"},
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
	if _, ok := fuzz.FindFlag(os.Args[1:2], []string{"h", "help"}); ok {
		fs.Usage()
		return ArgErr
	}

	if os.Args[1] != "test" {
		// pass through to 'go' command
		err := fuzz.ExecGo(os.Args[1:])
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
		// 'fzgo test', but no '-fuzz'. Pass through to 'go' command
		err := fuzz.ExecGo(os.Args[1:])
		if err != nil {
			return OtherErr
		}
		return Success
	}

	// we now know we have been asked to do fuzzing.
	function, err := fuzz.FindFunc(pkgPattern, flagFuzzFunc)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}
	if flagVerbose {
		fmt.Printf("fzgo: found function %s.%s\n", function.PkgName, function.FuncName)
	}

	// generate a hash covering the package, its dependencies, and some items like go-fuzz-build binary and go version
	h, err := fuzz.Hash(function.PkgPath, function.FuncName, flagVerbose)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}

	fuzzName := fmt.Sprintf("%s.%s", function.PkgName, function.FuncName)
	cacheDir := fuzz.CacheDir(h, function.PkgName, fuzzName)

	// build our instrumented code, or find it already built in the fzgo cache
	err = fuzz.Instrument(cacheDir, function)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}

	if flagCompile {
		fmt.Println("fzgo: instrumented binary in", cacheDir)
		return Success
	}

	// finalize our arguments, then start fuzzing.
	var workDir string
	if flagFuzzDir == "" {
		workDir = filepath.Join(function.PkgDir, "testdata", "fuzz", fuzzName)
	} else {
		workDir = filepath.Join(flagFuzzDir, fuzzName)
	}
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

	err = fuzz.Start(cacheDir, workDir, flagFuzzTime, parallel, funcTimeout, flagVerbose)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}

	return Success
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
	}
}
