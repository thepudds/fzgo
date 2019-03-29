// fzgo is a simple prototype of integrating dvyukov/go-fuzz into 'go test'.
//
// See the README at https://github.com/thepudds/fzgo for more details.
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
	allowMultiFuzz := flagDebug != "nomultifuzz"
	fmt.Println("allowMultiFuzz", allowMultiFuzz)
	functions, err := fuzz.FindFunc(pkgPattern, flagFuzzFunc, allowMultiFuzz)
	if err != nil {
		fmt.Println("fzgo:", err)
		return OtherErr
	}
	if flagVerbose {
		var names []string
		for _, function := range functions {
			names = append(names, function.String())
		}
		fmt.Printf("fzgo: found functions %s\n", strings.Join(names, ", "))
	}

	// TODO: the logic in main initially was fairly simple. The logic to
	// support multiple fuzz targets should probably be pushed further out of main,
	// but wanted to some feedback first.
	var targets []fuzz.Target
	for _, function := range functions {
		// generate a hash covering the package, its dependencies, and some items like go-fuzz-build binary and go version
		h, err := fuzz.Hash(function.PkgPath, function.FuncName, flagVerbose)
		if err != nil {
			fmt.Println("fzgo:", err)
			return OtherErr
		}

		fuzzName := fmt.Sprintf("%s.%s", function.PkgName, function.FuncName)
		cacheDir := fuzz.CacheDir(h, function.PkgName, fuzzName)
		targets = append(targets, fuzz.Target{Function: function, FuzzName: fuzzName, CacheDir: cacheDir})

		// build our instrumented code, or find it already built in the fzgo cache
		err = fuzz.Instrument(cacheDir, function)
		if err != nil {
			fmt.Println("fzgo:", err)
			return OtherErr
		}
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
			// pull our last bit of info out of our arguments, then start fuzzing.
			var workDir string
			if flagFuzzDir == "" {
				workDir = filepath.Join(target.Function.PkgDir, "testdata", "fuzz", target.FuzzName)
			} else {
				workDir = filepath.Join(flagFuzzDir, target.FuzzName)
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

			err = fuzz.Start(target, workDir, fuzzDuration, parallel, funcTimeout, flagVerbose)
			if err != nil {
				fmt.Println("fzgo:", err)
				return OtherErr
			}
		}
		// run forever if flagFuzzTime was not set,
		// but otherwise break after fuzzing each target once for flagFuzzTime above.
		if !loopForever {
			break
		}
		timeQuantum *= 2
		if timeQuantum > 5*time.Minute {
			timeQuantum = 5 * time.Minute
		}
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
		fmt.Println()
	}
}
