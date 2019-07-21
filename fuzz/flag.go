// Package fuzz defines the API used by fzgo (a simple prototype of integrating dvyukov/go-fuzz into 'go test').
//
// See the README at https://github.com/thepudds/fzgo for more details.
package fuzz

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

// UnimplementedBuildFlags is a list of 'go test' build flags that are not implemented
// in this simple 'fzgo' prototype; these will cause an error if used with 'fzgo test -fuzz'.
// (If 'test -fuzz' is not specified, 'fzgo' will pass any of these arguments through to the actual 'go' tool).
var UnimplementedBuildFlags = []string{
	"a",             // -a  (force rebuilding of packages that are already up-to-date.)
	"asmflags",      // -asmflags '[pattern=]arg list'  (arguments to pass on each go tool asm invocation.)
	"buildmode",     // -buildmode mode  (build mode to use. See 'go help buildmode' for more.)
	"compiler",      // -compiler name  (name of compiler to use, as in runtime.Compiler (gccgo or gc).)
	"gccgoflags",    // -gccgoflags '[pattern=]arg list'  (arguments to pass on each gccgo compiler/linker invocation.)
	"gcflags",       // -gcflags '[pattern=]arg list'  (arguments to pass on each go tool compile invocation.)
	"installsuffix", // -installsuffix suffix  (a suffix to use in the name of the package installation directory,...)
	"ldflags",       // -ldflags '[pattern=]arg list'  (arguments to pass on each go tool link invocation.)
	"linkshared",    // -linkshared  (link against shared libraries previously created with...)
	"mod",           // -mod mode  (module download mode to use: readonly or vendor.)
	"msan",          // -msan  (enable interoperation with memory sanitizer.)
	"n",             // -n  (print the commands but do not run them.)
	"p",             // -p n  (the number of programs, such as build commands or...)
	"pkgdir",        // -pkgdir dir  (install and load all packages from dir instead of the usual locations.)
	"race",          // -race  (enable data race detection.)
	"tags",          // -tags 'tag list'  (a space-separated list of build tags to consider satisfied during the...)
	"toolexec",      // -toolexec 'cmd args'  (a program to use to invoke toolchain programs like vet and asm.)
	"work",          // -work  (print the name of the temporary work directory and...)
	"x",             // -x  (print the commands.)
}

// IncompatibleTestFlags is a list of 'go test' flags that might be
// incompatible with a final 'go test -fuzz' based on the March 2017 proposal document.
// These currently cause an error if 'fzgo test -fuzz' is also specified.
// This list likely would change based on more discussion of the proposal.
var IncompatibleTestFlags = []string{
	"args",                 // -args  (Pass the remainder of the command line (everything after -args)...)
	"bench",                // -bench regexp  (Run only those benchmarks matching a regular expression.)
	"benchmem",             // -benchmem  (Print memory allocation statistics for benchmarks.)
	"benchtime",            // -benchtime t  (Run enough iterations of each benchmark to take t, specified...)
	"blockprofile",         // -blockprofile block.out  (Write a goroutine blocking profile to the specified file...)
	"blockprofilerate",     // -blockprofilerate n  (Control the detail provided in goroutine blocking profiles by...)
	"count",                // -count n  (Run each test and benchmark n times (default 1).)
	"cover",                // -cover  (Enable coverage analysis.)
	"covermode",            // -covermode set,count,atomic  (Set the mode for coverage analysis for the package[s]...)
	"coverpkg",             // -coverpkg pattern1,pattern2,pattern3  (Apply coverage analysis in each test to packages matching the patterns.)
	"cpu",                  // -cpu 1,2,4  (Specify a list of GOMAXPROCS values for which the tests or...)
	"cpuprofile",           // -cpuprofile cpu.out  (Write a CPU profile to the specified file before exiting.)
	"exec",                 // -exec xprog  (Run the test binary using xprog. The behavior is the same as...)
	"failfast",             // -failfast  (Do not start new tests after the first test failure.)
	"json",                 // -json  (Convert test output to JSON suitable for automated processing.)
	"list",                 // -list regexp  (List tests, benchmarks, or examples matching the regular expression.)
	"memprofile",           // -memprofile mem.out  (Write an allocation profile to the file after all tests have passed.)
	"memprofilerate",       // -memprofilerate n  (Enable more precise (and expensive) memory allocation profiles by...)
	"mutexprofile",         // -mutexprofile mutex.out  (Write a mutex contention profile to the specified file...)
	"mutexprofilefraction", // -mutexprofilefraction n  (Sample 1 in n stack traces of goroutines holding a...)
	"o",                    // -o file  (Compile the test binary to the named file.)
	"outputdir",            // -outputdir directory  (Place output files from profiling in the specified directory,...)
	"run",                  // -run regexp  (Run only those tests and examples matching the regular expression.)
	"short",                // -short  (Tell long-running tests to shorten their run time.)
	"trace",                // -trace trace.out  (Write an execution trace to the specified file before exiting.)
	"vet",                  // -vet list  (Configure the invocation of "go vet" during "go test"...)
}

// UnimplementedTestFlags is a list of 'go test' flags that are expected to be
// eventually be compatible with a final 'go test -fuzz' per the March 2017 proposal document,
// but which are not currently implemented in this simple 'fzgo' prototype. These will
// currently cause an error if used with 'fzgo test -fuzz'.
var UnimplementedTestFlags = []string{
	"coverprofile", // -coverprofile cover.out  (Write a coverage profile to the file after all tests have passed.)
	"i",            // -i  (Install packages that are dependencies of the test.)
}

// supportedBools is a list of allowed boolean flags for 'fzgo test -fuzz'.
var supportedBools = []string{"c", "i", "v"}

// FlagDef holds the definition of an arg we will interpret.
type FlagDef struct {
	Name        string
	Ptr         interface{} // *string, *bool, *int, or *time.Duration
	Description string
}

// ParseArgs finds the flags we are going to interpret and sets the values in
// a flag.FlagSet. ParseArgs handles a package pattern that might appear in the middle
// of args in order to allow the flag.FlagSet.Parse() to find flags after the package pattern.
// ParseArgs also returns at most one package pattern, or "." if none was specified in args.
func ParseArgs(args []string, fs *flag.FlagSet) (string, error) {
	report := func(err error) error { return fmt.Errorf("failed parsing fuzzing flags: %v", err) }

	// first, check if we are asked to do anything fuzzing-related by
	// checking if -fuzz or -test.fuzz is present.
	_, _, ok := FindTestFlag(args, []string{"fuzz"})
	if !ok {
		// nothing else to do for any fuzz-related args parsing.
		return "", nil
	}

	// second, to make the 'fzgo' prototype a bit friendlier,
	// give more specific errors for 3 categories of illegal flags.
	if illegalFlag, _, ok := FindTestFlag(args, IncompatibleTestFlags); ok {
		return "", fmt.Errorf("test flag -%s is currently proposed to be incompatible with 'go test -fuzz'", illegalFlag)
	}
	if illegalFlag, _, ok := FindTestFlag(args, UnimplementedTestFlags); ok {
		return "", fmt.Errorf("test flag -%s is not yet implemented by fzgo prototype", illegalFlag)
	}
	if illegalFlag, _, ok := FindFlag(args, UnimplementedBuildFlags); ok {
		return "", fmt.Errorf("build flag -%s is not yet implemented by fzgo prototype", illegalFlag)
	}

	// third, find our package argument like './...' or 'fmt',
	// as well as nonPkgArgs are our args minus any package arguments (to set us up to use flag.FlagSet.Parse)
	pkgPatterns, nonPkgArgs, err := FindPkgs(args)
	if err != nil {
		return "", report(err)
	}
	var pkgPattern string
	if len(pkgPatterns) > 1 {
		return "", fmt.Errorf("more than one package pattern not allowed: %q", pkgPatterns)
	} else if len(pkgPatterns) == 0 {
		pkgPattern = "."
	} else {
		pkgPattern = pkgPatterns[0]
	}

	// fourth, we now have a clean set of arguments that we can
	// hand to the standard library flag parser (via fuzz.ParseFlags).
	// any unrecognized flags should be treated as errors, so
	// we now parse our non-package args.
	err = fs.Parse(nonPkgArgs)
	if err == flag.ErrHelp {
		return "", err
	} else if err != nil {
		return "", report(err)
	}
	if len(fs.Args()) > 0 {
		return "", fmt.Errorf("packages are the only non-flag arguments allowed with -fuzz flag. illegal argument: %q", fs.Arg(0))
	}
	return pkgPattern, nil
}

// FindFlag looks for the first matching arg that looks like a flag in the list of flag names,
// and returns the first flag name found. FindFlag does not stop at non-flag arguments (e.g.,
// it does not stop at a package pattern).  This is a simple scan, and not a complete parse
// of the arguments (and for example does not differentiate between a bool flag vs. a duration flag).
// A client should do a final valiation pass via fuzz.ParseArgs(), which calls the standard flag.FlagSet.Parse()
// and which will reject malformed arguments according to the normal rules of the flag package.
// Returns the found name, and a possible value that is either the value of name=value, or
// the next arg if there is no '=' immediately after name. It is up to the caller to know
// if the possible value should be interpreted as the actual value (because, for example,
// FindFlag has no knowledge of bool flag vs. other flags, etc.).
func FindFlag(args []string, names []string) (string, string, bool) {
	nameSet := map[string]bool{}
	for _, name := range names {
		nameSet[name] = true
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if flag, ok := candidateFlag(arg); ok {
			if flag == "args" {
				// for 'go test', go tool specific args are defined to stop at '-args' or '--args',
				// so stop looking
				return "", "", false
			}
			foundName, foundValue := "", ""
			if strings.Contains(flag, "=") {
				// found arg '-foo=bar' or '--foo=bar'
				splits := strings.SplitN(flag, "=", 2)
				foundName = splits[0]
				foundValue = splits[1]
			} else {
				foundName = flag
				if i+1 < len(args) {
					foundValue = args[i+1]
				}
			}

			if nameSet[foundName] {
				return foundName, foundValue, true
			}

		}
	}
	return "", "", false
}

// FindTestFlag looks for the first matching arg that looks like a flag in the list of flag names,
// and returns the first flag name found. If passed flag name 'foo', it looks for both '-foo' and '-test.foo'.
// See FindFlag for more details.
func FindTestFlag(args []string, names []string) (string, string, bool) {
	var finalNames []string
	for _, n := range names {
		finalNames = append(finalNames, n)
		finalNames = append(finalNames, "test."+n)
	}
	return FindFlag(args, finalNames)
}

// FindPkgs looks for args that seem to be package arguments
// and returns them in a slice.
func FindPkgs(args []string) ([]string, []string, error) {
	pkgs := []string{}
	supportedBoolSet := map[string]bool{}
	for _, name := range supportedBools {
		supportedBoolSet[name] = true
	}
	otherArgs := make([]string, len(args))
	copy(otherArgs, args)

	// loop looking for candidate packages, which are the first non-flag arg(s).
	// stop our loop at '-args'/'--args', or after we find any package(s).
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if flag, ok := candidateFlag(arg); ok {
			if flag == "args" {
				// test-specific args are defined to stop at '-args' or '--args'
				// stop processing
				return pkgs, otherArgs, nil
			} else if !supportedBoolSet[flag] {
				// we have a flag, and it is not a bool.
				if !strings.Contains(flag, "=") {
					// next item should be the value for this flag,
					// so extra increment here to move ahead over it.
					i++
					continue
				}
			}
		} else {
			// found our first non-flag.
			pkgs = append(pkgs, arg)
			// will return this as our result in a momement, but first
			// see if the next arg(s) are non-flag as well.
			next := i + 1
			for next < len(args) {
				if _, ok := candidateFlag(args[next]); ok {
					break
				}
				// found another non-flag
				pkgs = append(pkgs, args[next])
				next++
			}
			otherArgs = append(otherArgs[0:i], otherArgs[next:]...)
			return pkgs, otherArgs, nil
		}
	}
	return pkgs, otherArgs, nil
}

// candidateFlag reports if the arg has leading hyphens (single or double),
// and also returns the (potential) flag name after stripping the leading '-' or '--'.
// If arg is -foo, returns "foo", true.  If arg is -foo=bar, returns "foo=bar", true.
// candidateFlag does not validate beyond checking for 1 or 2 leading hyphens and that
// the candidate flag is non-empty.
func candidateFlag(arg string) (string, bool) {
	// Look for leading '-' or '--'
	flag := ""
	if strings.HasPrefix(arg, "--") {
		flag = arg[2:]
	} else if strings.HasPrefix(arg, "-") {
		flag = arg[1:]
	}
	if len(flag) == 0 || strings.HasPrefix(flag, "-") {
		return "", false
	}
	return flag, true
}

// Usage is a func that returns a func that can be used as flag.FlagSet.Usage
type Usage func(*flag.FlagSet) func()

// FlagSet creates a new flag.FlagSet and registers our flags.
// Each flag is registered once as "foo" and once as "test.foo"
func FlagSet(name string, defs []FlagDef, usage Usage) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// we are taking responsibility for outputting errors and formating usage
	fs.SetOutput(ioutil.Discard)
	fs.Usage = usage(fs)
	for _, d := range defs {
		switch v := d.Ptr.(type) {
		case *string:
			fs.StringVar(v, d.Name, "", d.Description)
			fs.StringVar(v, "test."+d.Name, "", d.Description)
		case *int:
			fs.IntVar(v, d.Name, 0, d.Description)
			fs.IntVar(v, "test."+d.Name, 0, d.Description)
		case *bool:
			fs.BoolVar(v, d.Name, false, d.Description)
			fs.BoolVar(v, "test."+d.Name, false, d.Description)
		case *time.Duration:
			fs.DurationVar(v, d.Name, 0, d.Description)
			fs.DurationVar(v, "test."+d.Name, 0, d.Description)
		default:
			// this would be programmer error
			return nil, fmt.Errorf("arguments: unexpected type %T registered for flag %s", d.Ptr, d.Name)
		}
	}
	return fs, nil
}
