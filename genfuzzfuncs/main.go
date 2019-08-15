// genfuzzfuncs is an early stage prototype for automatically generating
// fuzz functions, similar in spirit to cweill/gotests.
//
// For example, if you run genfuzzfuncs against github.com/google/uuid, it generates
// a uuid_fuzz.go file with 30 or so functions like:
//
//   func Fuzz_UUID_MarshalText(u1 uuid.UUID) {
// 	   u1.MarshalText()
//   }
//
//   func Fuzz_UUID_UnmarshalText(u1 *uuid.UUID, data []byte) {
// 	   if u1 == nil {
// 		 return
// 	   }
// 	   u1.UnmarshalText(data)
//   }
//
// You can then edit or delete indivdual fuzz funcs as desired, and then fuzz
// using the rich signature fuzzing support in thepudds/fzgo, such as:
//
//  fzgo test -fuzz=. ./...
package main

import (
	"flag"
	"fmt"
	"os"
)

// Usage contains short usage information.
var Usage = `
usage:
	genfuzzfuncs [-pkg=pkgPattern] [-func=regexp] [-unexported] [-qualifyall] 
	
Running genfuzzfuncs without any arguments targets the package in the current directory.

genfuzzfuncs outputs to stdout a set of wrapper functions for all functions
matching the func regex in the target package, which defaults to current directory.
Any function that already starts with 'Fuzz' is skipped, and so are any functions
with zero parameters or that have interface parameters.

The resulting wrapper functions will all start with 'Fuzz', and are candidates 
for use with fuzzing via thepudds/fzgo.

genfuzzfuncs does not attempt to populate imports, but 'goimports -w <file>' 
should usaully be able to do so.

`

func main() {
	// handle flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, Usage)
		flag.PrintDefaults()
	}
	pkgFlag := flag.String("pkg", ".", "package pattern, defaults to current package")
	funcFlag := flag.String("func", ".", "function regex, defaults to matching all")
	unexportedFlag := flag.Bool("unexported", false, "emit wrappers for unexported functions in addition to exported functions")
	qualifyAllFlag := flag.Bool("qualifyall", true, "all identifiers are qualified with package, including identifiers from the target package. "+
		"If the package is '.' or not set, this defaults to false. Else, it defaults to true.")
	constructorFlag := flag.Bool("ctors", false, "automatically insert constructors when wrapping a method call "+
		"if a suitable constructor can be found in the same package.")
	constructorPatternFlag := flag.String("ctorspattern", "^New", "regexp to use if searching for constructors to automatically use.")

	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		os.Exit(2)
	}

	// search for functions in the requested package that
	// matches the supplied func regex
	options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
	if !*unexportedFlag {
		options |= flagRequireExported
	}
	var qualifyAll bool
	if *pkgFlag == "." {
		qualifyAll = false
	} else {
		// qualifyAllFlag defaults to true, which is what we want
		// for non-local package.
		qualifyAll = *qualifyAllFlag
	}

	functions, err := FindFunc(*pkgFlag, *funcFlag, nil, options)
	if err != nil {
		fail(err)
	}

	wrapperOpts := wrapperOptions{
		qualifyAll:         qualifyAll,
		insertConstructors: *constructorFlag,
		constructorPattern: *constructorPatternFlag,
	}
	err = createWrappers(os.Stdout, *pkgFlag, functions, wrapperOpts)
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "genfuzzfuncs: error: %v\n", err)
	os.Exit(1)
}
