[![Build Status](https://travis-ci.org/thepudds/fzgo.svg?branch=master)](https://travis-ci.org/thepudds/fzgo)

## fzgo: simple prototype of integrating go-fuzz with 'go test'

fzgo is a simple initial prototype of integrating [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz)
into 'go test', with the heavy lifting being done by `go-fuzz`, `go-fuzz-build`, and the `go` tool. The focus 
is on step 1 of a tentative list of "Draft goals for a prototype" outlined in this
[comment](https://github.com/golang/go/issues/19109#issuecomment-441442080) on [#19109](https://golang.org/issue/19109):

   _Step 1. Prototype proposed CLI, including interaction with existing 'go test'._
 
`fzgo` supports the `-fuzz` flag and several other related flags proposed in the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008). `fzgo` also supports typical `go` commands 
such as `fzgo build`, `fgzo test`, or `fzgo env` (which are implemented by wrapping the `go` tool).

* `go-fuzz` requires a two step process. `fzgo` eliminates the separate manual preparation step.
* `fzgo` automatically caches instrumented binaries in `GOPATH/pkg/fuzz` and re-uses them if possible.
* The fuzzing corpus defaults to `pkgpath/testdata/fuzz/fuzzname`. 
* The `-fuzzdir` flag allows the corpus to be stored elsewhere (e.g., a separate corpus repo).
* The fuzzing function name must begin with `Fuzz` and still uses the `func Fuzz(data []byte) int` form used by `go-fuzz`. 
* `fuzz` and `gofuzz` build tags are allowed but not required.

## Usage
```
Usage: fzgo test [build/test flags] [packages] [build/test flags]

Examples:

   fzgo test                           # test the current package
   fzgo test -fuzz .                   # fuzz the current package with a function starting with 'Fuzz'
   fzgo test -fuzz FuzzFoo             # fuzz the current package with a function matching 'FuzzFoo'
   fzgo test ./... -fuzz FuzzFoo       # fuzz a package in ./... with a function matching 'FuzzFoo'
   fzgo test sample/pkg -fuzz FuzzFoo  # fuzz 'sample/pkg' with a function matching 'FuzzFoo'

The following flags work with 'fzgo test -fuzz':

   -fuzz regexp
       fuzz at most one function matching regexp
   -fuzzdir dir
       store fuzz artifacts in dir (default pkgpath/testdata/fuzz)
   -fuzztime d
       fuzz for duration d (default unlimited)
   -parallel n
       start n fuzzing operations (default GOMAXPROCS)
   -timeout d
       fail an individual call to a fuzz function after duration d (default 10s, minimum 1s)
   -c
       compile the instrumented code but do not run it
   -v
       verbose: print additional output
```  

## Install

```
$ go get -u github.com/thepudds/fzgo
$ go get -u github.com/dvyukov/go-fuzz/...
```

Note: if you already have an older `dvyukov/go-fuzz`, you might need to first delete it from GOPATH as described in
the [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz#history-rewrite) repo.

The `go-fuzz` source code must be in your GOPATH, and the `go-fuzz` and `go-fuzz-build` binaries must be 
in your path environment variable.

## Status

This is a very early and very simple prototype. Don't expect great things.  ;-)

Testing is primarily done with the nice internal `testscripts` package used by the core Go team to test the `go` tool
and nicely extracted at [rogpeppe/go-internal/testscript](https://github.com/rogpeppe/go-internal/tree/master/testscript).

#### Changes from the proposal document

Two minor changes between the current prototype vs. the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008):

1. Some of the commentators at [#19109](https://golang.org/issue/19109) suggested `-fuzztime duration` as a 
way of controlling when to stop fuzzing. The proposal document does not include `-fuzztime` and `go-fuzz` 
does not support it, but it seems useful in general and `-fuzztime` is in the prototype (and it proved 
useful while testing the prototype).
2. The proposal document suggested `GOPATH/pkg/GOOS_GOARCH_fuzz/` for a cache, but the prototype instead
uses `GOPATH/pkg/fuzz/GOOS_GOARCH/`.

#### Pieces of proposal document not implemented in this prototype

* New signature for fuzzing function.
* Allowing fuzzing functions to reside in `*_test.go` files.
* Anything to do with deeper integration with the compiler for better or more robust instrumentation. This prototype is not focused on that area.
* `-fuzzminimize`, `-fuzzinput`, `-coverprofile`, or any of a much larger set of preexisting build flags like `-ldflags`.
* A longer list of items that are covered in the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008) but not yet mentioned above in this README...  
