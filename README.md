[![Build Status](https://travis-ci.org/thepudds/fzgo.svg?branch=master)](https://travis-ci.org/thepudds/fzgo) [![Go Report Card](https://goreportcard.com/badge/github.com/thepudds/fzgo)](https://goreportcard.com/report/github.com/thepudds/fzgo) 


## fzgo: go-fuzz + 'go test' = fewer bugs

`fzgo` is a prototype of [golang/go#19109](https://golang.org/issue/19109) **"cmd/go: make fuzzing a first class citizen, like tests or benchmarks"**.

`fzgo` supports some conveniences like fuzzing rich signatures and auto-generation of fuzzing functions.

The basic approach is that `fzgo` integrates [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz)
into `go test`, with the heavy lifting being done by `go-fuzz`, `go-fuzz-build`, and the `go` tool. The focus 
is on step 1 of a tentative list of "Draft goals for a prototype" outlined in [this
comment](https://github.com/golang/go/issues/19109#issuecomment-441442080) on [#19109](https://golang.org/issue/19109):

   _Step 1. Prototype proposed CLI, including interaction with existing 'go test'._
 
`fzgo` supports the `-fuzz` flag and several other related flags proposed in the March 2017 
[#19109 proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008). `fzgo` also supports typical `go` commands 
such as `fzgo build`, `fgzo test`, or `fzgo env` (which are implemented by wrapping the `go` tool).

Any and all feedback is welcome!

### Features

* Rich signatures like `FuzzRegexp(re string, input []byte, posix bool)` are supported, as well as the classic `Fuzz(data []byte) int` form used by `go-fuzz`. 
* The corpus is automatically used as deterministic input to unit tests when running a normal `go test`. 
* Individual corpus files can be unit tested via `fzgo test -fuzz=. -run=TestCorpus/<name>`.
* `go-fuzz` requires a two step process. `fzgo` eliminates the separate manual preparation step.
* `fzgo` automatically caches instrumented binaries in `GOPATH/pkg/fuzz` and re-uses them if possible.
* The fuzzing corpus defaults to `GOPATH/pkg/fuzz/corpus`. 
* The `-fuzzdir=/some/path` flag allows the corpus to be stored elsewhere (e.g., a separate corpus repo); `-fuzzdir=testdata` stores the corpus under `<pkgpath>/testdata/fuzz/fuzzname` (hence typically in VCS with the code under test).
* `fuzz` and `gofuzz` build tags are allowed but not required.
* An optional [genfuzzfuncs](https://github.com/thepudds/fzgo/blob/master/genfuzzfuncs/README.md) utility can automatically create fuzzing functions for all of the public functions and methods in a package of interest. This makes it quicker and easier to start fuzzing.

## Usage
```
Usage: fzgo test [build/test flags] [packages] [build/test flags]

Examples:

   fzgo test                           # normal 'go test' of current package, plus run any corpus as unit tests
   fzgo test -fuzz=.                   # fuzz the current package with a function starting with 'Fuzz'
   fzgo test -fuzz=FuzzFoo             # fuzz the current package with a function matching 'FuzzFoo'
   fzgo test ./... -fuzz=FuzzFoo       # fuzz a package in ./... with a function matching 'FuzzFoo'
   fzgo test sample/pkg -fuzz=FuzzFoo  # fuzz 'sample/pkg' with a function matching 'FuzzFoo'

Rich signatures like Fuzz(re string, input []byte, posix bool)` are supported, as well Fuzz(data []byte) int.
Fuzz functions must start with 'Fuzz'.

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
$ go get -u github.com/thepudds/fzgo/...
$ go get -u github.com/dvyukov/go-fuzz/...
```

Note: if you already have an older `dvyukov/go-fuzz`, you might need to first delete it from GOPATH as described in
the [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz#history-rewrite) repo.

The `go-fuzz` source code must be in your GOPATH, and the `go-fuzz` and `go-fuzz-build` binaries must be 
in your path environment variable.

**Note**: Module-mode is not supported ([#15](https://github.com/thepudds/fzgo/issues/15)), but you can fuzz a module with `fzgo` as long as the code under test is in GOPATH and you set `GO111MODULE=off` env variable.

## Status

This is a simple prototype. Don't expect great things.  ;-)

That said, there is reasonable test coverage and `fzgo` is hopefully beta quality. Automatically generating fuzz functions is implemented in a separate [genfuzzfuncs](https://github.com/thepudds/fzgo/blob/master/genfuzzfuncs/README.md) utility that is more alpha quality.

Testing is primarily done with the nice internal `testscripts` package used by the core Go team to test the `go` tool
and extracted at [rogpeppe/go-internal/testscript](https://github.com/rogpeppe/go-internal/tree/master/testscript).

#### Changes from the proposal document

The primary changes between the current fzgo prototype vs. the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008):

1. fzgo supports rich signatures.
2. The corpus location does not default to `<pkgpath>/testdata/fuzz`, but instead follows the approach outlined [here](https://groups.google.com/d/msg/golang-fuzzing-proposal/WVyRXx7AsO4/CXzvbMT1CgAJ) and more precisely described in [PR #7](https://github.com/thepudds/fzgo/pull/7).
3. Initially, fzgo disallowed multiple fuzz functions to match (per the March 2017 proposal),
but as an experiment fzgo now allows multiple fuzz functions to match in order to 
support something like 'go test -fuzz=. ./...' when there are multiple fuzz functions
across multiple packages. Fuzzing happens in round-robin manner if multiple fuzz functions match.
4. The proposal document suggested `GOPATH/pkg/GOOS_GOARCH_fuzz/` for a cache, but the prototype instead
uses `GOPATH/pkg/fuzz/GOOS_GOARCH/`.
5. The initial proposal document suggested generating new mutation-based inputs during `go test` when `-fuzz` was not specified. In order to keep `go test` deterministic, `fzgo` does not do that, but now does use the corpus as a deterministic set of inputs during `go test` when `-fuzz` is not specified.  Also, the proposal document suggested `-fuzzinput` as a way of specifying a file from the corpus to execute as a unit test. `fzgo` instead uses the normal `-run` argument to `go test`. For example, `fzgo test -run=TestCorpus/4fa128cf066f2a31 some/pkg` runs the any file in the `some/pkg` corpus with a filename matching `4fa128cf066f2a31`.
6. Some of the commentators at [#19109](https://golang.org/issue/19109) suggested `-fuzztime duration` as a 
way of controlling when to stop fuzzing. The proposal document does not include `-fuzztime` and `go-fuzz` 
does not support it, but it seems useful in general and `-fuzztime` is in the prototype (and it proved 
useful while testing the prototype). This might be removed later.
7. For experimentation, `FZGOFLAGSBUILD` and `FZGOFLAGSFUZZ` environmental variables can optionally contain a space-separated list of arguments to pass to `go-fuzz-build` and `go-fuzz`, respectively.

#### Pieces of proposal document not implemented in this prototype

* `fuzz.F` or `testing.F` signature for fuzzing function.
* Allowing fuzzing functions to reside in `*_test.go` files.
* Anything to do with deeper integration with the compiler for more robust instrumentation. This
prototype is not focused on that area.
* Any of a much larger set of preexisting build flags like `-ldflags`, `-coverprofile`.
* Areas covered in the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008), 
outside of the direct user-facing behavior that this prototype focuses on. That said, the majority of user-facing behavior mentioned in the proposal document is either implemented in the prototype or explicitly mentioned in this list as not implemented.

The argument parsing in 'go test' is bespoke, and the argument parsing in `fzgo` is an approximation of that.
That might be OK for an early prototype. The right thing to do might be to extract 
[src/cmd/go/internal/test/testflag.go](https://golang.org/src/cmd/go/internal/test/testflag.go), 
which includes this comment:

```
// The flag handling part of go test is large and distracting.
// We can't use the flag package because some of the flags from
// our command line are for us, and some are for 6.out, and
// some are for both.
```
