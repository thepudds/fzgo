[![Build Status](https://travis-ci.org/thepudds/fzgo.svg?branch=master)](https://travis-ci.org/thepudds/fzgo)

## fzgo: simple prototype of integrating go-fuzz with 'go test'

fzgo is a simple initial prototype of integrating [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz)
into 'go test', with the heavy lifting being done by `go-fuzz`, `go-fuzz-build`, and the `go` tool. The focus 
is on step 1 of a tentative list of "Draft goals for a prototype" outlined in [this
comment](https://github.com/golang/go/issues/19109#issuecomment-441442080) on [#19109](https://golang.org/issue/19109):

   _Step 1. Prototype proposed CLI, including interaction with existing 'go test'._
 
`fzgo` supports the `-fuzz` flag and several other related flags proposed in the March 2017 
[proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008). `fzgo` also supports typical `go` commands 
such as `fzgo build`, `fgzo test`, or `fzgo env` (which are implemented by wrapping the `go` tool).

* `go-fuzz` requires a two step process. `fzgo` eliminates the separate manual preparation step.
* `fzgo` automatically caches instrumented binaries in `GOPATH/pkg/fuzz` and re-uses them if possible.
* The fuzzing corpus defaults to `pkgpath/testdata/fuzz/fuzzname`. 
* The `-fuzzdir` flag allows the corpus to be stored elsewhere (e.g., a separate corpus repo).
* The fuzzing function name must begin with `Fuzz` and still uses the `func Fuzz(data []byte) int` form used by `go-fuzz`. 
* `fuzz` and `gofuzz` build tags are allowed but not required.
* The corpus is automatically used as deterministic input to unit tests when running a normal test (e.g., `fzgo test <pkg>`).

## Usage
```
Usage: fzgo test [build/test flags] [packages] [build/test flags]

Examples:

   fzgo test                           # normal 'go test' of current package, plus run any corpus as unit tests
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

Three changes between the current fzgo prototype vs. the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008):

1. Initially, fzgo disallowed multiple fuzz functions to match (per the March 2017 proposal),
but as an experiment fzgo now allows multiple fuzz functions to match in order to 
support something like 'go test -fuzz=. ./...' when there are multiple fuzz functions
across multiple packages. Fuzzing happens in round-robin manner if multiple fuzz functions match.
2. Some of the commentators at [#19109](https://golang.org/issue/19109) suggested `-fuzztime duration` as a 
way of controlling when to stop fuzzing. The proposal document does not include `-fuzztime` and `go-fuzz` 
does not support it, but it seems useful in general and `-fuzztime` is in the prototype (and it proved 
useful while testing the prototype).
3. The proposal document suggested `GOPATH/pkg/GOOS_GOARCH_fuzz/` for a cache, but the prototype instead
uses `GOPATH/pkg/fuzz/GOOS_GOARCH/`.
4. The initial proposal document suggested generating new mutation-based inputs during `go test` when `-fuzz` was not specified. In order to keep `go test` deterministic, `fzgo` does not do that, but now does use the corpus as a deterministic set of inputs during `go test` when `-fuzz` is not specified.  Also, the proposal document suggested `-fuzzinput` as a way of specifying a file from the corpus to execute as a unit test. `fzgo` instead uses the normal `-run` argument to `go test`. For example, `fzgo test -run=TestCorpus/4fa128cf066f2a31 some/pkg` runs the any file in the `some/pkg` corpus with a filename matching `4fa128cf066f2a31`.

#### Pieces of proposal document not implemented in this prototype

* New signature for fuzzing function.
* Allowing fuzzing functions to reside in `*_test.go` files.
* Anything to do with deeper integration with the compiler for more robust instrumentation. This
prototype is not focused on that area.
* `-fuzzminimize`, `-coverprofile`.
* Any of a much larger set of preexisting build flags like `-ldflags`.
* Other items covered in the March 2017 [proposal document](https://github.com/golang/go/issues/19109#issuecomment-285456008), 
especially in areas outside of the direct user-facing behavior that this prototype focuses on. That said, the majority of user-facing behavior mentioned in the proposal document is either implemented in the prototype or explicitly mentioned in this list as not implemented.

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
