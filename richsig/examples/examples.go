package pkgname

import (
	"regexp"

	"github.com/thepudds/fzgo/fuzz"
)

// FuzzWithBasicTypes is a fuzzing function written by a user
// that has a rich signature. All parameters are basic types,
// but is uses stdlib types within (regexp).
// We can fuzz it automatically, even though it doesn't match the standard []data
// signature. This is just a test -- the fuzzing itself is not of interest.
func FuzzWithBasicTypes(re string, input []byte, posix bool) (bool, error) {

	var r *regexp.Regexp
	var err error
	if posix {
		r, err = regexp.CompilePOSIX(re)
	} else {
		r, err = regexp.Compile(re)
	}
	if err != nil {
		return false, err
	}

	return r.Match(input), nil
}

// FuzzWithStdlibType is a test function using a combination of basic types
// and also one from the stdlib (regexp).
func FuzzWithStdlibType(something, another string, allow bool, re *regexp.Regexp) {
	regexp.MatchString(something, another)
}

// FuzzWithFzgoFunc uses a non-stdlib type
func FuzzWithFzgoFunc(f fuzz.Func) string {
	return f.String()
}

// ExampleType is defined in the same package as the fuzz target that uses it (next func below).
type ExampleType int

// FuzzWithTargetType shows a type defined in the same file as the fuzz function.
func FuzzWithTargetType(e ExampleType) {

}
