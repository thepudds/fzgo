package fuzz

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWrapperGeneration(t *testing.T) {
	type args struct {
		pkgPattern     string
		funcPattern    string
		allowMultiFuzz bool
		printArgs      bool
	}
	tests := []struct {
		name       string
		args       args
		wantOutput string
		wantErr    bool
	}{
		{
			name: "only basic types: string, []byte, bool",
			args: args{
				funcPattern: "FuzzWithBasicTypes",
				pkgPattern:  "github.com/thepudds/fzgo/examples/richsignatures",
				printArgs:   false,
			},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import "github.com/thepudds/fzgo/randparam"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	fuzzer := randparam.NewFuzzer(data)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that
// uses fzgo/randparam.Fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *randparam.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
	var re string
	fuzzer.Fuzz(&re)

	var input []byte
	fuzzer.Fuzz(&input)

	var posix bool
	fuzzer.Fuzz(&posix)

	pkgname.FuzzWithBasicTypes(re, input, posix)

}
`,
		},
		{
			name: "type from stdlib: regexp",
			args: args{
				funcPattern: "FuzzWithStdlibType",
				pkgPattern:  "github.com/thepudds/fzgo/examples/richsignatures",
				printArgs:   false,
			},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import "github.com/thepudds/fzgo/randparam"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	fuzzer := randparam.NewFuzzer(data)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that
// uses fzgo/randparam.Fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *randparam.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
	var something string
	fuzzer.Fuzz(&something)

	var another string
	fuzzer.Fuzz(&another)

	var allow bool
	fuzzer.Fuzz(&allow)

	var re *regexp.Regexp
	fuzzer.Fuzz(&re)

	pkgname.FuzzWithStdlibType(something, another, allow, re)

}
`,
		},
		{
			name: "type from outside stdlib: github.com/fzgo/fuzz.Func",
			args: args{
				funcPattern: "FuzzWithFzgoFunc",
				pkgPattern:  "github.com/thepudds/fzgo/examples/richsignatures",
			},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import "github.com/thepudds/fzgo/randparam"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	fuzzer := randparam.NewFuzzer(data)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that
// uses fzgo/randparam.Fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *randparam.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
	var f fuzz.Func
	fuzzer.Fuzz(&f)

	pkgname.FuzzWithFzgoFunc(f)

}
`,
		},
		{
			name: "print args with verbose",
			args: args{
				funcPattern: "FuzzWithBasicTypes",
				pkgPattern:  "github.com/thepudds/fzgo/examples/richsignatures",
				printArgs:   true,
			},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import "github.com/thepudds/fzgo/randparam"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	fuzzer := randparam.NewFuzzer(data)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that
// uses fzgo/randparam.Fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *randparam.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
	var re string
	fuzzer.Fuzz(&re)
	fmt.Printf("               arg 1:     %#v\n", re)

	var input []byte
	fuzzer.Fuzz(&input)
	fmt.Printf("               arg 2:     %#v\n", input)

	var posix bool
	fuzzer.Fuzz(&posix)
	fmt.Printf("               arg 3:     %#v\n", posix)

	pkgname.FuzzWithBasicTypes(re, input, posix)

}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			functions, err := FindFunc(tt.args.pkgPattern, tt.args.funcPattern, nil, tt.args.allowMultiFuzz)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FindFunc() error = %v, wantErr %v", err, tt.wantErr)
			}
			err = createWrapper(&b, functions[0], tt.args.printArgs)
			if err != nil {
				t.Fatalf("createWrapper() error = %v", err)
			}
			gotOutput := b.String()
			diff := cmp.Diff(tt.wantOutput, gotOutput)
			if diff != "" {
				t.Fatalf("createWrapper() failed to match function output. diff:\n%s", diff)
			}
		})
	}
}
