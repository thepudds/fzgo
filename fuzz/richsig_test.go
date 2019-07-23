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
	}
	tests := []struct {
		name       string
		args       args
		wantOutput string
		wantErr    bool
		// TODO: delete? update? not use currently.
		// want    []Func
	}{
		{
			name:    "only basic types: string, []byte, bool",
			args:    args{funcPattern: "FuzzWithBasicTypes", pkgPattern: "github.com/thepudds/fzgo/examples/richsignatures"},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import gofuzz "github.com/google/gofuzz"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	// fuzzer := fuzz.New()
	var seed int64
	if len(data) == 0 {
		seed = 0
	} else {
		seed = int64(data[0])
	}
	fuzzer := gofuzz.NewWithSeed(seed)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that takes
// uses google/gofuzz fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *gofuzz.Fuzzer) {

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
			name:    "type from stdlib: regexp",
			args:    args{funcPattern: "FuzzWithStdlibType", pkgPattern: "github.com/thepudds/fzgo/examples/richsignatures"},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import gofuzz "github.com/google/gofuzz"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	// fuzzer := fuzz.New()
	var seed int64
	if len(data) == 0 {
		seed = 0
	} else {
		seed = int64(data[0])
	}
	fuzzer := gofuzz.NewWithSeed(seed)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that takes
// uses google/gofuzz fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *gofuzz.Fuzzer) {

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
			name:    "type from outside stdlib: github.com/fzgo/fuzz.Func",
			args:    args{funcPattern: "FuzzWithFzgoFunc", pkgPattern: "github.com/thepudds/fzgo/examples/richsignatures"},
			wantErr: false,
			wantOutput: `
package richsigwrapper

import "github.com/thepudds/fzgo/examples/richsignatures"

import gofuzz "github.com/google/gofuzz"

// FuzzRichSigWrapper is an automatically generated wrapper that is
// compatible with dvyukov/go-fuzz.
func FuzzRichSigWrapper(data []byte) int {
	// fuzzer := fuzz.New()
	var seed int64
	if len(data) == 0 {
		seed = 0
	} else {
		seed = int64(data[0])
	}
	fuzzer := gofuzz.NewWithSeed(seed)
	fuzzOne(fuzzer)
	return 0
}

// fuzzOne is an automatically generated function that takes
// uses google/gofuzz fuzzer to automatically fuzz the arguments for a
// user-supplied function.
func fuzzOne (fuzzer *gofuzz.Fuzzer) {

	// Create random args for each parameter from the signature.
	// fuzzer.Fuzz recursively fills all of obj's fields with something random.
	// Only exported (public) fields can be set currently. (That is how google/go-fuzz operates).
	var f fuzz.Func
	fuzzer.Fuzz(&f)

	pkgname.FuzzWithFzgoFunc(f)

}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			functions, err := FindFunc(tt.args.pkgPattern, tt.args.funcPattern, nil, tt.args.allowMultiFuzz)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			createWrapper(&b, functions[0])
			gotOutput := b.String()
			diff := cmp.Diff(tt.wantOutput, gotOutput)
			if diff != "" {
				t.Fatalf("FindFunc() failed to match function output. diff:\n%s", diff)
			}

			/* TODO: delete? update?
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindFunc() = %v, want %v", got, tt.want)
			}
			*/
		})
	}
}
