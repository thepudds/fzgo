package main

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// the simplest to run is:
//    go test -run=ConstructorInjection/constructor_injection:_exported_only,_not_local_pkg

func TestConstructorInjection(t *testing.T) {
	tests := []struct {
		name               string
		onlyExported       bool
		qualifyAll         bool
		injectConstructors bool
		want               string
	}{
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "constructor injection: exported only, not local pkg",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: true,
			want: `package fuzzwrapexamplesfuzz    // rename if needed

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_A_PtrMethodNoArg(c int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(c int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_A_ValMethodNoArg(c int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(c int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	fuzzwrapexamples.NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	fuzzwrapexamples.NewBVal(c)
}

`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "no constructor injection: exported only, not local pkg",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: false,
			want: `package fuzzwrapexamplesfuzz    // rename if needed

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_A_PtrMethodNoArg(r *fuzzwrapexamples.A) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(r *fuzzwrapexamples.A, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(r *fuzzwrapexamples.B) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(r *fuzzwrapexamples.B, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_A_ValMethodNoArg(r fuzzwrapexamples.A) {
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(r fuzzwrapexamples.A, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(r fuzzwrapexamples.B) {
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(r fuzzwrapexamples.B, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	fuzzwrapexamples.NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	fuzzwrapexamples.NewBVal(c)
}

`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "constructor injection: exported only, local pkg",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: true,
			want: `package fuzzwrapexamples

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_A_PtrMethodNoArg(c int) {
	r := NewAPtr(c)
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(c int, i int) {
	r := NewAPtr(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(c int) {
	r := NewBVal(c)
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(c int, i int) {
	r := NewBVal(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_A_ValMethodNoArg(c int) {
	r := NewAPtr(c)
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(c int, i int) {
	r := NewAPtr(c)
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(c int) {
	r := NewBVal(c)
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(c int, i int) {
	r := NewBVal(c)
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	NewBVal(c)
}

`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors=false -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "no constructor injection: exported only, local pkg",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: false,
			want: `package fuzzwrapexamples

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_A_PtrMethodNoArg(r *A) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(r *A, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(r *B) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(r *B, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_A_ValMethodNoArg(r A) {
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(r A, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(r B) {
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(r B, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	NewBVal(c)
}

`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := FindFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Errorf("FindFuncfail() failed: %v", err)
			}

			var b bytes.Buffer
			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: tt.injectConstructors,
				constructorPattern: "^New",
			}
			err = createWrappers(&b, pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Errorf("createWrappers() failed: %v", err)
			}

			got := b.String()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
