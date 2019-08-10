package main

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_genfuzzfuncs(t *testing.T) {
	tests := []struct {
		name         string
		onlyExported bool
		want         string
	}{
		{"exported only", true, `package fuzzwrapexamples

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_TypeExported_PointerExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	FuncExported(i)
}

// skipping Fuzz_FuncExportedUsesInterface because parameters include interfaces or funcs: io.Reader

`},
		{"exported and not exported", false, `package fuzzwrapexamples

import (
	// fill in manually if needed, or run 'goimports'
)

func Fuzz_TypeExported_PointerExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_pointerRcvNotExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_PointerExportedMethod(t *typeNotExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_typeNotExported_pointerRcvNotExportedMethod(t *typeNotExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_TypeExported_nonPointerRcvNotExportedMethod(t TypeExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_NonPointerExportedMethod(t typeNotExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_typeNotExported_nonPointerRcvNotExportedMethod(t typeNotExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	FuncExported(i)
}

// skipping Fuzz_FuncExportedUsesInterface because parameters include interfaces or funcs: io.Reader

func Fuzz_funcNotExported(i int) {
	funcNotExported(i)
}

`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := FindFunc("github.com/thepudds/fzgo/genfuzzfuncs/examples/exportedtests", ".", nil, options)
			if err != nil {
				t.Errorf("FindFuncfail() failed: %v", err)
			}

			var b bytes.Buffer
			qualifyAll := false
			err = createWrappers(&b, functions, qualifyAll)
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
