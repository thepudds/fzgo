package fuzzwrapexamples

import "io"

// FuncExported is a test function to make sure we emit exported functions.
func FuncExported(i int)    {}
func funcNotExported(i int) {}

type typeNotExported int

func (t *typeNotExported) pointerRcvNotExportedMethod(i int)   {}
func (t typeNotExported) nonPointerRcvNotExportedMethod(i int) {}
func (t *typeNotExported) PointerExportedMethod(i int)         {}
func (t typeNotExported) NonPointerExportedMethod(i int)       {}

// TypeExported is a test type to make sure we emit exported methods.
type TypeExported int

func (t *TypeExported) pointerRcvNotExportedMethod(i int)   {}
func (t TypeExported) nonPointerRcvNotExportedMethod(i int) {}
func (t *TypeExported) PointerExportedMethod(i int)         {}
func (t TypeExported) NonPointerExportedMethod(i int)       {}

var ExportedLiteral = func(i int) {}
var notExportedLiteral = func(i int) {}

// ExportedInterface is a test interface to make sure
// we don't emit anything for functions in interfaces
type ExportedInterface interface {
	ExportedFunc()
}

// FuncExportedUsesInterface is a test func to make sure
// we don't emit anything for functions that use interfaces
func FuncExportedUsesInterface(w io.Reader) {}
