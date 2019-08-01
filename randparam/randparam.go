// Package randparam allows a []byte to be used as a source of random parameter values.
//
// The primary use case is to allow fzgo to use dvyukov/go-fuzz to fuzz rich signatures such as:
//    FuzzFunc(re string, input string, posix bool)
// google/gofuzz is used to walk the structure of parameters, but randparam uses custom random generators,
// including in the hopes of allowing dvyukov/go-fuzz literal injection to work,
// as well as to better exploit the genetic mutations of dvyukov/go-fuzz, etc.
package randparam

import (
	"math/rand"

	gofuzz "github.com/google/gofuzz"
)

// Fuzzer generates random values for public members.
// It wires together dvyukov/go-fuzz (for randomness, instrumentation, managing corpus, etc.)
// with google/gofuzz (for walking a structure recursively), though it uses functions from
// this package to actually fill in string, []byte, and number values.
type Fuzzer struct {
	gofuzzFuzzer *gofuzz.Fuzzer
}

// randFuncs is a list of our custom variable generation functions
// that tap into our custom random number generator to pull values from
// the initial input []byte.
var randFuncs = []interface{}{
	randInt,
	randInt8,
	randInt16,
	randInt32,
	randInt64,
	randUint,
	randUint8,
	randUint16,
	randUint32,
	randUint64,
	randFloat32,
	randFloat64,
	randByte,
	randRune,
}

// NewFuzzer returns a *Fuzzer, initialized with the []byte as an input stream for drawing values via rand.Rand.
func NewFuzzer(data []byte) *Fuzzer {
	// create our random data stream that fill use data []byte for results.
	fzgoSrc := &randSource{data: data}
	randSrc := rand.New(fzgoSrc)

	// create some closures for custom fuzzing (so that we have direct access to fzgoSrc).
	randFuncsWithFzgoSrc := []interface{}{
		func(ptr *[]byte, c gofuzz.Continue) {
			randBytes(ptr, c, fzgoSrc)
		},
		func(ptr *string, c gofuzz.Continue) {
			randString(ptr, c, fzgoSrc)
		},
	}

	// combine our two custom fuzz function lists.
	funcs := append(randFuncs, randFuncsWithFzgoSrc...)

	// create the google/gofuzz fuzzer
	gofuzzFuzzer := gofuzz.New().RandSource(randSrc).Funcs(funcs...)
	f := &Fuzzer{gofuzzFuzzer: gofuzzFuzzer}
	return f
}

// Fuzz fills in public members of obj. For numbers, strings, []bytes, it tries to populate the
// obj value with literals found in the initial input []byte.
func (f *Fuzzer) Fuzz(obj interface{}) {
	f.gofuzzFuzzer.Fuzz(obj)
}

// Override google/gofuzz fuzzing approach for strings, []byte, and numbers

// randBytes generates a 0-255 len byte slice using the input []byte stream.
// The next byte in the input []byte is used as the length, and then the subsequent
// values in the input []byte are used as the content. If we run out of
// input []byte data, then zeros are supplied by fzgo/randparam.randSource.
func randBytes(ptr *[]byte, c gofuzz.Continue, fzgoSrc *randSource) {
	// draw a size in [0, 255] from our input byte[] stream
	size := int(fzgoSrc.Byte())
	bs := make([]byte, size)

	for i := range bs {
		bs[i] = fzgoSrc.Byte()
	}

	*ptr = bs
}

func randString(s *string, c gofuzz.Continue, fzgoSrc *randSource) {
	var bs []byte
	randBytes(&bs, c, fzgoSrc)
	*s = string(bs)
}

// A set of custom numeric value filling funcs follows.
// These are currently simple implementations that only use gofuzz.Continue
// as a source for data, which means obtaining 64-bits of the input stream
// at a time. For sizes < 64 bits, this could be tighted up to waste less of the input stream
// by getting access to fzgo/randparam.randSource.

func randInt(val *int, c gofuzz.Continue) {
	*val = int(c.Rand.Uint64())
}

func randInt8(val *int8, c gofuzz.Continue) {
	*val = int8(c.Rand.Uint64())
}

func randInt16(val *int16, c gofuzz.Continue) {
	*val = int16(c.Rand.Uint64())
}

func randInt32(val *int32, c gofuzz.Continue) {
	*val = int32(c.Rand.Uint64())
}

func randInt64(val *int64, c gofuzz.Continue) {
	*val = int64(c.Rand.Uint64())
}

func randUint(val *uint, c gofuzz.Continue) {
	*val = uint(c.Rand.Uint64())
}

func randUint8(val *uint8, c gofuzz.Continue) {
	*val = uint8(c.Rand.Uint64())
}

func randUint16(val *uint16, c gofuzz.Continue) {
	*val = uint16(c.Rand.Uint64())
}

func randUint32(val *uint32, c gofuzz.Continue) {
	*val = uint32(c.Rand.Uint64())
}

func randUint64(val *uint64, c gofuzz.Continue) {
	*val = uint64(c.Rand.Uint64())
}

func randFloat32(val *float32, c gofuzz.Continue) {
	*val = float32(c.Rand.Uint64())
}

func randFloat64(val *float64, c gofuzz.Continue) {
	*val = float64(c.Rand.Uint64())
}

func randByte(val *byte, c gofuzz.Continue) {
	*val = byte(c.Rand.Uint64())
}

func randRune(val *rune, c gofuzz.Continue) {
	*val = rune(c.Rand.Uint64())
}

// Note: complex64, complex128, uintptr are not supported by google/gofuzz, I think.
// Interfaces are also not currently supported by google/gofuzz, or at least not
// easily as far as I am aware. Might be able to get it to work with custom
// functions, such as:
//   func randIoWriter(val *io.Writer, c gofuzz.Continue) {
