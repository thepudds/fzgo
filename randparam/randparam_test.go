package randparam

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFuzzerStringsBytes_Fuzz(t *testing.T) {

	t.Run("string - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 9 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x9}, []byte("123456789")...)
		want := "123456789"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 5 byte length, 6 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x5}, []byte("123456")...)
		want := "12345"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 2 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x9}, []byte("12")...)
		want := string(append([]byte("12"), []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}...))

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("byte slice - 8 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x8}, []byte("12345678")...)
		want := []byte("12345678")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("byte slice - 3 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x3}, []byte("12345678")...)
		want := []byte("123")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 8 bytes input", func(t *testing.T) {
		input := make([]byte, 8)
		i := uint64(0xfeedfacedeadbeef)
		binary.LittleEndian.PutUint64(input, i)
		want := uint64(0xfeedfacedeadbeef)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 4 bytes input", func(t *testing.T) {
		input := []byte{0xef, 0xbe, 0xad, 0xde}
		want := uint64(0xdeadbeef)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 4 bytes input", func(t *testing.T) {
		input := []byte{0x42, 0x00, 0x00, 0x00}
		want := int32(0x42)

		fuzzer := NewFuzzer(input)
		var got int32
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

}
