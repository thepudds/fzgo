package randparam

import (
	"encoding/binary"
)

// randSource supplies a stream of data via the rand.Source64 interface,
// but does so using an input data []byte. If randSource exhausts the
// data []byte, it start returning zeros.
type randSource struct {
	data []byte // data is the remaining byte stream to use for random values.
}

func (s *randSource) Uint64() uint64 {
	if len(s.data) >= 8 {
		valBytes := s.data[:8]
		s.data = s.data[8:]
		return binary.LittleEndian.Uint64(valBytes)
	} else if len(s.data) > 0 {
		grab := len(s.data) // will be < 8
		valBytes := s.data[:grab]
		s.data = s.data[grab:]
		var val uint64
		for i, b := range valBytes {
			val |= uint64(b) << uint64(i*8)
		}
		return val
	}

	// we are out of bytes in our input stream.
	// fall back to zero.
	return 0
}

// Byte returns one byte, consuming only one byte of our input data.
// This is not part of rand.Source64 interface, but useful
// in our custom fuzzing functions so that we don't waste input
// bytes in the data []byte we receive from go-fuzz.
func (s *randSource) Byte() byte {
	if len(s.data) > 0 {
		val := s.data[0]
		s.data = s.data[1:]
		return val
	}
	// we are out of bytes in our input stream.
	// fall back to zero.
	return 0
}

// Int63 is needed for rand.Source64 interface.
func (s *randSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

// Seed is needed for rand.Source64 interface.
// It is a no-op for this package.
func (s *randSource) Seed(seed int64) {
	// no-op
}
