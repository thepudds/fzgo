package fuzztime

import "time"

// FuzzTime is a very simple fuzzing function
func FuzzTime(data []byte) int {

	_, err := time.ParseDuration(string(data))

	if err != nil {
		return 1
	}
	return 0
}
