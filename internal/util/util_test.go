package util

import (
	"testing"
)

func TestBuildGPBerLen(t *testing.T) {
	tests := []struct {
		name        string
		inputLength uint
		expected    []byte
		expectError bool
	}{
		{
			name:        "single byte length",
			inputLength: 128,
			expected:    []byte{0x80},
			expectError: false,
		},
		{
			name:        "two byte length",
			inputLength: 129,
			expected:    []byte{0x81, 0x81},
			expectError: false,
		},
		{
			name:        "three byte length",
			inputLength: 258,
			expected:    []byte{0x82, 0x01, 0x02},
			expectError: false,
		},
		{
			name:        "Error: invalid length",
			inputLength: 65536,
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := BuildGPBerLength(tc.inputLength)

			EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}
