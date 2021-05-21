package dgi

import (
	"testing"

	"gobalplatform/internal/util"
)

func TestDGI_Bytes(t *testing.T) {
	upperBound1BData := make([]byte, 254)
	lowerBound3BData := make([]byte, 255)
	upperBound3BData := make([]byte, 65534)
	invalidSize := make([]byte, 65535)

	tests := []struct {
		name        string
		dgi         DGI
		expected    []byte
		expectError bool
	}{
		{
			name: "upper bound 1B length",
			dgi: DGI{
				DGI:   [2]byte{0x80, 0x81},
				Value: upperBound1BData,
			},
			expected:    append([]byte{0x80, 0x81, 0xFE}, upperBound1BData...),
			expectError: false,
		},
		{
			name: "lower bound 3B length",
			dgi: DGI{
				DGI:   [2]byte{0x80, 0x81},
				Value: lowerBound3BData,
			},
			expected:    append([]byte{0x80, 0x81, 0xFF, 0x00, 0xFF}, lowerBound3BData...),
			expectError: false,
		},
		{
			name: "upper bound 3B length",
			dgi: DGI{
				DGI:   [2]byte{0x80, 0x81},
				Value: upperBound3BData,
			},
			expected:    append([]byte{0x80, 0x81, 0xFF, 0xFF, 0xFE}, upperBound3BData...),
			expectError: false,
		},
		{
			name: "Error: invalid length",
			dgi: DGI{
				DGI:   [2]byte{0x80, 0x81},
				Value: invalidSize,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.dgi.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}
