package aid

import (
	"bytes"
	"testing"

	"github.com/skythen/gobalplatform/internal/util"
)

func TestParseAID(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    *AID
		expectError bool
	}{
		{
			name:        "valid AID",
			inputBytes:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected:    &AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expectError: false,
		},
		{
			name:        "Error: invalid length, too short",
			inputBytes:  []byte{0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid length, too long",
			inputBytes:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseAID(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestAID_RID(t *testing.T) {
	tests := []struct {
		name     string
		aid      AID
		expected []byte
	}{
		{
			name:     "get RID",
			aid:      AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.aid.RID()

			if !bytes.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestAID_PIX(t *testing.T) {
	tests := []struct {
		name     string
		aid      AID
		expected []byte
	}{
		{
			name:     "get PIX",
			aid:      AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected: []byte{0x06, 0x07},
		},
		{
			name:     "empty PIX",
			aid:      AID{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.aid.PIX()

			if !bytes.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
