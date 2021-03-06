package resource

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/skythen/gobalplatform/internal/util"
)

func TestParseExtendedCardResourcesInformation(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    *ExtendedCardResourcesInformation
		expectError bool
	}{
		{
			name:       "memory encoded on 4 bytes",
			inputBytes: []byte{0xFF, 0x21, 0x10, 0x81, 0x02, 0x00, 0x01, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected: &ExtendedCardResourcesInformation{
				InstalledApplications: 1,
				FreeNVM:               175236,
				FreeVM:                15807,
			},
			expectError: false,
		},
		{
			name:       "memory encoded on 2 bytes",
			inputBytes: []byte{0xFF, 0x21, 0x0E, 0x81, 0x02, 0x00, 0xFF, 0x82, 0x02, 0x00, 0x02, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected: &ExtendedCardResourcesInformation{
				InstalledApplications: 255,
				FreeNVM:               2,
				FreeVM:                15807,
			},
			expectError: false,
		},
		{
			name:       "memory encoded on 1 bytes",
			inputBytes: []byte{0xFF, 0x21, 0x0D, 0x81, 0x02, 0x00, 0xFF, 0x82, 0x01, 0x02, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected: &ExtendedCardResourcesInformation{
				InstalledApplications: 255,
				FreeNVM:               2,
				FreeVM:                15807,
			},
			expectError: false,
		},
		{
			name:       "memory encoded on 8 bytes",
			inputBytes: []byte{0xFF, 0x21, 0x14, 0x81, 0x02, 0x00, 0xFF, 0x82, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected: &ExtendedCardResourcesInformation{
				InstalledApplications: 255,
				FreeNVM:               255,
				FreeVM:                15807,
			},
			expectError: false,
		},
		{
			name:        "Error: invalid BER-TLV ",
			inputBytes:  []byte{0xFF, 0x21, 0x20, 0x81, 0x02, 0x00, 0xFF, 0x82, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid encoding of free memory ",
			inputBytes:  []byte{0xFF, 0x21, 0x15, 0x81, 0x02, 0x00, 0xFF, 0x82, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: missing tag FF21",
			inputBytes:  []byte{0xFF, 0x22, 0x10, 0x81, 0x02, 0x00, 0x01, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: missing tag 81",
			inputBytes:  []byte{0xFF, 0x21, 0x10, 0x80, 0x02, 0x00, 0x01, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid encoding of number of applications",
			inputBytes:  []byte{0xFF, 0x21, 0x11, 0x81, 0x03, 0x00, 0x01, 0x02, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: missing tag 82",
			inputBytes:  []byte{0xFF, 0x21, 0x10, 0x81, 0x02, 0x00, 0x01, 0x83, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: missing tag 83",
			inputBytes:  []byte{0xFF, 0x21, 0x10, 0x81, 0x02, 0x00, 0x01, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x84, 0x04, 0x00, 0x00, 0x3D, 0xBF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid encoding of free volatile memory ",
			inputBytes:  []byte{0xFF, 0x21, 0x11, 0x81, 0x02, 0x00, 0x01, 0x82, 0x04, 0x00, 0x02, 0xAC, 0x84, 0x83, 0x05, 0x00, 0x00, 0x3D, 0xBF, 0x01},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseExtendedCardResourcesInformation(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseKeyInformationTemplate(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    *KeyInformationTemplate
		expectError bool
	}{
		{
			name:       "valid Information Template, mixed basic and extended key information",
			inputBytes: []byte{0xE0, 0x21, 0xC0, 0x06, 0x01, 0xFF, 0x80, 0x10, 0x81, 0x10, 0xC0, 0x05, 0x02, 0xFF, 0xF0, 0x10, 0x11, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x01, 0xBB},
			expected: &KeyInformationTemplate{
				{
					Basic: KeyInformationData{
						ID:            0x01,
						VersionNumber: 0xFF,
						Components: []KeyComponent{
							{
								Type:                    0x80,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
							{
								Type:                    0x81,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: nil,
				},
				{
					Basic: KeyInformationData{
						ID:            0x02,
						VersionNumber: 0xFF,
						Components: []KeyComponent{
							{
								Type:                    0xF0,
								Length:                  0,
								ParameterReferenceValue: []byte{0x10, 0x11},
							},
						},
					},
					Extended: nil,
				},
				{
					Basic: KeyInformationData{
						ID:            0x03,
						VersionNumber: 0x01,
						Components: []KeyComponent{
							{
								Type:                    0x80,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: nil,
				},
				{
					Basic: KeyInformationData{
						ID:            0x04,
						VersionNumber: 0x01,
						Components: []KeyComponent{
							{
								Type:                    0x03,
								Length:                  3,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: &ExtendedKeyData{
						KeyUsage: UsageQualifierInfo{
							Verification:               true,
							Computation:                true,
							SecureMessagingResponse:    true,
							SecureMessagingCommand:     true,
							Confidentiality:            true,
							CryptographicChecksum:      true,
							DigitalSignature:           true,
							CryptographicAuthorization: true,
						},
						KeyAccess: 0xBB,
					},
				},
			},
			expectError: false,
		},
		{
			name:       "Basic Reference",
			inputBytes: []byte{0xE0, 0x12, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0xFF, 0x80, 0x10},
			expected: &KeyInformationTemplate{
				{
					Basic: KeyInformationData{
						ID:            0x01,
						VersionNumber: 0xFF,
						Components: []KeyComponent{
							{
								Type:                    0x80,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: nil,
				},
				{
					Basic: KeyInformationData{
						ID:            0x02,
						VersionNumber: 0xFF,
						Components: []KeyComponent{
							{
								Type:                    0x80,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: nil,
				},
				{
					Basic: KeyInformationData{
						ID:            0x03,
						VersionNumber: 0xFF,
						Components: []KeyComponent{
							{
								Type:                    0x80,
								Length:                  16,
								ParameterReferenceValue: nil,
							},
						},
					},
					Extended: nil,
				},
			},
			expectError: false,
		},
		{
			name:        "Error: length of extended component exceeds 0x7FFF",
			inputBytes:  []byte{0xE0, 0x1F, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x05, 0x02, 0xFF, 0xF0, 0x10, 0x11, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0xFF, 0xFF, 0x01, 0xFF, 0x01, 0xBB},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: key parameter reference invalid value length",
			inputBytes:  []byte{0xE0, 0x20, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x06, 0x02, 0xFF, 0xF0, 0xCC, 0xDD, 0xEE, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x01, 0xBB},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid key usage length",
			inputBytes:  []byte{0xE0, 0x1E, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x03, 0xFF, 0x01, 0xBB},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: key usage value not present",
			inputBytes:  []byte{0xE0, 0x1B, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x07, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: key usage present but key access missing",
			inputBytes:  []byte{0xE0, 0x1C, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x08, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid key access length",
			inputBytes:  []byte{0xE0, 0x1E, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x03, 0xBB},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: key access value not present",
			inputBytes:  []byte{0xE0, 0x1D, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x02, 0xFF, 0x80, 0x10, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x09, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x01},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid BER-TLV",
			inputBytes:  []byte{0xE0, 0x07, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: missing tag 'E0",
			inputBytes:  []byte{0xE1, 0x06, 0xC0, 0x04, 0x01, 0xFF, 0x80, 0x10},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid basic component length",
			inputBytes:  []byte{0xE0, 0x05, 0xC0, 0x03, 0x01, 0xFF, 0x80},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid extended component length",
			inputBytes:  []byte{0xE0, 0x06, 0xC0, 0x04, 0x01, 0xFF, 0xFF, 0x10},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: extended component has no key usage",
			inputBytes:  []byte{0xE0, 0x22, 0xC0, 0x06, 0x01, 0xFF, 0x80, 0x10, 0x81, 0x10, 0xC0, 0x06, 0x02, 0xFF, 0xFF, 0x03, 0x10, 0x11, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x01, 0xBB},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: mixing basic and extended components",
			inputBytes:  []byte{0xE0, 0x22, 0xC0, 0x07, 0x01, 0xFF, 0x80, 0x10, 0xFF, 0x03, 0x10, 0xC0, 0x05, 0x02, 0xFF, 0xF0, 0x10, 0x11, 0xC0, 0x04, 0x03, 0x01, 0x80, 0x10, 0xC0, 0x0A, 0x04, 0x01, 0xFF, 0x03, 0x00, 0x03, 0x01, 0xFF, 0x01, 0xBB},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseKeyInformationTemplate(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseUsageQualifier(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *UsageQualifierInfo
	}{
		{
			name:      "All Usages",
			inputByte: 0xFF,
			expected: &UsageQualifierInfo{
				Verification:               true,
				Computation:                true,
				SecureMessagingResponse:    true,
				SecureMessagingCommand:     true,
				Confidentiality:            true,
				CryptographicChecksum:      true,
				DigitalSignature:           true,
				CryptographicAuthorization: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseUsageQualifier(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
