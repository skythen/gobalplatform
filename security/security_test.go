package security

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/skythen/gobalplatform/internal/util"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name        string
		inputByte   byte
		expected    *Level
		expectError bool
	}{
		{
			name:      "Authenticated",
			inputByte: 0xB3,
			expected: &Level{
				AuthenticationStatus: Authenticated,
				CDEC:                 true,
				CMAC:                 true,
				RMAC:                 true,
				RENC:                 true,
			},
			expectError: false,
		},
		{
			name:      "Any Authenticated",
			inputByte: 0x41,
			expected: &Level{
				AuthenticationStatus: AnyAuthenticated,
				CDEC:                 false,
				CMAC:                 true,
				RMAC:                 false,
				RENC:                 false,
			},
			expectError: false,
		},
		{
			name:        "Error: Authenticated and Any Authenticated",
			inputByte:   0xC1,
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseLevel(tc.inputByte)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestLevel_Byte(t *testing.T) {
	tests := []struct {
		name          string
		securityLevel Level
		expected      byte
	}{
		{
			name: "Authenticated",
			securityLevel: Level{
				AuthenticationStatus: Authenticated,
				CDEC:                 true,
				CMAC:                 true,
				RMAC:                 true,
				RENC:                 true,
			},
			expected: 0xB3,
		},
		{
			name: "Any Authenticated",
			securityLevel: Level{
				AuthenticationStatus: AnyAuthenticated,
				CDEC:                 false,
				CMAC:                 true,
				RMAC:                 false,
				RENC:                 false,
			},
			expected: 0x41,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.securityLevel.Byte()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseSCP02Parameter(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *SCP02Parameter
	}{
		{
			name:      "all options",
			inputByte: 0xFF,
			expected: &SCP02Parameter{
				ThreeSCKeys:                true,
				CMACOnUnmodifiedAPDU:       true,
				ExplicitInitiation:         true,
				ICVMacOverAID:              true,
				ICVEncryptionForCMAC:       true,
				RMACSupported:              true,
				KnownPseudoRandomAlgorithm: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseSCP02Parameter(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSCP02Parameter_Byte(t *testing.T) {
	tests := []struct {
		name      string
		parameter SCP02Parameter
		expected  byte
	}{
		{
			name: "all options",
			parameter: SCP02Parameter{
				ThreeSCKeys:                true,
				CMACOnUnmodifiedAPDU:       true,
				ExplicitInitiation:         true,
				ICVMacOverAID:              true,
				ICVEncryptionForCMAC:       true,
				RMACSupported:              true,
				KnownPseudoRandomAlgorithm: true,
			},
			expected: 0x7F,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.parameter.Byte()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseSCP03Parameter(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *SCP03Parameter
	}{
		{
			name:      "all options",
			inputByte: 0x70,
			expected: &SCP03Parameter{
				PseudoRandomCardChallenge: true,
				RMACSupport:               true,
				RENCSupport:               true,
			},
		},
		{
			name:      "only rmac",
			inputByte: 0x30,
			expected: &SCP03Parameter{
				PseudoRandomCardChallenge: true,
				RMACSupport:               true,
				RENCSupport:               false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseSCP03Parameter(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSCP03Parameter_Byte(t *testing.T) {
	tests := []struct {
		name      string
		parameter SCP03Parameter
		expected  byte
	}{
		{
			name: "all options",
			parameter: SCP03Parameter{
				PseudoRandomCardChallenge: true,
				RMACSupport:               true,
				RENCSupport:               true,
			},
			expected: 0x70,
		},
		{
			name: "only R-MAC",
			parameter: SCP03Parameter{
				PseudoRandomCardChallenge: false,
				RMACSupport:               true,
				RENCSupport:               false,
			},
			expected: 0x20,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.parameter.Byte()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseSCP10Parameter(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *SCP10Parameter
	}{
		{
			name:      "no options",
			inputByte: 0x00,
			expected: &SCP10Parameter{
				KeyAgreement:                    false,
				SignatureWithoutMessageRecovery: false,
			},
		},
		{
			name:      "all options",
			inputByte: 0x03,
			expected: &SCP10Parameter{
				KeyAgreement:                    true,
				SignatureWithoutMessageRecovery: true,
			},
		},
		{
			name:      "key agreement",
			inputByte: 0x01,
			expected: &SCP10Parameter{
				KeyAgreement:                    true,
				SignatureWithoutMessageRecovery: false,
			},
		},
		{
			name:      "signature without message recovery",
			inputByte: 0x02,
			expected: &SCP10Parameter{
				KeyAgreement:                    false,
				SignatureWithoutMessageRecovery: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseSCP10Parameter(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSCP10Parameter_Byte(t *testing.T) {
	tests := []struct {
		name      string
		parameter SCP10Parameter
		expected  byte
	}{
		{
			name: "no options",
			parameter: SCP10Parameter{
				KeyAgreement:                    false,
				SignatureWithoutMessageRecovery: false,
			},
			expected: 0x00,
		},
		{
			name: "key agreement",
			parameter: SCP10Parameter{
				KeyAgreement:                    true,
				SignatureWithoutMessageRecovery: false,
			},
			expected: 0x01,
		},
		{
			name: "signature without message recovery",
			parameter: SCP10Parameter{
				KeyAgreement:                    false,
				SignatureWithoutMessageRecovery: true,
			},
			expected: 0x02,
		},
		{
			name: "all options",
			parameter: SCP10Parameter{
				KeyAgreement:                    true,
				SignatureWithoutMessageRecovery: true,
			},
			expected: 0x03,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.parameter.Byte()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
