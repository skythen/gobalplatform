package open

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
)

func TestParseExecutableLoadFileData(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    []ExecutableLoadFileData
		expectError bool
	}{
		{
			name: "valid",
			inputBytes: []byte{0xE3, 0x24,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected: []ExecutableLoadFileData{
				{
					AID:            aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
					LifeCycleState: LCSElfLoaded,
					VersionNumber:  MajorMinorVersion{Major: 1, Minor: 1},
					EMAIDs: []aid.AID{
						{0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
						{0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
					},
					AssociatedSDAID: aid.AID{0xC1, 0xC2, 0xC3, 0xC4, 0xC5},
				},
			},
			expectError: false,
		},
		{
			name: "Error: invalid BER-TLV",
			inputBytes: []byte{0xE3, 0x23,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing registry related data tag",
			inputBytes: []byte{0xE4, 0x24,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing aid.AID tag",
			inputBytes: []byte{0xE3, 0x24,
				0x4E, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid aid.AID",
			inputBytes: []byte{0xE3, 0x23,
				0x4F, 0x04, 0x01, 0x02, 0x03, 0x04,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing LCS tag",
			inputBytes: []byte{0xE3, 0x24,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x71, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid LCS",
			inputBytes: []byte{0xE3, 0x25,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x03, 0x01, 0x02, 0x03,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing ELF version tag",
			inputBytes: []byte{0xE3, 0x24,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCD, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid ELF version",
			inputBytes: []byte{0xE3, 0x25,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x03, 0x01, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid EM aid.AID",
			inputBytes: []byte{0xE3, 0x23,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x04, 0xA1, 0xA2, 0xA3, 0xA4,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing SD AID tag",
			inputBytes: []byte{0xE3, 0x24,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCD, 0x05, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid SD AID",
			inputBytes: []byte{0xE3, 0x23,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x01,
				0xCE, 0x02, 0x01, 0x01,
				0x84, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0x84, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
				0xCC, 0x04, 0xC1, 0xC2, 0xC3, 0xC4,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseExecutableLoadFileData(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseApplicationData(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    []ApplicationData
		expectError bool
	}{
		{
			name: "valid",
			inputBytes: []byte{0xE3, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected: []ApplicationData{
				{
					AID:            aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
					LifeCycleState: LCSApplicationSelectable,
					Privileges:     Privileges{CVMManagement, GlobalRegistry},
					ImplicitSelectionParameters: []ImplicitSelectionParameters{
						{
							ContactlessIO:  true,
							ContactIO:      true,
							LogicalChannel: 6,
						},
					},
					ELFAID:                      aid.AID{0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
					AssociatedSecurityDomainAID: aid.AID{0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
				},
			},
			expectError: false,
		},
		{
			name: "Error: invalid BER-TLV",
			inputBytes: []byte{0xE3, 0x22,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing registry related data tag",
			inputBytes: []byte{0xE4, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing AID tag",
			inputBytes: []byte{0xE3, 0x21,
				0x4E, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid aid.AID",
			inputBytes: []byte{0xE3, 0x20,
				0x4F, 0x04, 0x01, 0x02, 0x03, 0x04,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing LCS",
			inputBytes: []byte{0xE3, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x71, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid LCS",
			inputBytes: []byte{0xE3, 0x23,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x03, 0x07, 0x08, 0x09,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing Privileges",
			inputBytes: []byte{0xE3, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC9, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid Privileges",
			inputBytes: []byte{0xE3, 0x22,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x04, 0x02, 0x04, 0x00, 0x05,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid Implicit Selection Parameters",
			inputBytes: []byte{0xE3, 0x22,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x02, 0xC6, 0x01,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing ELF AID",
			inputBytes: []byte{0xE3, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xD4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid ELF AID",
			inputBytes: []byte{0xE3, 0x20,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x04, 0xA1, 0xA2, 0xA3, 0xA4,
				0xCC, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: missing SD AID",
			inputBytes: []byte{0xE3, 0x21,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCD, 0x05, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid SD AID",
			inputBytes: []byte{0xE3, 0x20,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x9F, 0x70, 0x01, 0x07,
				0xC5, 0x03, 0x02, 0x04, 0x00,
				0xCF, 0x01, 0xC6,
				0xC4, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
				0xCC, 0x04, 0xB1, 0xB2, 0xB3, 0xB4,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseApplicationData(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseRestrictParameter(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *Restrict
	}{
		{
			name:      "restrict all",
			inputByte: 0x7F,
			expected: &Restrict{
				RegistryUpdate:  true,
				Personalization: true,
				Extradition:     true,
				MakeSelectable:  true,
				Install:         true,
				Load:            true,
				Delete:          true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseRestrictParameter(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRestrict_Byte(t *testing.T) {
	tests := []struct {
		name     string
		restrict Restrict
		expected byte
	}{
		{
			name: "convert",
			restrict: Restrict{
				RegistryUpdate:  true,
				Personalization: true,
				Extradition:     true,
				MakeSelectable:  true,
				Install:         true,
				Load:            true,
				Delete:          true,
			},
			expected: 0x7F,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.restrict.Byte()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseImplicitSelectionParameters(t *testing.T) {
	tests := []struct {
		name      string
		inputByte byte
		expected  *ImplicitSelectionParameters
	}{
		{
			name:      "valid",
			inputByte: 0xC6,
			expected: &ImplicitSelectionParameters{
				ContactlessIO:  true,
				ContactIO:      true,
				LogicalChannel: 6,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParseImplicitSelectionParameters(tc.inputByte)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParsePrivileges(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  [3]byte
		expected    Privileges
		expectError bool
	}{
		{
			name:       "three byte privileges (DAP Verification)",
			inputBytes: [3]byte{0xFE, 0xFF, 0xF8},
			expected: Privileges{
				SecurityDomain,
				DAPVerification,
				DelegatedManagement,
				CardLock,
				CardTerminate,
				CardReset,
				CVMManagement,
				TrustedPath,
				AuthorizedManagement,
				TokenVerification,
				GlobalDelete,
				GlobalLock,
				GlobalRegistry,
				FinalApplication,
				GlobalService,
				ReceiptGeneration,
				CipheredLoadFileDataBlock,
				ContactlessActivation,
				ContactlessSelfActivation,
				PrivacyTrusted,
			},
			expectError: false,
		}, {
			name:       "three byte privileges (Mandated DAP Verification)",
			inputBytes: [3]byte{0xFF, 0xFF, 0xF0},
			expected: Privileges{
				SecurityDomain,
				MandatedDAPVerification,
				DelegatedManagement,
				CardLock,
				CardTerminate,
				CardReset,
				CVMManagement,
				TrustedPath,
				AuthorizedManagement,
				TokenVerification,
				GlobalDelete,
				GlobalLock,
				GlobalRegistry,
				FinalApplication,
				GlobalService,
				ReceiptGeneration,
				CipheredLoadFileDataBlock,
				ContactlessActivation,
				ContactlessSelfActivation,
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ParsePrivileges(tc.inputBytes)

			cmp.Equal(received, tc.expected)
		})
	}
}

func TestPrivileges_Bytes(t *testing.T) {
	tests := []struct {
		name        string
		input       Privileges
		expected    []byte
		expectError bool
	}{
		{
			name: "convert to bytes (DAP Verification)",
			input: Privileges{
				SecurityDomain,
				DAPVerification,
				CardLock,
				CardTerminate,
				CardReset,
				CVMManagement,
				TrustedPath,
				AuthorizedManagement,
				TokenVerification,
				GlobalDelete,
				GlobalLock,
				GlobalRegistry,
				FinalApplication,
				GlobalService,
				ReceiptGeneration,
				CipheredLoadFileDataBlock,
				ContactlessActivation,
				ContactlessSelfActivation,
				PrivacyTrusted,
			},
			expected:    []byte{0xDE, 0xFF, 0xF8},
			expectError: false,
		},
		{
			name: "convert to bytes (Mandated DAP Verification)",
			input: Privileges{
				SecurityDomain,
				MandatedDAPVerification,
				DelegatedManagement,
				CardLock,
				CardTerminate,
				CardReset,
				CVMManagement,
				TrustedPath,
				AuthorizedManagement,
				TokenVerification,
				GlobalDelete,
				GlobalLock,
				GlobalRegistry,
				FinalApplication,
				GlobalService,
				ReceiptGeneration,
				CipheredLoadFileDataBlock,
				ContactlessActivation,
				ContactlessSelfActivation,
			},
			expected:    []byte{0xFF, 0xFF, 0xF0},
			expectError: false,
		},
		{
			name: "one byte",
			input: Privileges{
				SecurityDomain,
				DAPVerification,
				CardLock,
				CardTerminate,
				CardReset,
				CVMManagement,
				TrustedPath,
				AuthorizedManagement,
				TokenVerification,
				GlobalDelete,
				GlobalLock,
				GlobalRegistry,
				FinalApplication,
				GlobalService,
				ReceiptGeneration,
				CipheredLoadFileDataBlock,
				ContactlessActivation,
				ContactlessSelfActivation,
				PrivacyTrusted,
			},
			expected:    []byte{0xDE, 0xFF, 0xF8},
			expectError: false,
		},
		{
			name: "set b7 for Delegated Management",
			input: Privileges{
				DelegatedManagement,
			},
			expected:    []byte{0xA0, 0x00, 0x00},
			expectError: false,
		},
		{
			name: "Error: both DAP Verification and Mandated DAP Verification",
			input: Privileges{
				DAPVerification,
				MandatedDAPVerification,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: both DAP Verification and Mandated DAP Verification",
			input: Privileges{
				MandatedDAPVerification,
				DAPVerification,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.input.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}
