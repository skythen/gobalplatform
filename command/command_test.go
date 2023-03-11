package command

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/skythen/apdu"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/open"
)

func TestDeleteCardContent(t *testing.T) {
	tests := []struct {
		name                string
		inputAID            aid.AID
		inputRelatedObjects bool
		inputToken          []byte
		inputSignature      *CRTDigitalSignature
		expected            apdu.Capdu
	}{
		{
			name:                "DELETE related objects, lastOrOnly , no token, no signatures",
			inputAID:            aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputRelatedObjects: true,
			inputToken:          nil,
			inputSignature:      nil,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x80,
				Data: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
		{
			name:                "DELETE no related objects, lastOrOnly, no token, no signature",
			inputAID:            aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputRelatedObjects: false,
			inputToken:          nil,
			inputSignature:      nil,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x00,
				Data: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
		{
			name:                "DELETE related objects, more cmd,with token, with signatures",
			inputAID:            aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputRelatedObjects: true,
			inputToken:          []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputSignature:      &CRTDigitalSignature{SDIdentificationNumber: []byte{0x01, 0x02, 0x03, 0x04}},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x80,
				Data: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x9E, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xB6, 0x06, 0x42, 0x04, 0x01, 0x02, 0x03, 0x04},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := DeleteCardContent(tc.inputRelatedObjects, tc.inputAID, tc.inputToken, tc.inputSignature)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestDeleteRootSecurityDomain(t *testing.T) {
	tests := []struct {
		name           string
		inputAID       aid.AID
		inputToken     []byte
		inputSignature *CRTDigitalSignature
		expected       apdu.Capdu
	}{
		{
			name:           "DELETE no token, no signatures",
			inputAID:       aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputToken:     nil,
			inputSignature: nil,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x00,
				Data: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
		{
			name:           "DELETE with token, with signatures",
			inputAID:       aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputToken:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputSignature: &CRTDigitalSignature{SDIdentificationNumber: []byte{0x01, 0x02, 0x03, 0x04}},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x00,
				Data: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x9E, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xB6, 0x06, 0x42, 0x04, 0x01, 0x02, 0x03, 0x04},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := DeleteRootSecurityDomain(tc.inputAID, tc.inputToken, tc.inputSignature)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestDeleteKey(t *testing.T) {
	tests := []struct {
		name                  string
		inputRelatedObjects   bool
		inputAID              aid.AID
		inputKeyID            util.NullByte
		inputKeyVersionNumber util.NullByte
		expected              apdu.Capdu
	}{
		{
			name:                  "DELETE key",
			inputRelatedObjects:   false,
			inputAID:              aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputKeyID:            util.NullByte{Byte: 0x01, Valid: true},
			inputKeyVersionNumber: util.NullByte{Byte: 0x02, Valid: true},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x00,
				Data: []byte{0xD0, 0x01, 0x01, 0xD2, 0x01, 0x02},
				Ne:   256,
			},
		},
		{
			name:                  "DELETE key with related objects",
			inputRelatedObjects:   true,
			inputAID:              aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputKeyID:            util.NullByte{Byte: 0x01, Valid: true},
			inputKeyVersionNumber: util.NullByte{Byte: 0x02, Valid: true},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE4,
				P1:   0x00,
				P2:   0x80,
				Data: []byte{0xD0, 0x01, 0x01, 0xD2, 0x01, 0x02},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := DeleteKey(tc.inputRelatedObjects, tc.inputKeyID, tc.inputKeyVersionNumber)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestInstallForLoad(t *testing.T) {
	tests := []struct {
		name                       string
		inputP2                    byte
		inputSDAID                 aid.AID
		inputLoadFileAID           aid.AID
		inputLoadFileDataBlockHash []byte
		inputLoadParameters        []byte
		inputToken                 []byte
		expected                   apdu.Capdu
		expectError                bool
	}{
		{
			name:                       "Install [for load], full",
			inputP2:                    InstallP2NoInfo,
			inputLoadFileAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputSDAID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputLoadFileDataBlockHash: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			inputLoadParameters: LoadParameters{
				SystemSpecificParameters: &SystemSpecificParameters{
					LoadFileDataBlockFormatID: util.NullByte{Byte: 5, Valid: true},
				}}.Bytes(),
			inputToken: []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x02,
				P2:   0x00,
				Data: []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x05, 0xEF, 0x03, 0xCD, 0x01, 0x05, 0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne:   256,
			},
			expectError: false,
		},
		{
			name:                       "Install [for load], no LFDBH",
			inputP2:                    InstallP2BeginningOfCombinedProcess,
			inputLoadFileAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputSDAID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputLoadFileDataBlockHash: nil,
			inputLoadParameters:        nil,
			inputToken:                 []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x02,
				P2:   0x01,
				Data: []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x00, 0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne:   256,
			},
			expectError: false,
		},
		{
			name:                       "Error: invalid load parameters length",
			inputP2:                    InstallP2EndOfCombinedProcess,
			inputLoadFileAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputSDAID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputLoadFileDataBlockHash: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			inputLoadParameters: LoadParameters{
				SystemSpecificParameters: &SystemSpecificParameters{
					LoadFileDataBlockParameters: make([]byte, 65536),
				},
				ControlReferenceTemplateForDigitalSignature: nil,
			}.Bytes(),
			inputToken:  []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:    apdu.Capdu{},
			expectError: true,
		},
		{
			name:                       "Error: invalid load token length",
			inputLoadFileAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputSDAID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputLoadFileDataBlockHash: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			inputLoadParameters:        nil,
			inputToken:                 make([]byte, 65536),
			expected:                   apdu.Capdu{},
			expectError:                true,
		},
		{
			name:                       "Error: Install [for load], no params",
			inputLoadFileAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputSDAID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputLoadFileDataBlockHash: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			inputLoadParameters:        nil,
			inputToken:                 []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x02,
				P2:   0x00,
				Data: []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne:   256,
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InstallForLoad(tc.inputP2, tc.inputSDAID, tc.inputLoadFileAID, tc.inputLoadFileDataBlockHash, tc.inputLoadParameters, tc.inputToken)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestInstallForInstall(t *testing.T) {
	tests := []struct {
		name                   string
		inputP2                byte
		inputELFAID            aid.AID
		inputEMAID             aid.AID
		inputAppAID            aid.AID
		inputMakeSelectable    bool
		inputPrivs             open.Privileges
		inputInstallParameters []byte
		inputToken             []byte
		expected               apdu.Capdu
		expectError            bool
	}{
		{
			name:                "Install [for install], not selectable",
			inputP2:             InstallP2NoInfo,
			inputELFAID:         aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputEMAID:          aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputAppAID:         aid.AID{0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
			inputMakeSelectable: false,
			inputPrivs:          open.Privileges{open.ContactlessSelfActivation},
			inputToken:          []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			inputInstallParameters: InstallParameters{
				ApplicationSpecificParameters: []byte{0xAA, 0xFF},
			}.Bytes(),
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x04,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
					0x05, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
					0x03, 0x00, 0x00, 0x10,
					0x04, 0xC9, 0x02, 0xAA, 0xFF,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                "Install [for installation], make selectable",
			inputELFAID:         aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputEMAID:          aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputAppAID:         aid.AID{0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
			inputMakeSelectable: true,
			inputPrivs:          open.Privileges{open.ContactlessSelfActivation},
			inputToken:          []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			inputInstallParameters: InstallParameters{
				ApplicationSpecificParameters: []byte{0xAA, 0xFF},
			}.Bytes(),
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x0C,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
					0x05, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
					0x03, 0x00, 0x00, 0x10,
					0x04, 0xC9, 0x02, 0xAA, 0xFF,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                "Error: invalid parameters length",
			inputELFAID:         aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputEMAID:          aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputAppAID:         aid.AID{0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
			inputMakeSelectable: false,
			inputPrivs:          open.Privileges{open.ContactlessSelfActivation, open.MandatedDAPVerification},
			inputToken:          []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			inputInstallParameters: InstallParameters{
				ApplicationSpecificParameters: make([]byte, 65536),
			}.Bytes(),
			expected:    apdu.Capdu{},
			expectError: true,
		},
		{
			name:                   "Error: invalid token length",
			inputELFAID:            aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputEMAID:             aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputAppAID:            aid.AID{0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
			inputMakeSelectable:    false,
			inputPrivs:             open.Privileges{open.ContactlessSelfActivation, open.MandatedDAPVerification},
			inputToken:             make([]byte, 65536),
			inputInstallParameters: nil,
			expected:               apdu.Capdu{},
			expectError:            true,
		},
		{
			name:                "Error: invalid privileges",
			inputELFAID:         aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputEMAID:          aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputAppAID:         aid.AID{0xEE, 0xDD, 0xCC, 0xBB, 0xAA},
			inputMakeSelectable: false,
			inputPrivs:          open.Privileges{open.ContactlessSelfActivation, open.MandatedDAPVerification, open.DAPVerification},
			inputToken:          []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			inputInstallParameters: InstallParameters{
				ApplicationSpecificParameters: []byte{0xAA, 0xFF},
			}.Bytes(),
			expected:    apdu.Capdu{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InstallForInstall(tc.inputP2, tc.inputMakeSelectable, tc.inputELFAID, tc.inputEMAID, tc.inputAppAID, tc.inputPrivs, tc.inputInstallParameters, tc.inputToken)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestInstallForMakeSelectable(t *testing.T) {
	tests := []struct {
		name                          string
		inputP2                       byte
		inputApplicationAID           aid.AID
		inputPrivs                    open.Privileges
		inputMakeSelectableParameters []byte
		inputToken                    []byte
		expected                      apdu.Capdu
		expectError                   bool
	}{
		{
			name:                          "Install [for make selectable]",
			inputP2:                       InstallP2EndOfCombinedProcess,
			inputApplicationAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputPrivs:                    []open.Privilege{open.ContactlessSelfActivation},
			inputMakeSelectableParameters: nil,
			inputToken:                    []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x08,
				P2:  0x03,
				Data: []byte{0x00, 0x00,
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x03, 0x00, 0x00, 0x10,
					0x00,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                "with parameters",
			inputApplicationAID: aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputPrivs:          []open.Privilege{open.ContactlessSelfActivation},
			inputMakeSelectableParameters: MakeSelectableParameters{
				SystemSpecificParameters: &SystemSpecificParameters{
					ImplicitSelectionParameter: util.NullByte{Byte: 0xFF, Valid: true},
				},
			}.Bytes(),
			inputToken: []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x08,
				P2:  0x00,
				Data: []byte{0x00, 0x00,
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x03, 0x00, 0x00, 0x10,
					0x05, 0xEF, 0x03, 0xCF, 0x01, 0xFF,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                          "Error: invalid privileges",
			inputApplicationAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputPrivs:                    []open.Privilege{open.MandatedDAPVerification, open.DAPVerification},
			inputMakeSelectableParameters: nil,
			inputToken:                    []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:                      apdu.Capdu{},
			expectError:                   true,
		},
		{
			name:                "Error: invalid make selectable parameters",
			inputApplicationAID: aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputPrivs:          []open.Privilege{open.MandatedDAPVerification},
			inputMakeSelectableParameters: MakeSelectableParameters{
				SystemSpecificParameters: nil,
				ControlReferenceTemplateForDigitalSignature: &CRTDigitalSignature{
					SDIdentificationNumber:        make([]byte, 65536),
					SDImageNumber:                 nil,
					ApplicationProviderIdentifier: nil,
					TokenIdentifier:               nil,
				},
			}.Bytes(),
			inputToken:  []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:    apdu.Capdu{},
			expectError: true,
		},
		{
			name:                          "Error: invalid make selectable token",
			inputApplicationAID:           aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputPrivs:                    []open.Privilege{open.MandatedDAPVerification},
			inputMakeSelectableParameters: nil,
			inputToken:                    make([]byte, 65536),
			expected:                      apdu.Capdu{},
			expectError:                   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InstallForMakeSelectable(tc.inputP2, tc.inputApplicationAID, tc.inputPrivs, tc.inputMakeSelectableParameters, tc.inputToken)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestInstallForRegistryUpdate(t *testing.T) {
	tests := []struct {
		name                 string
		inputSDAID           *aid.AID
		inputInstanceAID     *aid.AID
		inputPrivs           *open.Privileges
		inputRegUpdateParams []byte
		inputToken           []byte
		expected             apdu.Capdu
		expectError          bool
	}{
		{
			name:                 "Install [for registry update] last or only installation command",
			inputSDAID:           &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID:     &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:           &open.Privileges{open.ContactlessSelfActivation},
			inputRegUpdateParams: nil,
			inputToken:           []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x40,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
					0x03, 0x00, 0x00, 0x10,
					0x00,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                 "Install [for registry update] more installation cmd",
			inputSDAID:           &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID:     &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:           &open.Privileges{open.ContactlessSelfActivation},
			inputRegUpdateParams: nil,
			inputToken:           []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x40,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
					0x03, 0x00, 0x00, 0x10,
					0x00,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                 "Install [for registry update] more installation cmd",
			inputSDAID:           &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID:     &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:           &open.Privileges{open.ContactlessSelfActivation},
			inputRegUpdateParams: nil,
			inputToken:           []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x40,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
					0x03, 0x00, 0x00, 0x10,
					0x00,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:             "with parameters",
			inputSDAID:       &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID: &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:       &open.Privileges{open.ContactlessSelfActivation},
			inputRegUpdateParams: RegistryUpdateParameters{
				SystemSpecificParameters: &SystemSpecificParameters{
					NonVolatileMemoryMinimumRequirement: []byte{0x0A, 0x0B},
				},
			}.Bytes(),
			inputToken: []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x40,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
					0x03, 0x00, 0x00, 0x10,
					0x06, 0xEF, 0x04, 0xC8, 0x02, 0x0A, 0x0B,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:             "no privileges",
			inputSDAID:       &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID: &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:       nil,
			inputRegUpdateParams: RegistryUpdateParameters{
				SystemSpecificParameters: &SystemSpecificParameters{NonVolatileMemoryMinimumRequirement: []byte{0x0A, 0x0B}}}.Bytes(),
			inputToken: []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x40,
				P2:  0x00,
				Data: []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
					0x00,
					0x06, 0xEF, 0x04, 0xC8, 0x02, 0x0A, 0x0B,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                 "Error: invalid privileges",
			inputSDAID:           &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID:     &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:           &open.Privileges{open.MandatedDAPVerification, open.DAPVerification},
			inputRegUpdateParams: nil,
			inputToken:           []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:             apdu.Capdu{},
			expectError:          true,
		},
		{
			name:             "Error: invalid parameter length",
			inputSDAID:       &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID: &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:       &open.Privileges{open.MandatedDAPVerification},
			inputRegUpdateParams: RegistryUpdateParameters{
				SystemSpecificParameters: nil,
				ControlReferenceTemplateForDigitalSignature: &CRTDigitalSignature{
					SDIdentificationNumber:        make([]byte, 65536),
					SDImageNumber:                 nil,
					ApplicationProviderIdentifier: nil,
					TokenIdentifier:               nil,
				},
			}.Bytes(),
			inputToken:  []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:    apdu.Capdu{},
			expectError: true,
		},
		{
			name:                 "Error: invalid token length",
			inputSDAID:           &aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputInstanceAID:     &aid.AID{0x0A, 0x0B, 0x0C, 0x0D, 0x0E},
			inputPrivs:           &open.Privileges{open.MandatedDAPVerification},
			inputRegUpdateParams: nil,
			inputToken:           make([]byte, 65536),
			expected:             apdu.Capdu{},
			expectError:          true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InstallForRegistryUpdate(tc.inputSDAID, tc.inputInstanceAID, tc.inputPrivs, tc.inputRegUpdateParams, tc.inputToken)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestInstallForPersonalization(t *testing.T) {
	tests := []struct {
		name        string
		inputAppAID aid.AID
		expected    apdu.Capdu
	}{
		{
			name:        "Install [for personalization]",
			inputAppAID: aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x20,
				P2:  0x00,
				Data: []byte{0x00, 0x00,
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x00,
					0x00},
				Ne: 256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := InstallForPersonalization(tc.inputAppAID)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestInstallForExtradition(t *testing.T) {
	tests := []struct {
		name                   string
		inputSDAID             aid.AID
		inputElfOrAppAID       aid.AID
		inputExtraditionParams []byte
		inputToken             []byte
		expected               apdu.Capdu
		expectError            bool
	}{
		{
			name:             "Install [for extradition]",
			inputSDAID:       aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputElfOrAppAID: aid.AID{0xAA, 0xBC, 0xCD, 0xDE, 0xEF},
			inputExtraditionParams: ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &CRTDigitalSignature{
					SDIdentificationNumber: []byte{0x01, 0x02},
				},
			}.Bytes(),
			inputToken: []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x10,
				P2:  0x00,
				Data: []byte{
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0xAA, 0xBC, 0xCD, 0xDE, 0xEF,
					0x00,
					0x06, 0xB6, 0x04, 0x42, 0x02, 0x01, 0x02,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:                   "empty Parameters",
			inputSDAID:             aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputElfOrAppAID:       aid.AID{0xAA, 0xBC, 0xCD, 0xDE, 0xEF},
			inputExtraditionParams: ExtraditionParameters{}.Bytes(),
			inputToken:             []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected: apdu.Capdu{
				Cla: 0x80,
				Ins: 0xE6,
				P1:  0x10,
				P2:  0x00,
				Data: []byte{
					0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x00,
					0x05, 0xAA, 0xBC, 0xCD, 0xDE, 0xEF,
					0x00,
					0x00,
					0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
				Ne: 256,
			},
			expectError: false,
		},
		{
			name:             "Error: invalid parameters length",
			inputSDAID:       aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputElfOrAppAID: aid.AID{0xAA, 0xBC, 0xCD, 0xDE, 0xEF},
			inputExtraditionParams: ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &CRTDigitalSignature{
					SDIdentificationNumber: []byte{0x01, 0x02},
				},
			}.Bytes(),
			inputToken:  make([]byte, 65536),
			expected:    apdu.Capdu{},
			expectError: true,
		},
		{
			name:             "Error: invalid token length",
			inputSDAID:       aid.AID{0x06, 0x07, 0x08, 0x09, 0x0A},
			inputElfOrAppAID: aid.AID{0xAA, 0xBC, 0xCD, 0xDE, 0xEF},
			inputExtraditionParams: ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &CRTDigitalSignature{
					SDIdentificationNumber: make([]byte, 65536),
				},
			}.Bytes(),
			inputToken:  []byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
			expected:    apdu.Capdu{},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InstallForExtradition(tc.inputSDAID, tc.inputElfOrAppAID, tc.inputExtraditionParams, tc.inputToken)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestLoadBlock(t *testing.T) {
	tests := []struct {
		name           string
		inputBlock     []byte
		inputBlockNum  byte
		inputLastBlock bool
		expected       apdu.Capdu
	}{
		{
			name:           "Install [for load]",
			inputBlock:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			inputBlockNum:  0x03,
			inputLastBlock: false,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE8,
				P1:   0x00,
				P2:   0x03,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
		{
			name:           "Install [for load] last block",
			inputBlock:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			inputBlockNum:  0xFF,
			inputLastBlock: true,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE8,
				P1:   0x80,
				P2:   0xFF,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := LoadBlock(tc.inputLastBlock, tc.inputBlockNum, tc.inputBlock)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestGetData(t *testing.T) {
	tests := []struct {
		name         string
		inputP1      byte
		inputP2      byte
		inputCmdData []byte
		expected     apdu.Capdu
	}{
		{
			name:         "GET DATA all access rules ",
			inputP1:      0xFF,
			inputP2:      0x40,
			inputCmdData: nil,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xCA,
				P1:   0xFF,
				P2:   0x40,
				Data: nil,
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := GetData(tc.inputP1, tc.inputP2, tc.inputCmdData)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name                 string
		inputAID             aid.AID
		inputFirstOccurrence bool
		expected             apdu.Capdu
	}{
		{
			name:                 "SELECT first or only occurrence",
			inputAID:             aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputFirstOccurrence: true,
			expected: apdu.Capdu{
				Cla:  0x00,
				Ins:  0xA4,
				P1:   0x04,
				P2:   0x00,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
		{
			name:                 "SELECT next occurrence",
			inputAID:             aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
			inputFirstOccurrence: false,
			expected: apdu.Capdu{
				Cla:  0x00,
				Ins:  0xA4,
				P1:   0x04,
				P2:   0x02,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := Select(tc.inputFirstOccurrence, tc.inputAID)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestManageChannelOpenNextLogicalChannel(t *testing.T) {
	tests := []struct {
		name           string
		inputChannelID byte
		expected       apdu.Capdu
	}{
		{
			name:           "MANAGE CHANNEL open logical channel",
			inputChannelID: 0x03,
			expected: apdu.Capdu{
				Cla:  0x00,
				Ins:  0x70,
				P1:   0x00,
				P2:   0x03,
				Data: nil,
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ManageChannelOpen(tc.inputChannelID)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestManageChannelCloseLogicalChannel(t *testing.T) {
	tests := []struct {
		name           string
		inputChannelID byte
		expected       apdu.Capdu
	}{
		{
			name:           "MANAGE CHANNEL close logical channel",
			inputChannelID: 0x03,
			expected: apdu.Capdu{
				Cla:  0x00,
				Ins:  0x70,
				P1:   0x80,
				P2:   0x03,
				Data: nil,
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := ManageChannelClose(tc.inputChannelID)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestPutKey(t *testing.T) {
	tests := []struct {
		name               string
		inputNewKeys       bool
		inputMultipleKeys  bool
		inputKeyData       []byte
		inputKeyVersionNum byte
		inputKeyID         byte
		expected           apdu.Capdu
	}{
		{
			name:               "PUT KEY, single key, more cmd",
			inputMultipleKeys:  false,
			inputKeyData:       []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputKeyVersionNum: 0x30,
			inputKeyID:         0x20,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xD8,
				P1:   0x30,
				P2:   0x20,
				Data: []byte{0x30, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
		{
			name:               "PUT KEY, single key, no more cmd",
			inputMultipleKeys:  false,
			inputKeyData:       []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputKeyVersionNum: 0x30,
			inputKeyID:         0x20,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xD8,
				P1:   0x30,
				P2:   0x20,
				Data: []byte{0x30, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
		{
			name:               "PUT KEY, multiple sessionKeys, more cmd",
			inputMultipleKeys:  true,
			inputKeyData:       []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputKeyVersionNum: 0x30,
			inputKeyID:         0x20,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xD8,
				P1:   0x30,
				P2:   0xA0,
				Data: []byte{0x30, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
		{
			name:               "PUT KEY, multiple sessionKeys, no more cmd",
			inputMultipleKeys:  true,
			inputKeyData:       []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputKeyVersionNum: 0x30,
			inputKeyID:         0x20,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xD8,
				P1:   0x30,
				P2:   0xA0,
				Data: []byte{0x30, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := PutKey(tc.inputNewKeys, tc.inputMultipleKeys, tc.inputKeyData, tc.inputKeyVersionNum, tc.inputKeyID)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestGetStatus(t *testing.T) {
	tests := []struct {
		name      string
		inputP1   byte
		inputData []byte
		inputNext bool
		expected  apdu.Capdu
	}{
		{
			name:      "GET STATUS ISD",
			inputP1:   0x80,
			inputData: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
			inputNext: false,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xF2,
				P1:   0x80,
				P2:   0x02,
				Data: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
				Ne:   256,
			},
		},
		{
			name:      "GET STATUS next",
			inputP1:   0x80,
			inputData: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
			inputNext: true,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xF2,
				P1:   0x80,
				P2:   0x03,
				Data: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := GetStatus(tc.inputP1, tc.inputNext, tc.inputData)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestGetStatusCRS(t *testing.T) {
	tests := []struct {
		name      string
		inputP1   byte
		inputData []byte
		inputNext bool
		expected  apdu.Capdu
	}{
		{
			name:      "GET STATUS CRS Applications",
			inputP1:   0x40,
			inputData: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
			inputNext: false,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xF2,
				P1:   0x40,
				P2:   0x00,
				Data: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
				Ne:   256,
			},
		},
		{
			name:      "GET STATUS CRS next",
			inputP1:   0x40,
			inputData: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
			inputNext: true,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xF2,
				P1:   0x40,
				P2:   0x01,
				Data: []byte{0x4F, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := GetStatusCRS(tc.inputP1, tc.inputNext, tc.inputData)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSetStatus(t *testing.T) {
	tests := []struct {
		name      string
		inputP1   byte
		inputP2   byte
		inputData []byte
		expected  apdu.Capdu
	}{
		{
			name:    "SET STATUS Card OP_READY",
			inputP1: 0x80,
			inputP2: 0x01,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xF0,
				P1:   0x80,
				P2:   0x01,
				Data: nil,
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := SetStatus(tc.inputP1, tc.inputP2, tc.inputData)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestStoreData(t *testing.T) {
	tests := []struct {
		name             string
		inputData        []byte
		inputBlockNumber byte
		inputP1          byte
		expected         apdu.Capdu
	}{
		{
			name:             "STORE DATA no CDEC info, no struct info, expect no response data, last",
			inputData:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputBlockNumber: 0x03,
			inputP1:          0x80,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE2,
				P1:   0x80,
				P2:   0x03,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
		{
			name:             "STORE DATA CDEC application dependent, DGI, expect response data, last",
			inputData:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputBlockNumber: 0x01,
			inputP1:          0xA9,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE2,
				P1:   0xA9,
				P2:   0x01,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
		{
			name:             "STORE DATA encrypted data, BER-TLV, expect no response data, more blocks",
			inputData:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			inputBlockNumber: 0xFF,
			inputP1:          0x70,
			expected: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE2,
				P1:   0x70,
				P2:   0xFF,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Ne:   256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := StoreData(tc.inputP1, tc.inputBlockNumber, tc.inputData)
			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestOnLogicalChannel(t *testing.T) {
	tests := []struct {
		name           string
		inputChannelID byte
		inputCla       byte
		expected       byte
	}{
		{
			name:           "channel 0",
			inputChannelID: 0,
			inputCla:       0x80,
			expected:       0x80,
		},
		{
			name:           "channel 1",
			inputChannelID: 1,
			inputCla:       0x80,
			expected:       0x81,
		},
		{
			name:           "channel 3",
			inputChannelID: 3,
			inputCla:       0x80,
			expected:       0x83,
		},
		{
			name:           "channel 4",
			inputChannelID: 4,
			inputCla:       0x80,
			expected:       0xC0,
		},
		{
			name:           "channel 5",
			inputChannelID: 5,
			inputCla:       0x80,
			expected:       0xC1,
		},
		{
			name:           "channel 19",
			inputChannelID: 19,
			inputCla:       0x80,
			expected:       0xCF,
		},
		{
			name:           "channel 20, truncate to 19",
			inputChannelID: 20,
			inputCla:       0x80,
			expected:       0xCF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := OnLogicalChannel(tc.inputChannelID, tc.inputCla)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestAsChain(t *testing.T) {
	firstBlock := make([]byte, 255)
	secondBlock := make([]byte, 255)
	thirdBlock := make([]byte, 168)

	for i := range firstBlock {
		firstBlock[i] = 0xAA
	}

	for i := range secondBlock {
		secondBlock[i] = 0xBB
	}

	for i := range thirdBlock {
		thirdBlock[i] = 0xCC
	}

	data := make([]byte, 0, len(firstBlock)+len(secondBlock)+len(thirdBlock))

	data = append(data, firstBlock...)
	data = append(data, secondBlock...)
	data = append(data, thirdBlock...)

	tests := []struct {
		name       string
		inputCapdu apdu.Capdu
		expected   []apdu.Capdu
	}{
		{
			name: "1 block CAPDU",
			inputCapdu: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x02,
				P2:   0x01,
				Data: []byte{0x01, 0x02, 0x03},
				Ne:   256,
			},
			expected: []apdu.Capdu{
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x02,
					P2:   0x01,
					Data: []byte{0x01, 0x02, 0x03},
					Ne:   256,
				},
			},
		},
		{
			name: "1 block CAPDU, P1 indicates more blocks",
			inputCapdu: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x82,
				P2:   0x01,
				Data: []byte{0x01, 0x02, 0x03},
				Ne:   256,
			},
			expected: []apdu.Capdu{
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x02,
					P2:   0x01,
					Data: []byte{0x01, 0x02, 0x03},
					Ne:   256,
				},
			},
		},
		{
			name: "3 block CAPDU",
			inputCapdu: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x02,
				P2:   0x01,
				Data: data,
				Ne:   256,
			},
			expected: []apdu.Capdu{
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x82,
					P2:   0x01,
					Data: firstBlock,
					Ne:   256,
				},
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x82,
					P2:   0x01,
					Data: secondBlock,
					Ne:   256,
				},
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x02,
					P2:   0x01,
					Data: thirdBlock,
					Ne:   256,
				},
			},
		},
		{
			name: "3 block CAPDU, P1 indicates more blocks",
			inputCapdu: apdu.Capdu{
				Cla:  0x80,
				Ins:  0xE6,
				P1:   0x82,
				P2:   0x01,
				Data: data,
				Ne:   256,
			},
			expected: []apdu.Capdu{
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x82,
					P2:   0x01,
					Data: firstBlock,
					Ne:   256,
				},
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x82,
					P2:   0x01,
					Data: secondBlock,
					Ne:   256,
				},
				{
					Cla:  0x80,
					Ins:  0xE6,
					P1:   0x02,
					P2:   0x01,
					Data: thirdBlock,
					Ne:   256,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := AsChain(tc.inputCapdu)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestResponseStatus_ToString(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus ResponseStatus
		expected       string
		expectError    bool
	}{
		{
			name: "Convert to string",
			responseStatus: ResponseStatus{
				SW:          "6581",
				Description: "[Delete] Memory failure",
			},
			expected: "SW: 6581 Description: [Delete] Memory failure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.responseStatus.ToString()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestAppendSWDetails(t *testing.T) {
	tests := []struct {
		name        string
		inputString string
		inputINS    byte
		inputRapdu  apdu.Rapdu
		expected    string
	}{
		{
			name:        "Append",
			inputString: "some string",
			inputINS:    0xE4,
			inputRapdu: apdu.Rapdu{
				SW1: 0x65,
				SW2: 0x81,
			},
			expected: "some string - SW: 6581 Description: [Delete] Memory failure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := AppendSWDetails(tc.inputString, tc.inputINS, tc.inputRapdu)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestLookupError(t *testing.T) {
	tests := []struct {
		name        string
		inputRapdu  apdu.Rapdu
		inputINS    byte
		expected    ResponseStatus
		expectError bool
	}{
		{
			name: "Delete 0x6581",
			inputRapdu: apdu.Rapdu{
				SW1: 0x65,
				SW2: 0x81,
			},
			inputINS: 0xE4,
			expected: ResponseStatus{
				SW:          "6581",
				Description: "[Delete] Memory failure",
			},
		}, {
			name: "Delete 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xE4,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[Delete] Referenced data not found",
			},
		}, {
			name: "Delete 0x6A82",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x82,
			},
			inputINS: 0xE4,
			expected: ResponseStatus{
				SW:          "6A82",
				Description: "[Delete] Application not found",
			},
		}, {
			name: "Delete 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xE4,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[Delete] Incorrect values in command data",
			},
		}, {
			name: "Get data even 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xCA,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[GetData] Referenced data not found",
			},
		}, {
			name: "Get data odd 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xCB,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[GetData] Referenced data not found",
			},
		}, {
			name: "Get status 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xF2,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[GetStatus] Referenced data not found",
			},
		}, {
			name: "Get status 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xF2,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[GetStatus] Incorrect values in command data",
			},
		}, {
			name: "Install 0x6581",
			inputRapdu: apdu.Rapdu{
				SW1: 0x65,
				SW2: 0x81,
			},
			inputINS: 0xE6,
			expected: ResponseStatus{
				SW:          "6581",
				Description: "[Install] Memory failure",
			},
		}, {
			name: "Install 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xE6,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[Install] Incorrect parameters in data field",
			},
		}, {
			name: "Install 0x6A84",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x84,
			},
			inputINS: 0xE6,
			expected: ResponseStatus{
				SW:          "6A84",
				Description: "[Install] Not enough memory space",
			},
		}, {
			name: "Install 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xE6,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[Install] Referenced data not found",
			},
		}, {
			name: "Load 0x6581",
			inputRapdu: apdu.Rapdu{
				SW1: 0x65,
				SW2: 0x81,
			},
			inputINS: 0xE8,
			expected: ResponseStatus{
				SW:          "6581",
				Description: "[Load] Memory failure",
			},
		}, {
			name: "Load 0x6A84",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x84,
			},
			inputINS: 0xE8,
			expected: ResponseStatus{
				SW:          "6A84",
				Description: "[Load] Not enough memory space",
			},
		}, {
			name: "Manage channel 0x6882",
			inputRapdu: apdu.Rapdu{
				SW1: 0x68,
				SW2: 0x82,
			},
			inputINS: 0x70,
			expected: ResponseStatus{
				SW:          "6882",
				Description: "[ManageChannel] Secure messaging not supported",
			},
		}, {
			name: "Manage channel 0x6A81",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x81,
			},
			inputINS: 0x70,
			expected: ResponseStatus{
				SW:          "6A81",
				Description: "[ManageChannel] Function not supported",
			},
		}, {
			name: "Put key 0x6581",
			inputRapdu: apdu.Rapdu{
				SW1: 0x65,
				SW2: 0x81,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "6581",
				Description: "[PutKey] Memory failure",
			},
		}, {
			name: "Put key 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[PutKey] Wrong data",
			},
		}, {
			name: "Put key 0x6A84",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x84,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "6A84",
				Description: "[PutKey] Not enough memory space",
			},
		}, {
			name: "Put key 0x6A84",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[PutKey] Referenced data not found",
			},
		}, {
			name: "Put key 0x9484",
			inputRapdu: apdu.Rapdu{
				SW1: 0x94,
				SW2: 0x84,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "9484",
				Description: "[PutKey] Algorithm not supported",
			},
		}, {
			name: "Put key 0x9485",
			inputRapdu: apdu.Rapdu{
				SW1: 0x94,
				SW2: 0x85,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "9485",
				Description: "[PutKey] Invalid key check value",
			},
		}, {
			name: "Put key 0x6982",
			inputRapdu: apdu.Rapdu{
				SW1: 0x69,
				SW2: 0x82,
			},
			inputINS: 0xD8,
			expected: ResponseStatus{
				SW:          "6982",
				Description: "[PutKey] Invalid key check value",
			},
		}, {
			name: "Select 0x6882",
			inputRapdu: apdu.Rapdu{
				SW1: 0x68,
				SW2: 0x82,
			},
			inputINS: 0xA4,
			expected: ResponseStatus{
				SW:          "6882",
				Description: "[Select] Secure messaging not supported",
			},
		}, {
			name: "Select 0x6A81",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x81,
			},
			inputINS: 0xA4,
			expected: ResponseStatus{
				SW:          "6A81",
				Description: "[Select] Function not supported",
			},
		}, {
			name: "Select 0x6A82",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x82,
			},
			inputINS: 0xA4,
			expected: ResponseStatus{
				SW:          "6A82",
				Description: "[Select] Selected Application / file not found",
			},
		}, {
			name: "Set status 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xF0,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[SetStatus] Incorrect values in command data",
			},
		}, {
			name: "Set status 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xF0,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[SetStatus] Referenced data not found",
			},
		}, {
			name: "Store data 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0xE2,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[StoreData] Incorrect values in command data",
			},
		}, {
			name: "Store data 0x6A84",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x84,
			},
			inputINS: 0xE2,
			expected: ResponseStatus{
				SW:          "6A84",
				Description: "[StoreData] Not enough memory space",
			},
		}, {
			name: "Store data 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0xE2,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[StoreData] Referenced data not found",
			},
		}, {
			name: "Initialize update 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0x50,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[InitializeUpdate] Referenced data not found",
			},
		}, {
			name: "External authenticate 0x6300",
			inputRapdu: apdu.Rapdu{
				SW1: 0x63,
				SW2: 0x00,
			},
			inputINS: 0x82,
			expected: ResponseStatus{
				SW:          "6300",
				Description: "[ExternalAuthenticate] Authentication of host cryptogram failed",
			},
		}, {
			name: "External authenticate 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0x82,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[ExternalAuthenticate] Referenced data not found",
			},
		}, {
			name: "External authenticate 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x94,
				SW2: 0x84,
			},
			inputINS: 0x82,
			expected: ResponseStatus{
				SW:          "9484",
				Description: "[ExternalAuthenticate] Algorithm not supported",
			},
		}, {
			name: "Begin r-mac session 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0x7A,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[BeginRMACSession] Referenced data not found",
			},
		}, {
			name: "Begin r-mac session 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0x78,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[EndRMACSession] Referenced data not found",
			},
		}, {
			name: "Internal authenticate 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0x88,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[InternalAuthenticate] Incorrect values in command data",
			},
		}, {
			name: "Manage security environment 0x6A88",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x88,
			},
			inputINS: 0x22,
			expected: ResponseStatus{
				SW:          "6A88",
				Description: "[ManageSecurityEnvironment] Referenced data not found",
			},
		}, {
			name: "Manage security environment 0x9484",
			inputRapdu: apdu.Rapdu{
				SW1: 0x94,
				SW2: 0x84,
			},
			inputINS: 0x22,
			expected: ResponseStatus{
				SW:          "9484",
				Description: "[ManageSecurityEnvironment] Algorithm not supported",
			},
		}, {
			name: "Perform security operation 0x6300",
			inputRapdu: apdu.Rapdu{
				SW1: 0x63,
				SW2: 0x00,
			},
			inputINS: 0x2A,
			expected: ResponseStatus{
				SW:          "6300",
				Description: "[PerformSecurityOperation] Verification of the certificate failed",
			},
		}, {
			name: "Perform security operation 0x6883",
			inputRapdu: apdu.Rapdu{
				SW1: 0x68,
				SW2: 0x83,
			},
			inputINS: 0x2A,
			expected: ResponseStatus{
				SW:          "6883",
				Description: "[PerformSecurityOperation] The last command of the chain was expected",
			},
		}, {
			name: "Perform security operation 0x6A80",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x80,
			},
			inputINS: 0x2A,
			expected: ResponseStatus{
				SW:          "6A80",
				Description: "[PerformSecurityOperation] Incorrect values in command data",
			},
		}, {
			name: "General 0x6300",
			inputRapdu: apdu.Rapdu{
				SW1: 0x63,
				SW2: 0x00,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6300",
				Description: "[General] No specific diagnosis",
			},
		}, {
			name: "General 0x6700",
			inputRapdu: apdu.Rapdu{
				SW1: 0x67,
				SW2: 0x00,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6700",
				Description: "[General] Wrong length in Lc",
			},
		}, {
			name: "General 0x6881",
			inputRapdu: apdu.Rapdu{
				SW1: 0x68,
				SW2: 0x81,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6881",
				Description: "[General] Logical channel not supported or is not active",
			},
		}, {
			name: "General 0x6982",
			inputRapdu: apdu.Rapdu{
				SW1: 0x69,
				SW2: 0x82,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6982",
				Description: "[General] Security status not satisfied",
			},
		}, {
			name: "General 0x6985",
			inputRapdu: apdu.Rapdu{
				SW1: 0x69,
				SW2: 0x85,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6985",
				Description: "[General] Conditions of use not satisfied",
			},
		}, {
			name: "General 0x6A86",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6A,
				SW2: 0x86,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6A86",
				Description: "[General] Incorrect P1 P2",
			},
		}, {
			name: "General 0x6D00",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6D,
				SW2: 0x00,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6D00",
				Description: "[General] Invalid instruction",
			},
		}, {
			name: "General 0x6E00",
			inputRapdu: apdu.Rapdu{
				SW1: 0x6E,
				SW2: 0x00,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "6E00",
				Description: "[General] Invalid class",
			},
		},
		{
			name: "Unknown",
			inputRapdu: apdu.Rapdu{
				SW1: 0xFF,
				SW2: 0xFF,
			},
			inputINS: 0xFF,
			expected: ResponseStatus{
				SW:          "FFFF",
				Description: "[Unknown]",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := LookupResponseStatus(tc.inputINS, tc.inputRapdu)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
