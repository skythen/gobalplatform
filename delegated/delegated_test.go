package delegated

import (
	"fmt"
	"testing"

	"github.com/skythen/bertlv"
	"gobalplatform/aid"
	"gobalplatform/command"
	"gobalplatform/internal/util"
	"gobalplatform/open"
)

func TestParseConfirmation(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *Confirmation
		expectError bool
	}{
		{
			name: "1 byte length receipt, no Token identifier, no Token data digest",
			input: []byte{0x10,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x00, 0x03,
				0x02, 0xFF, 0xFE,
			},
			expected: &Confirmation{
				Receipt: []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
				Data: ConfirmationData{
					Counter:         3,
					SDUniqueData:    []byte{0xFF, 0xFE},
					TokenIdentifier: nil,
					TokenDataDigest: nil,
				},
			},
			expectError: false,
		},
		{
			name: "1 byte length receipt, Token identifier, no Token data digest",
			input: []byte{0x10,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x00, 0x03,
				0x02, 0xFF, 0xFE,
				0x03, 0xEE, 0xDD, 0xCC,
			},
			expected: &Confirmation{
				Receipt: []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
				Data: ConfirmationData{
					Counter:         3,
					SDUniqueData:    []byte{0xFF, 0xFE},
					TokenIdentifier: []byte{0xEE, 0xDD, 0xCC},
					TokenDataDigest: nil,
				},
			},
			expectError: false,
		},
		{
			name: "1 byte length receipt, Token identifier, Token data digest",
			input: []byte{0x10,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x00, 0x03,
				0x02, 0xFF, 0xFE,
				0x03, 0xEE, 0xDD, 0xCC,
				0x04, 0xA1, 0xA2, 0xA3, 0xA4,
			},
			expected: &Confirmation{
				Receipt: []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
				Data: ConfirmationData{
					Counter:         3,
					SDUniqueData:    []byte{0xFF, 0xFE},
					TokenIdentifier: []byte{0xEE, 0xDD, 0xCC},
					TokenDataDigest: []byte{0xA1, 0xA2, 0xA3, 0xA4},
				},
			},
			expectError: false,
		},
		{
			name:        "Error: invalid confirmation length",
			input:       []byte{0x81, 0x80, 0x00, 0x00},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid 2 byte length receipt",
			input: []byte{0x81, 0x80,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x00, 0x03,
				0x02, 0xFF, 0xFE,
				0x03, 0xEE, 0xDD, 0xCC,
				0x04, 0xA1, 0xA2, 0xA3, 0xA4,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid length (confirmation data too short)",
			input: []byte{0x81, 0x80,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x00, 0x03,
				0x02,
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: invalid length (confirmation data too short)",
			input:       []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseConfirmationStructure(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateLoadToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)

	nonVolatileCodeMinimumRequirement := []byte{0xCC, 0xCC}
	volatileMemoryQuota := []byte{0xDD, 0xDD}
	nonVolatileMemoryQuota := []byte{0xEE, 0xEE}
	lfdbFormatID := util.NullByte{Byte: 0xCC, Valid: true}
	lfdbParams := []byte{0x01, 0x02}

	elfAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	sdAID := []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5}

	lfdbHash := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}

	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bLoadParametersFirstCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xEF),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0xC6), nonVolatileCodeMinimumRequirement).
				AddBytes(bertlv.NewOneByteTag(0xC7), volatileMemoryQuota).
				AddBytes(bertlv.NewOneByteTag(0xC8), nonVolatileMemoryQuota).
				AddByte(bertlv.NewOneByteTag(0xCD), lfdbFormatID.Byte).
				AddBytes(bertlv.NewOneByteTag(0xDD), lfdbParams).
				Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	oneByteLenTokenData := make([]byte, 0)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(elfAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, elfAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(sdAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, sdAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(lfdbHash)))
	oneByteLenTokenData = append(oneByteLenTokenData, lfdbHash...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bLoadParametersFirstCase)))
	oneByteLenTokenData = append(oneByteLenTokenData, bLoadParametersFirstCase...)

	expectedFirstCase := []byte{command.InstallP1ForLoad, command.InstallP2NoInfo, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	bLoadParametersSecondCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xEF),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0xC6), nonVolatileCodeMinimumRequirement).
				AddBytes(bertlv.NewOneByteTag(0xC7), volatileMemoryQuota).
				AddBytes(bertlv.NewOneByteTag(0xC8), nonVolatileMemoryQuota).
				AddByte(bertlv.NewOneByteTag(0xCD), lfdbFormatID.Byte).
				AddBytes(bertlv.NewOneByteTag(0xDD), lfdbParams).
				Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	threeByteLenTokenData := make([]byte, 0)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(elfAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, elfAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(sdAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, sdAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(lfdbHash)))
	threeByteLenTokenData = append(threeByteLenTokenData, lfdbHash...)
	threeByteLenTokenData = append(threeByteLenTokenData, []byte{0x82, 0x01, 0x28}...)
	threeByteLenTokenData = append(threeByteLenTokenData, bLoadParametersSecondCase...)

	expectedSecondCase := []byte{command.InstallP1ForLoad, command.InstallP2NoInfo, 0x00, 0x01, 0x40}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                string
		inputKey            []byte
		inputDst            []byte
		inputP1             byte
		inputP2             byte
		inputELFAID         aid.AID
		inputSDAID          aid.AID
		inputLfdbh          []byte
		inputLoadParameters command.LoadParameters
		expected            []byte
		expectError         bool
	}{
		{
			name:        "Calculate Token (1B length)",
			inputDst:    make([]byte, len(expectedFirstCase)),
			inputP1:     command.InstallP1ForLoad,
			inputP2:     command.InstallP2NoInfo,
			inputELFAID: elfAID,
			inputSDAID:  sdAID,
			inputLfdbh:  lfdbHash,
			inputLoadParameters: command.LoadParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					LoadFileDataBlockFormatID:           lfdbFormatID,
					LoadFileDataBlockParameters:         lfdbParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			// token inputCapdu data appended with dummy key
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:        "Calculate Token (3B length)",
			inputP1:     command.InstallP1ForLoad,
			inputP2:     command.InstallP2NoInfo,
			inputELFAID: elfAID,
			inputSDAID:  sdAID,
			inputLfdbh:  lfdbHash,
			inputLoadParameters: command.LoadParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					LoadFileDataBlockFormatID:           lfdbFormatID,
					LoadFileDataBlockParameters:         lfdbParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               longTokenIdentifier,
				},
			},
			// token input data appended with dummy key
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:        "Error: Invalid parameter length",
			inputDst:    make([]byte, 0),
			inputP1:     command.InstallP1ForLoad,
			inputP2:     command.InstallP2NoInfo,
			inputELFAID: tooLongAID,
			inputSDAID:  sdAID,
			inputLoadParameters: command.LoadParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					LoadFileDataBlockFormatID:           lfdbFormatID,
					LoadFileDataBlockParameters:         make([]byte, 65536),
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "Error: Invalid token data",
			inputDst:    make([]byte, 0),
			inputP1:     command.InstallP1ForLoad,
			inputP2:     command.InstallP2NoInfo,
			inputELFAID: tooLongAID,
			inputSDAID:  sdAID,
			inputLoadParameters: command.LoadParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					LoadFileDataBlockFormatID:           lfdbFormatID,
					LoadFileDataBlockParameters:         lfdbParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForLoad(tc.inputP1, tc.inputP2, tc.inputELFAID, tc.inputSDAID, tc.inputLfdbh, tc.inputLoadParameters)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateInstallToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)

	elfAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	emAID := []byte{0xB1, 0xB2, 0xB3, 0xB4, 0xB5}
	instanceAID := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

	privs := open.Privileges{open.SecurityDomain, open.AuthorizedManagement, open.DAPVerification, open.ContactlessSelfActivation}

	bPrivs, err := privs.Bytes()
	if err != nil {
		panic(err)
	}

	applicationSpecificParameters := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	volatileMemoryQuota := []byte{0xDD, 0xDD}
	nonVolatileMemoryQuota := []byte{0xEE, 0xEE}
	implicitSelectParams := util.NullByte{Byte: 0xFF, Valid: true}
	globalServiceParams := []byte{0x01, 0x02}
	volatileReservedMemory := []byte{0xFF, 0xFF}
	nonVolatileReservedMemory := []byte{0xFE, 0xFE}
	tsSpecificParameter := []byte{0x11, 0x11}

	tsTemplate := []byte{0x05, 0x04, 0x03, 0x02, 0x01}

	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bInstallParamsFirstCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xC9), applicationSpecificParameters).
		AddBytes(bertlv.NewOneByteTag(0xEA), tsTemplate).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	oneByteLenTokenData := make([]byte, 0)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(elfAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, elfAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(emAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, emAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(instanceAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, instanceAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bPrivs)))
	oneByteLenTokenData = append(oneByteLenTokenData, bPrivs...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bInstallParamsFirstCase)))
	oneByteLenTokenData = append(oneByteLenTokenData, bInstallParamsFirstCase...)

	expectedFirstCase := []byte{command.InstallP1ForInstall, command.InstallP2NoInfo, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	bInstallParamsSecondCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xC9), applicationSpecificParameters).
		AddBytes(bertlv.NewOneByteTag(0xEF),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0xC7), volatileMemoryQuota).
				AddBytes(bertlv.NewOneByteTag(0xC8), nonVolatileMemoryQuota).
				AddBytes(bertlv.NewOneByteTag(0xCB), globalServiceParams).
				AddBytes(bertlv.NewOneByteTag(0xD7), volatileReservedMemory).
				AddBytes(bertlv.NewOneByteTag(0xD8), nonVolatileReservedMemory).
				AddBytes(bertlv.NewOneByteTag(0xCA), tsSpecificParameter).
				AddByte(bertlv.NewOneByteTag(0xCF), implicitSelectParams.Byte).
				Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xEA), tsTemplate).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	threeByteLenTokenData := make([]byte, 0)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(elfAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, elfAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(emAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, emAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(instanceAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, instanceAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(bPrivs)))
	threeByteLenTokenData = append(threeByteLenTokenData, bPrivs...)
	threeByteLenTokenData = append(threeByteLenTokenData, []byte{0x82, 0x01, 0x3D}...)
	threeByteLenTokenData = append(threeByteLenTokenData, bInstallParamsSecondCase...)

	expectedSecondCase := []byte{command.InstallP1ForInstall, command.InstallP2NoInfo, 0x00, 0x01, 0x56}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                   string
		inputKey               []byte
		inputP1                byte
		inputP2                byte
		inputELFAID            aid.AID
		inputEMAID             aid.AID
		inputInstanceAID       aid.AID
		inputPrivileges        open.Privileges
		inputInstallParameters command.InstallParameters
		expected               []byte
		expectError            bool
	}{
		{
			name:             "Calculate Token (1B length)",
			inputP1:          command.InstallP1ForInstall,
			inputP2:          command.InstallP2NoInfo,
			inputELFAID:      elfAID,
			inputEMAID:       emAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputInstallParameters: command.InstallParameters{
				ApplicationSpecificParameters: applicationSpecificParameters,
				TS102226SpecificTemplate:      tsTemplate,
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:             "Calculate Token (3B length)",
			inputP1:          command.InstallP1ForInstall,
			inputP2:          command.InstallP2NoInfo,
			inputELFAID:      elfAID,
			inputEMAID:       emAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputInstallParameters: command.InstallParameters{
				ApplicationSpecificParameters: applicationSpecificParameters,
				SystemSpecificParameters: &command.SystemSpecificParameters{
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					GlobalServiceParameters:             globalServiceParams,
					VolatileReservedMemory:              volatileReservedMemory,
					NonVolatileReservedMemory:           nonVolatileReservedMemory,
					TS102226SpecificParameters:          tsSpecificParameter,
					ImplicitSelectionParameter:          implicitSelectParams,
				}, TS102226SpecificTemplate: tsTemplate,
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               longTokenIdentifier,
				},
			},
			// token inputCapdu data appended with dummy key
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:             "Error: Invalid parameter length",
			inputP1:          command.InstallP1ForInstall,
			inputP2:          0x00,
			inputELFAID:      tooLongAID,
			inputEMAID:       emAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputInstallParameters: command.InstallParameters{
				ApplicationSpecificParameters: make([]byte, 65536),
				SystemSpecificParameters: &command.SystemSpecificParameters{
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					GlobalServiceParameters:             globalServiceParams,
					VolatileReservedMemory:              volatileReservedMemory,
					NonVolatileReservedMemory:           nonVolatileReservedMemory,
					TS102226SpecificParameters:          tsSpecificParameter,
					ImplicitSelectionParameter:          implicitSelectParams,
				}, TS102226SpecificTemplate: tsTemplate,
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: Invalid token data",
			inputP1:          command.InstallP1ForInstall,
			inputP2:          0x00,
			inputELFAID:      tooLongAID,
			inputEMAID:       emAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputInstallParameters: command.InstallParameters{
				ApplicationSpecificParameters: applicationSpecificParameters,
				SystemSpecificParameters: &command.SystemSpecificParameters{
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					GlobalServiceParameters:             globalServiceParams,
					VolatileReservedMemory:              volatileReservedMemory,
					NonVolatileReservedMemory:           nonVolatileReservedMemory,
					TS102226SpecificParameters:          tsSpecificParameter,
					ImplicitSelectionParameter:          implicitSelectParams,
				}, TS102226SpecificTemplate: tsTemplate,
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: invalid Privileges",
			inputP1:          command.InstallP1ForInstall,
			inputP2:          0x00,
			inputELFAID:      elfAID,
			inputEMAID:       emAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  open.Privileges{open.MandatedDAPVerification, open.DAPVerification},
			inputInstallParameters: command.InstallParameters{
				ApplicationSpecificParameters: applicationSpecificParameters,
				SystemSpecificParameters: &command.SystemSpecificParameters{
					VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
					NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
					GlobalServiceParameters:             globalServiceParams,
					VolatileReservedMemory:              volatileReservedMemory,
					NonVolatileReservedMemory:           nonVolatileReservedMemory,
					TS102226SpecificParameters:          tsSpecificParameter,
					ImplicitSelectionParameter:          implicitSelectParams,
				}, TS102226SpecificTemplate: tsTemplate,
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForInstall(tc.inputP1, tc.inputP2, tc.inputELFAID, tc.inputEMAID, tc.inputInstanceAID, tc.inputPrivileges, tc.inputInstallParameters)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateMakeSelectableToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)
	instanceAID := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
	privs := open.Privileges{open.SecurityDomain, open.AuthorizedManagement, open.DAPVerification, open.ContactlessSelfActivation}
	implicitSelectParams := util.NullByte{Byte: 0xFF, Valid: true}
	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bMakeSelectableParamsFirstCase := bertlv.Builder{}.AddBytes(bertlv.NewOneByteTag(0xEF),
		bertlv.Builder{}.
			AddByte(bertlv.NewOneByteTag(0xCF), implicitSelectParams.Byte).
			Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	bPrivs, err := privs.Bytes()
	if err != nil {
		panic(err)
	}

	oneByteLenTokenData := make([]byte, 0)
	oneByteLenTokenData = append(oneByteLenTokenData, 0x00)
	oneByteLenTokenData = append(oneByteLenTokenData, 0x00)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(instanceAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, instanceAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bPrivs)))
	oneByteLenTokenData = append(oneByteLenTokenData, bPrivs...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bMakeSelectableParamsFirstCase)))
	oneByteLenTokenData = append(oneByteLenTokenData, bMakeSelectableParamsFirstCase...)

	expectedFirstCase := []byte{command.InstallP1ForMakeSelectable, command.InstallP2NoInfo, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	bMakeSelectableParamsSecondCase := bertlv.Builder{}.AddBytes(bertlv.NewOneByteTag(0xEF),
		bertlv.Builder{}.
			AddByte(bertlv.NewOneByteTag(0xCF), implicitSelectParams.Byte).
			Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	threeByteLenTokenData := make([]byte, 0)
	threeByteLenTokenData = append(threeByteLenTokenData, 0x00)
	threeByteLenTokenData = append(threeByteLenTokenData, 0x00)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(instanceAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, instanceAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(bPrivs)))
	threeByteLenTokenData = append(threeByteLenTokenData, bPrivs...)
	threeByteLenTokenData = append(threeByteLenTokenData, []byte{0x82, 0x01, 0x18}...)
	threeByteLenTokenData = append(threeByteLenTokenData, bMakeSelectableParamsSecondCase...)

	fmt.Println(len(bMakeSelectableParamsSecondCase))
	fmt.Println(len(threeByteLenTokenData))

	expectedSecondCase := []byte{command.InstallP1ForMakeSelectable, command.InstallP2NoInfo, 0x00, 0x01, 0x27}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                          string
		inputKey                      []byte
		inputP1                       byte
		inputP2                       byte
		inputInstanceAID              aid.AID
		inputPrivileges               open.Privileges
		inputMakeSelectableParameters command.MakeSelectableParameters
		expected                      []byte
		expectError                   bool
	}{
		{
			name:             "Calculate Token (1B length)",
			inputP1:          command.InstallP1ForMakeSelectable,
			inputP2:          0x00,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputMakeSelectableParameters: command.MakeSelectableParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:             "Calculate Token (3B length)",
			inputP1:          command.InstallP1ForMakeSelectable,
			inputP2:          0x00,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputMakeSelectableParameters: command.MakeSelectableParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               longTokenIdentifier,
				},
			},
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:             "Error: Invalid parameter length",
			inputP1:          command.InstallP1ForMakeSelectable,
			inputP2:          0x00,
			inputInstanceAID: tooLongAID,
			inputPrivileges:  privs,
			inputMakeSelectableParameters: command.MakeSelectableParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        make([]byte, 65536),
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: Invalid token data",
			inputP1:          command.InstallP1ForMakeSelectable,
			inputP2:          0x00,
			inputInstanceAID: tooLongAID,
			inputPrivileges:  privs,
			inputMakeSelectableParameters: command.MakeSelectableParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: invalid Privileges",
			inputP1:          command.InstallP1ForMakeSelectable,
			inputP2:          0x00,
			inputInstanceAID: instanceAID,
			inputPrivileges:  open.Privileges{open.DAPVerification, open.MandatedDAPVerification},
			inputMakeSelectableParameters: command.MakeSelectableParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForMakeSelectable(tc.inputP1, tc.inputP2, tc.inputInstanceAID, tc.inputPrivileges, tc.inputMakeSelectableParameters)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateExtraditeToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)

	sdAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	instanceAID := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bExtraditionParamsFirstCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	oneByteLenTokenData := make([]byte, 0)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(sdAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, sdAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, 0x00)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(instanceAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, instanceAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, 0x00)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bExtraditionParamsFirstCase)))
	oneByteLenTokenData = append(oneByteLenTokenData, bExtraditionParamsFirstCase...)

	expectedFirstCase := []byte{command.InstallP1ForForExtradition, command.InstallP2NoInfo, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	bUpdateParamsSecondCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	threeByteLenTokenData := make([]byte, 0)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(sdAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, sdAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, 0x00)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(instanceAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, instanceAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, 0x00)
	threeByteLenTokenData = append(threeByteLenTokenData, []byte{0x82, 0x01, 0x13}...)
	threeByteLenTokenData = append(threeByteLenTokenData, bUpdateParamsSecondCase...)

	expectedSecondCase := []byte{command.InstallP1ForForExtradition, command.InstallP2NoInfo, 0x00, 0x01, 0x24}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                       string
		inputKey                   []byte
		inputP1                    byte
		inputP2                    byte
		inputSDAID                 aid.AID
		inputInstanceAID           aid.AID
		inputExtraditionParameters command.ExtraditionParameters
		expected                   []byte
		expectError                bool
	}{
		{
			name:             "Calculate Token (1B length)",
			inputP1:          command.InstallP1ForForExtradition,
			inputP2:          0x00,
			inputSDAID:       sdAID,
			inputInstanceAID: instanceAID,
			inputExtraditionParameters: command.ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:             "Calculate Token (3B length)",
			inputP1:          command.InstallP1ForForExtradition,
			inputP2:          0x00,
			inputSDAID:       sdAID,
			inputInstanceAID: instanceAID,
			inputExtraditionParameters: command.ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               longTokenIdentifier,
				},
			},
			// token inputCapdu data appended with dummy key
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:             "Error: Invalid parameter length",
			inputP1:          command.InstallP1ForForExtradition,
			inputP2:          0x00,
			inputSDAID:       tooLongAID,
			inputInstanceAID: instanceAID,
			inputExtraditionParameters: command.ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        make([]byte, 65536),
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: Invalid token data",
			inputP1:          command.InstallP1ForForExtradition,
			inputP2:          0x00,
			inputSDAID:       tooLongAID,
			inputInstanceAID: instanceAID,
			inputExtraditionParameters: command.ExtraditionParameters{
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForExtradition(tc.inputP1, tc.inputP2, tc.inputSDAID, tc.inputInstanceAID, tc.inputExtraditionParameters)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateRegistryUpdateToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)

	sdAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	instanceAID := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5}
	privs := open.Privileges{open.SecurityDomain, open.AuthorizedManagement, open.DAPVerification, open.ContactlessSelfActivation}
	implicitSelectParams := util.NullByte{Byte: 0xFF, Valid: true}
	globalServiceParams := []byte{0x01, 0x02}
	restrict := open.Restrict{Load: true, Delete: true}
	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bUpdateParamsFirstCase := bertlv.Builder{}.AddBytes(bertlv.NewOneByteTag(0xEF),
		bertlv.Builder{}.
			AddBytes(bertlv.NewOneByteTag(0xCB), globalServiceParams).
			AddByte(bertlv.NewOneByteTag(0xD9), restrict.Byte()).
			AddByte(bertlv.NewOneByteTag(0xCF), implicitSelectParams.Byte).
			Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	bPrivs, err := privs.Bytes()
	if err != nil {
		panic(err)
	}

	oneByteLenTokenData := make([]byte, 0)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(sdAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, sdAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, 0x00)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(instanceAID)))
	oneByteLenTokenData = append(oneByteLenTokenData, instanceAID...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bPrivs)))
	oneByteLenTokenData = append(oneByteLenTokenData, bPrivs...)
	oneByteLenTokenData = append(oneByteLenTokenData, byte(len(bUpdateParamsFirstCase)))
	oneByteLenTokenData = append(oneByteLenTokenData, bUpdateParamsFirstCase...)

	expectedFirstCase := []byte{command.InstallP1ForRegistryUpdate, command.InstallP2NoInfo, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	bUpdateParamsSecondCase := bertlv.Builder{}.AddBytes(bertlv.NewOneByteTag(0xEF),
		bertlv.Builder{}.
			AddBytes(bertlv.NewOneByteTag(0xCB), globalServiceParams).
			AddByte(bertlv.NewOneByteTag(0xD9), restrict.Byte()).
			AddByte(bertlv.NewOneByteTag(0xCF), implicitSelectParams.Byte).
			Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	threeByteLenTokenData := make([]byte, 0)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(sdAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, sdAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, 0x00)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(instanceAID)))
	threeByteLenTokenData = append(threeByteLenTokenData, instanceAID...)
	threeByteLenTokenData = append(threeByteLenTokenData, byte(len(bPrivs)))
	threeByteLenTokenData = append(threeByteLenTokenData, bPrivs...)
	threeByteLenTokenData = append(threeByteLenTokenData, []byte{0x82, 0x01, 0x1F}...)
	threeByteLenTokenData = append(threeByteLenTokenData, bUpdateParamsSecondCase...)

	expectedSecondCase := []byte{command.InstallP1ForRegistryUpdate, command.InstallP2NoInfo, 0x00, 0x01, 0x33}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                          string
		inputKey                      []byte
		inputP1                       byte
		inputP2                       byte
		inputSDAID                    aid.AID
		inputInstanceAID              aid.AID
		inputPrivileges               open.Privileges
		inputRegistryUpdateParameters command.RegistryUpdateParameters
		expected                      []byte
		expectError                   bool
	}{
		{
			name:             "Calculate Token (1B length)",
			inputP1:          command.InstallP1ForRegistryUpdate,
			inputP2:          0x00,
			inputSDAID:       sdAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputRegistryUpdateParameters: command.RegistryUpdateParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
					GlobalServiceParameters:    globalServiceParams,
					RestrictParameter:          &restrict,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:             "Calculate Token (3B length)",
			inputP1:          command.InstallP1ForRegistryUpdate,
			inputP2:          0x00,
			inputSDAID:       sdAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputRegistryUpdateParameters: command.RegistryUpdateParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
					GlobalServiceParameters:    globalServiceParams,
					RestrictParameter:          &restrict,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               longTokenIdentifier,
				},
			},
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:             "Error: Invalid parameter length",
			inputP1:          command.InstallP1ForRegistryUpdate,
			inputP2:          0x00,
			inputSDAID:       tooLongAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputRegistryUpdateParameters: command.RegistryUpdateParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
					GlobalServiceParameters:    globalServiceParams,
					RestrictParameter:          &restrict,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        make([]byte, 65536),
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: Invalid token data",
			inputP1:          command.InstallP1ForRegistryUpdate,
			inputP2:          0x00,
			inputSDAID:       tooLongAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  privs,
			inputRegistryUpdateParameters: command.RegistryUpdateParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
					GlobalServiceParameters:    globalServiceParams,
					RestrictParameter:          &restrict,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name:             "Error: invalid privs",
			inputP1:          command.InstallP1ForRegistryUpdate,
			inputP2:          0x00,
			inputSDAID:       sdAID,
			inputInstanceAID: instanceAID,
			inputPrivileges:  open.Privileges{open.DAPVerification, open.MandatedDAPVerification},
			inputRegistryUpdateParameters: command.RegistryUpdateParameters{
				SystemSpecificParameters: &command.SystemSpecificParameters{
					ImplicitSelectionParameter: implicitSelectParams,
					GlobalServiceParameters:    globalServiceParams,
					RestrictParameter:          &restrict,
				},
				ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
					SDIdentificationNumber:        sdIDNum,
					SDImageNumber:                 sdImNum,
					ApplicationProviderIdentifier: appProvID,
					TokenIdentifier:               tokenID,
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForRegistryUpdate(tc.inputP1, tc.inputP2, tc.inputSDAID, tc.inputInstanceAID, tc.inputPrivileges, tc.inputRegistryUpdateParameters)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateDeleteToken(t *testing.T) {
	tooLongAID := make([]byte, 16777216)
	longTokenIdentifier := make([]byte, 255)

	objAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	oneByteLenTokenData := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0x4F), objAID).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	expectedFirstCase := []byte{0x00, 0x00, byte(len(oneByteLenTokenData))}
	expectedFirstCase = append(expectedFirstCase, oneByteLenTokenData...)

	threeByteLenTokenData := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0x4F), objAID).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), longTokenIdentifier).
				Bytes()).
		Bytes()

	expectedSecondCase := []byte{0x00, 0x00, 0x00, 0x01, 0x1A}
	expectedSecondCase = append(expectedSecondCase, threeByteLenTokenData...)

	tests := []struct {
		name                string
		inputKey            []byte
		inputP1             byte
		inputP2             byte
		elfOrAppAID         aid.AID
		crtDigitalSignature command.CRTDigitalSignature
		expected            []byte
		expectError         bool
	}{
		{
			name:        "Calculate Token (1B length)",
			inputP1:     0x00,
			inputP2:     0x00,
			elfOrAppAID: objAID,
			crtDigitalSignature: command.CRTDigitalSignature{
				SDIdentificationNumber:        sdIDNum,
				SDImageNumber:                 sdImNum,
				ApplicationProviderIdentifier: appProvID,
				TokenIdentifier:               tokenID,
			},
			expected:    expectedFirstCase,
			expectError: false,
		},
		{
			name:        "Calculate Token (3B length)",
			inputP1:     0x00,
			inputP2:     0x00,
			elfOrAppAID: objAID,
			crtDigitalSignature: command.CRTDigitalSignature{
				SDIdentificationNumber:        sdIDNum,
				SDImageNumber:                 sdImNum,
				ApplicationProviderIdentifier: appProvID,
				TokenIdentifier:               longTokenIdentifier,
			},
			// token inputCapdu data appended with dummy key
			expected:    expectedSecondCase,
			expectError: false,
		},
		{
			name:        "Error: Invalid token data",
			inputP1:     0x00,
			inputP2:     0x00,
			elfOrAppAID: tooLongAID,
			crtDigitalSignature: command.CRTDigitalSignature{
				SDIdentificationNumber:        sdIDNum,
				SDImageNumber:                 sdImNum,
				ApplicationProviderIdentifier: appProvID,
				TokenIdentifier:               tokenID,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForDelete(tc.inputP1, tc.inputP2, tc.elfOrAppAID, tc.crtDigitalSignature)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGenerateLoadInstallAndMakeSelectableToken(t *testing.T) {
	// Install for load
	nonVolatileCodeMinimumRequirement := []byte{0xCC, 0xCC}
	volatileMemoryQuota := []byte{0xDD, 0xDD}
	nonVolatileMemoryQuota := []byte{0xEE, 0xEE}
	lfdbFormatID := util.NullByte{Byte: 0xCC, Valid: true}
	lfdbParams := []byte{0x01, 0x02}

	elfAID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	sdAID := []byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5}

	lfdbHash := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}

	sdIDNum := []byte{0x01, 0x02}
	sdImNum := []byte{0x03, 0x04}
	appProvID := []byte{0x05, 0x06}
	tokenID := []byte{0x07, 0x08}

	bLoadParametersFirstCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xEF),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0xC6), nonVolatileCodeMinimumRequirement).
				AddBytes(bertlv.NewOneByteTag(0xC7), volatileMemoryQuota).
				AddBytes(bertlv.NewOneByteTag(0xC8), nonVolatileMemoryQuota).
				AddByte(bertlv.NewOneByteTag(0xCD), lfdbFormatID.Byte).
				AddBytes(bertlv.NewOneByteTag(0xDD), lfdbParams).
				Bytes()).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	oneByteLenLoadTokenData := make([]byte, 0)
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, byte(len(elfAID)))
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, elfAID...)
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, byte(len(sdAID)))
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, sdAID...)
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, byte(len(lfdbHash)))
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, lfdbHash...)
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, byte(len(bLoadParametersFirstCase)))
	oneByteLenLoadTokenData = append(oneByteLenLoadTokenData, bLoadParametersFirstCase...)

	expected := []byte{command.InstallP1ForLoad, command.InstallP2BeginningOfCombinedProcess, byte(len(oneByteLenLoadTokenData))}
	expected = append(expected, oneByteLenLoadTokenData...)

	// Install for install and make selectable...
	emAID := []byte{0xB1, 0xB2, 0xB3, 0xB4, 0xB5}
	instanceAID := []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

	privs := open.Privileges{open.SecurityDomain, open.AuthorizedManagement, open.DAPVerification, open.ContactlessSelfActivation}

	bPrivs, err := privs.Bytes()
	if err != nil {
		panic(err)
	}

	applicationSpecificParameters := []byte{0xFF, 0xFF, 0xFF, 0xFF}

	tsTemplate := []byte{0x05, 0x04, 0x03, 0x02, 0x01}

	bInstallParamsFirstCase := bertlv.Builder{}.
		AddBytes(bertlv.NewOneByteTag(0xC9), applicationSpecificParameters).
		AddBytes(bertlv.NewOneByteTag(0xEA), tsTemplate).
		AddBytes(bertlv.NewOneByteTag(0xB6),
			bertlv.Builder{}.
				AddBytes(bertlv.NewOneByteTag(0x42), sdIDNum).
				AddBytes(bertlv.NewOneByteTag(0x45), sdImNum).
				AddBytes(bertlv.NewTwoByteTag(0x5F, 0x20), appProvID).
				AddBytes(bertlv.NewOneByteTag(0x93), tokenID).
				Bytes()).
		Bytes()

	oneByteLenInstallTokenData := make([]byte, 0)
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, byte(len(elfAID)))
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, elfAID...)
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, byte(len(emAID)))
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, emAID...)
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, byte(len(instanceAID)))
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, instanceAID...)
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, byte(len(bPrivs)))
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, bPrivs...)
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, byte(len(bInstallParamsFirstCase)))
	oneByteLenInstallTokenData = append(oneByteLenInstallTokenData, bInstallParamsFirstCase...)

	expected = append(expected, []byte{command.InstallP1ForLoadInstallAndMakeSelectable, command.InstallP2EndOfCombinedProcess, byte(len(oneByteLenInstallTokenData))}...)
	expected = append(expected, oneByteLenInstallTokenData...)

	tests := []struct {
		name        string
		inputKey    []byte
		inputData   *LoadInstallAndMakeSelectableTokenInput
		expected    []byte
		expectError bool
	}{
		{
			name: "Calculate Token",
			inputData: &LoadInstallAndMakeSelectableTokenInput{
				LoadP1:     command.InstallP1ForLoad,
				LoadP2:     command.InstallP2BeginningOfCombinedProcess,
				LoadELFAID: elfAID,
				SDAID:      sdAID,
				LFDBHash:   lfdbHash,
				LoadParameters: &command.LoadParameters{
					SystemSpecificParameters: &command.SystemSpecificParameters{
						NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
						VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
						NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
						LoadFileDataBlockFormatID:           lfdbFormatID,
						LoadFileDataBlockParameters:         lfdbParams,
					},
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
				InstallP1:     command.InstallP1ForLoadInstallAndMakeSelectable,
				InstallP2:     command.InstallP2EndOfCombinedProcess,
				InstallELFAID: elfAID,
				EMAID:         emAID,
				InstanceAID:   instanceAID,
				Privileges:    privs,
				InstallParameters: &command.InstallParameters{
					ApplicationSpecificParameters: applicationSpecificParameters,
					TS102226SpecificTemplate:      tsTemplate,
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
			},
			expected:    expected,
			expectError: false,
		},
		{
			name: "Error: invalid Privileges",
			inputData: &LoadInstallAndMakeSelectableTokenInput{
				LoadP1:     command.InstallP1ForLoad,
				LoadP2:     command.InstallP2BeginningOfCombinedProcess,
				LoadELFAID: elfAID,
				SDAID:      sdAID,
				LFDBHash:   lfdbHash,
				LoadParameters: &command.LoadParameters{
					SystemSpecificParameters: &command.SystemSpecificParameters{
						NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
						VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
						NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
						LoadFileDataBlockFormatID:           lfdbFormatID,
						LoadFileDataBlockParameters:         lfdbParams,
					},
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
				InstallP1:     command.InstallP1ForLoadInstallAndMakeSelectable,
				InstallP2:     command.InstallP2EndOfCombinedProcess,
				InstallELFAID: elfAID,
				EMAID:         emAID,
				InstanceAID:   instanceAID,
				Privileges:    open.Privileges{open.MandatedDAPVerification, open.DAPVerification},
				InstallParameters: &command.InstallParameters{
					ApplicationSpecificParameters: applicationSpecificParameters,
					TS102226SpecificTemplate:      tsTemplate,
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: Invalid install for load data",
			inputData: &LoadInstallAndMakeSelectableTokenInput{
				LoadP1:     command.InstallP1ForLoad,
				LoadP2:     command.InstallP2BeginningOfCombinedProcess,
				LoadELFAID: make([]byte, 16777215),
				SDAID:      sdAID,
				LFDBHash:   lfdbHash,
				LoadParameters: &command.LoadParameters{
					SystemSpecificParameters: &command.SystemSpecificParameters{
						NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
						VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
						NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
						LoadFileDataBlockFormatID:           lfdbFormatID,
						LoadFileDataBlockParameters:         lfdbParams,
					},
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
				InstallP1:     command.InstallP1ForLoadInstallAndMakeSelectable,
				InstallP2:     command.InstallP2EndOfCombinedProcess,
				InstallELFAID: elfAID,
				EMAID:         emAID,
				InstanceAID:   instanceAID,
				Privileges:    privs,
				InstallParameters: &command.InstallParameters{
					ApplicationSpecificParameters: applicationSpecificParameters,
					TS102226SpecificTemplate:      tsTemplate,
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: Invalid install data",
			inputData: &LoadInstallAndMakeSelectableTokenInput{
				LoadP1:     command.InstallP1ForLoad,
				LoadP2:     command.InstallP2BeginningOfCombinedProcess,
				LoadELFAID: elfAID,
				SDAID:      sdAID,
				LFDBHash:   lfdbHash,
				LoadParameters: &command.LoadParameters{
					SystemSpecificParameters: &command.SystemSpecificParameters{
						NonVolatileCodeMinimumRequirement:   nonVolatileCodeMinimumRequirement,
						VolatileMemoryMinimumRequirement:    volatileMemoryQuota,
						NonVolatileMemoryMinimumRequirement: nonVolatileMemoryQuota,
						LoadFileDataBlockFormatID:           lfdbFormatID,
						LoadFileDataBlockParameters:         lfdbParams,
					},
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
				InstallP1:     command.InstallP1ForLoadInstallAndMakeSelectable,
				InstallP2:     command.InstallP2EndOfCombinedProcess,
				InstallELFAID: make([]byte, 16777215),
				EMAID:         emAID,
				InstanceAID:   instanceAID,
				Privileges:    privs,
				InstallParameters: &command.InstallParameters{
					ApplicationSpecificParameters: applicationSpecificParameters,
					TS102226SpecificTemplate:      tsTemplate,
					ControlReferenceTemplateForDigitalSignature: &command.CRTDigitalSignature{
						SDIdentificationNumber:        sdIDNum,
						SDImageNumber:                 sdImNum,
						ApplicationProviderIdentifier: appProvID,
						TokenIdentifier:               tokenID,
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := InputForLoadInstallAndMakeSelectable(tc.inputData)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}
