package command

import (
	"encoding/hex"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"strings"
	"testing"
)

func TestLoadFileStructure_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		input    LoadFileStructure
		expected []byte
	}{
		{
			name: "convert to bytes",
			input: LoadFileStructure{
				DAPBlocks: []DAPBlock{
					{
						SDAID:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
						LFDBSignature: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
					},
					{
						SDAID:         []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
						LFDBSignature: []byte{0xFF, 0xEE, 0xDD, 0xEE, 0xCC, 0xBB},
					},
				},
				LoadFileDataBlock:         []byte{0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8},
				ICV:                       []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8},
				CipheredLoadFileDataBlock: []byte{0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8},
			},
			expected: []byte{
				0xE2, 0x12, 0x4F, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xC3, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
				0xE2, 0x12, 0x4F, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xC3, 0x06, 0xFF, 0xEE, 0xDD, 0xEE, 0xCC, 0xBB,
				0xC4, 0x08, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
				0xD3, 0x08, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
				0xD4, 0x08, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestDapBlock_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		dapBlock DAPBlock
		expected []byte
	}{
		{
			name: "bytes",
			dapBlock: DAPBlock{
				SDAID:         aid.AID{0x01, 0x02, 0x03, 0x04, 0x05},
				LFDBSignature: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			expected: []byte{0xE2, 0x11, 0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xC3, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.dapBlock.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestInstallParameters_Bytes(t *testing.T) {
	tests := []struct {
		name        string
		input       InstallParameters
		expected    []byte
		expectError bool
	}{
		{
			name: "convert to bytes ",
			input: InstallParameters{
				ApplicationSpecificParameters: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				SystemSpecificParameters: &SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement: []byte{0x01, 0x00},
					GlobalServiceParameters:           []byte{0x04, 0x05, 0x06},
					VolatileReservedMemory:            []byte{0x02, 0x00},
					NonVolatileReservedMemory:         []byte{0x03, 0x00},
					LoadFileDataBlockFormatID:         util.NullByte{Byte: 0xFF, Valid: true},
					LoadFileDataBlockParameters:       []byte{0x01, 0x02, 0x03},
					ImplicitSelectionParameter:        util.NullByte{Byte: 0xEE, Valid: true},
				},
			},
			expected: []byte{
				0xC9, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xEF, 0x1C,
				0xC6, 0x02, 0x01, 0x00,
				0xCB, 0x03, 0x04, 0x05, 0x06,
				0xCD, 0x01, 0xFF,
				0xD7, 0x02, 0x02, 0x00,
				0xD8, 0x02, 0x03, 0x00,
				0xDD, 0x03, 0x01, 0x02, 0x03,
				0xCF, 0x01, 0xEE,
			},
			expectError: false,
		},
		{
			name: "empty application specific",
			input: InstallParameters{
				ApplicationSpecificParameters: nil,
				SystemSpecificParameters: &SystemSpecificParameters{
					NonVolatileCodeMinimumRequirement: []byte{0x01, 0x00},
					GlobalServiceParameters:           []byte{0x04, 0x05, 0x06},
					VolatileReservedMemory:            []byte{0x02, 0x00},
					NonVolatileReservedMemory:         []byte{0x03, 0x00},
					LoadFileDataBlockFormatID:         util.NullByte{Byte: 0xFF, Valid: true},
					LoadFileDataBlockParameters:       []byte{0x01, 0x02, 0x03},
					ImplicitSelectionParameter:        util.NullByte{Byte: 0xEE, Valid: true},
				},
			},
			expected: []byte{
				0xC9, 0x00, // ApplicationSpecificParameters
				0xEF, 0x1C, // SystemSpecificParameters
				0xC6, 0x02, 0x01, 0x00, // NonVolatileCodeMinimumRequirement
				0xCB, 0x03, 0x04, 0x05, 0x06, // GlobalServiceParameters
				0xCD, 0x01, 0xFF, // LoadFileDataBlockFormatId
				0xD7, 0x02, 0x02, 0x00, // VolatileReservedMemory
				0xD8, 0x02, 0x03, 0x00, // NonVolatileReservedMemory
				0xDD, 0x03, 0x01, 0x02, 0x03, // LoadFileDataBlockParameters
				0xCF, 0x01, 0xEE, // ImplicitSelectionParameter
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()
			fmt.Println(strings.ToUpper(hex.EncodeToString(received)))

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestSystemSpecificParameters_Bytes(t *testing.T) {
	tests := []struct {
		name        string
		input       SystemSpecificParameters
		expected    []byte
		expectError bool
	}{
		{
			name: "SystemSpecificParameters with two byte length encoding",
			input: SystemSpecificParameters{
				NonVolatileCodeMinimumRequirement: []byte{0x01, 0x00},
				GlobalServiceParameters:           []byte{0x04, 0x05, 0x06},
				VolatileReservedMemory:            []byte{0x02, 0x00},
				NonVolatileReservedMemory:         []byte{0x03, 0x00},
				LoadFileDataBlockFormatID:         util.NullByte{Byte: 0xFF, Valid: true},
				LoadFileDataBlockParameters:       []byte{0x01, 0x02, 0x03},
				ImplicitSelectionParameter:        util.NullByte{Byte: 0xEE, Valid: true},
				PrivacyRequirements: &PrivacyRequirements{
					RequiredPrivacyStatus: nil,
					RequiredPrivacyCondition: &RequiredPrivacyCondition{
						Constructed: false,
						Value:       []byte{0x01, 0x02},
					},
				},
				ContactlessProtocolParameters: &ContactlessProtocolParameters{
					AssignedProtocolsImplicitSelection:     []byte{ImplicitSelectionProtocolTypeF},
					InitialContactlessActivationState:      util.NullByte{Byte: InitialActivated, Valid: true},
					ContactlessProtocolParametersProfile:   []byte{0xA1, 0x03, 0x81, 0x01, 0x01},
					RecognitionAlgorithm:                   []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05},
					ContinuousProcessing:                   []byte{0x02},
					CommunicationInterfaceAccessParameters: &CommunicationInterfaceAccessParameters{CommunicationInterfaceAccessPerInstance: util.NullByte{Byte: ContactBasedCommunication, Valid: true}},
					ProtocolDataTypeF: &ProtocolData{
						ProtocolParameterData:          []byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04},
						ProtocolParameterMandatoryMask: []byte{0x80, 0x01, 0x00},
					},
					ContactlessProtocolTypeState: util.NullByte{Byte: ContactlessProtocolTypeF, Valid: true},
				},
				UserInteractionParameters: &UserInteractionParameters{
					DisplayControlTemplate: []byte{0x5F, 0x45, 0x01},
					HeadApplication:        aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					AddToGroupAuthorizationList: []aid.AID{
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
					},
					RemoveFromGroupAuthorizationList: []aid.AID{
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					},
					AddToCRELList: []aid.AID{
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					},
					RemoveFromCRELList: []aid.AID{
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					},
					PolicyRestrictedApplications: []aid.AID{
						{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					},
					ApplicationDiscretionaryData: []byte{0x01, 0x01, 0x01},
					ApplicationFamily:            util.NullByte{Byte: 0x01, Valid: true},
					DisplayRequiredIndicator:     util.NullByte{Byte: DisplayRequired, Valid: true},
				},
				ETSIParameters:                     []byte{0x04, 0x05, 0x06},
				CumulativeGrantedVolatileMemory:    []byte{0x0A, 0x0B},
				CumulativeGrantedNonVolatileMemory: []byte{0x0A, 0x0B},
				PrivacySensitiveIndicator:          util.NullByte{Byte: NotPrivacySensitive, Valid: true},
			},
			expected: []byte{
				0xEF, 0x81, 0xBB, // SystemSpecificParameters
				0xC6, 0x02, 0x01, 0x00, // NonVolatileCodeMinimumRequirement
				0xCB, 0x03, 0x04, 0x05, 0x06, // GlobalServiceParameters
				0xCD, 0x01, 0xFF, // LoadFileDataBlockFormatId
				0xD7, 0x02, 0x02, 0x00, // VolatileReservedMemory
				0xD8, 0x02, 0x03, 0x00, // NonVolatileReservedMemory
				0xDD, 0x03, 0x01, 0x02, 0x03, // LoadFileDataBlockParameters
				0xCF, 0x01, 0xEE, // ImplicitSelectionParameter
				0xE0, 0x04, 0x81, 0x02, 0x01, 0x02, // Privacy Requirements
				0xA0, 0x2F, // Contactless Protocol Parameters
				0x80, 0x01, 0x84, // Assigned Protocols for implicit selection
				0x81, 0x01, 0x01, // Initial Contactless Activation State
				0xA2, 0x05, 0xA1, 0x03, 0x81, 0x01, 0x01, // Contactless Protocol Parameters Profile
				0x83, 0x06, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, // Recognition Algorithm
				0x84, 0x01, 0x02, // Continuous Processing
				0xA5, 0x03, 0x82, 0x01, 0x80, // Communication Interface Access Parameters
				0x88, 0x0D, 0xA0, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA1, 0x03, 0x80, 0x01, 0x00, // Protocol Data Type F
				0x89, 0x01, 0x20, // Contactless Protocol Type State
				0xA1, 0x56, // User Interaction Parameters
				0x7F, 0x20, 0x03, 0x5F, 0x45, 0x01, // Display Control Template
				0xA0, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Head Application
				0xA1, 0x11, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x4F, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Add to Group Authorization List
				0xA2, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Remove from Group Authorization List
				0xA3, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Add to CREL List
				0xA4, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Remove from CREL List
				0xA5, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Policy Restricted Applications
				0xA6, 0x03, 0x01, 0x01, 0x01, // Application Discretionary Data
				0x87, 0x01, 0x01, // Application Family
				0x88, 0x01, 0x00, // Display Required Indicator
				0xB0, 0x03, 0x04, 0x05, 0x06, // ETSI
				0x82, 0x02, 0x0A, 0x0B, // Cumulative Granted Volatile Memory
				0x83, 0x02, 0x0A, 0x0B, // Cumulative Granted Non-Volatile Memory
				0x96, 0x01, 0x00, // Privacy Sensitive Indicator
			},
			expectError: false,
		},
		{
			name: "SystemSpecificParameters with one byte length encoding",
			input: SystemSpecificParameters{
				NonVolatileCodeMinimumRequirement: []byte{0x01, 0x00},
				GlobalServiceParameters:           []byte{0x04, 0x05, 0x06},
				VolatileReservedMemory:            []byte{0x02, 0x00},
				NonVolatileReservedMemory:         []byte{0x03, 0x00},
				LoadFileDataBlockFormatID:         util.NullByte{Byte: 0xFF, Valid: true},
				LoadFileDataBlockParameters:       []byte{0x01, 0x02, 0x03},
				ImplicitSelectionParameter:        util.NullByte{Byte: 0xEE, Valid: true},
				PrivacyRequirements: &PrivacyRequirements{
					RequiredPrivacyStatus: nil,
					RequiredPrivacyCondition: &RequiredPrivacyCondition{
						Constructed: false,
						Value:       []byte{0x01, 0x02},
					},
				},
				ContactlessProtocolParameters: &ContactlessProtocolParameters{
					AssignedProtocolsImplicitSelection:     []byte{ImplicitSelectionProtocolTypeF},
					InitialContactlessActivationState:      util.NullByte{Byte: InitialActivated, Valid: true},
					ContactlessProtocolParametersProfile:   []byte{0xA1, 0x03, 0x81, 0x01, 0x01},
					RecognitionAlgorithm:                   []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05},
					ContinuousProcessing:                   []byte{0x02},
					CommunicationInterfaceAccessParameters: &CommunicationInterfaceAccessParameters{CommunicationInterfaceAccessPerInstance: util.NullByte{Byte: ContactBasedCommunication, Valid: true}},
					ProtocolDataTypeF: &ProtocolData{
						ProtocolParameterData:          []byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04},
						ProtocolParameterMandatoryMask: []byte{0x80, 0x01, 0x00},
					},
					ContactlessProtocolTypeState: util.NullByte{Byte: ContactlessProtocolTypeF, Valid: true},
				},
				ETSIParameters:                     []byte{0x04, 0x05, 0x06},
				CumulativeGrantedVolatileMemory:    []byte{0x0A, 0x0B},
				CumulativeGrantedNonVolatileMemory: []byte{0x0A, 0x0B},
				PrivacySensitiveIndicator:          util.NullByte{Byte: NotPrivacySensitive, Valid: true},
			},
			expected: []byte{
				0xEF, 0x63, // SystemSpecificParameters
				0xC6, 0x02, 0x01, 0x00, // NonVolatileCodeMinimumRequirement
				0xCB, 0x03, 0x04, 0x05, 0x06, // GlobalServiceParameters
				0xCD, 0x01, 0xFF, // LoadFileDataBlockFormatId
				0xD7, 0x02, 0x02, 0x00, // VolatileReservedMemory
				0xD8, 0x02, 0x03, 0x00, // NonVolatileReservedMemory
				0xDD, 0x03, 0x01, 0x02, 0x03, // LoadFileDataBlockParameters
				0xCF, 0x01, 0xEE, // ImplicitSelectionParameter
				0xE0, 0x04, 0x81, 0x02, 0x01, 0x02, // Privacy Requirements
				0xA0, 0x2F, // Contactless Protocol Parameters
				0x80, 0x01, 0x84, // Assigned Protocols for implicit selection
				0x81, 0x01, 0x01, // Initial Contactless Activation State
				0xA2, 0x05, 0xA1, 0x03, 0x81, 0x01, 0x01, // Contactless Protocol Parameters Profile
				0x83, 0x06, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, // Recognition Algorithm
				0x84, 0x01, 0x02, // Continuous Processing
				0xA5, 0x03, 0x82, 0x01, 0x80, // Communication Interface Access Parameters
				0x88, 0x0D, 0xA0, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA1, 0x03, 0x80, 0x01, 0x00, // Protocol Data Type F
				0x89, 0x01, 0x20, // Contactless Protocol Type State
				0xB0, 0x03, 0x04, 0x05, 0x06, // ETSI
				0x82, 0x02, 0x0A, 0x0B, // Cumulative Granted Volatile Memory
				0x83, 0x02, 0x0A, 0x0B, // Cumulative Granted Non-Volatile Memory
				0x96, 0x01, 0x00, // Privacy Sensitive Indicator
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRequiredPrivacyStatus_Bytes(t *testing.T) {
	tests := []struct {
		name                       string
		inputRequiredPrivacyStatus RequiredPrivacyStatus
		expected                   []byte
	}{
		{
			name: "not constructed bytes",
			inputRequiredPrivacyStatus: RequiredPrivacyStatus{
				Constructed: false,
				Value:       []byte{0x00, 0x01, 0x02},
			},
			expected: []byte{0x80, 0x03, 0x00, 0x01, 0x02},
		},
		{
			name: "constructed bytes",
			inputRequiredPrivacyStatus: RequiredPrivacyStatus{
				Constructed: true,
				Value:       []byte{0x00, 0x01, 0x02},
			},
			expected: []byte{0xA0, 0x03, 0x00, 0x01, 0x02},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.inputRequiredPrivacyStatus.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRequiredPrivacyCondition_Bytes(t *testing.T) {
	tests := []struct {
		name                          string
		inputRequiredPrivacyCondition RequiredPrivacyCondition
		expected                      []byte
	}{
		{
			name: "not constructed bytes",
			inputRequiredPrivacyCondition: RequiredPrivacyCondition{
				Constructed: false,
				Value:       []byte{0x00, 0x01, 0x02},
			},
			expected: []byte{0x81, 0x03, 0x00, 0x01, 0x02},
		},
		{
			name: "constructed bytes",
			inputRequiredPrivacyCondition: RequiredPrivacyCondition{
				Constructed: true,
				Value:       []byte{0x00, 0x01, 0x02},
			},
			expected: []byte{0xA1, 0x03, 0x00, 0x01, 0x02},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.inputRequiredPrivacyCondition.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestPrivacyRequirements_Bytes(t *testing.T) {
	tests := []struct {
		name                     string
		inputPrivacyRequirements PrivacyRequirements
		expected                 []byte
	}{
		{
			name: "multiple status, no condition",
			inputPrivacyRequirements: PrivacyRequirements{
				RequiredPrivacyStatus: []RequiredPrivacyStatus{
					{
						Constructed: false,
						Value:       []byte{0xF1, 0xF2},
					},
					{
						Constructed: true,
						Value:       []byte{0xE1, 0xE2},
					},
				},
				RequiredPrivacyCondition: nil,
			},
			expected: []byte{0xE0, 0x08, 0x80, 0x02, 0xF1, 0xF2, 0xA0, 0x02, 0xE1, 0xE2},
		},
		{
			name: "one status, with condition",
			inputPrivacyRequirements: PrivacyRequirements{
				RequiredPrivacyStatus: []RequiredPrivacyStatus{
					{
						Constructed: false,
						Value:       []byte{0xF1},
					},
				},
				RequiredPrivacyCondition: &RequiredPrivacyCondition{
					Constructed: true,
					Value:       []byte{0xE1, 0xE2},
				},
			},
			expected: []byte{0xE0, 0x07, 0x80, 0x01, 0xF1, 0xA1, 0x02, 0xE1, 0xE2},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.inputPrivacyRequirements.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestTagList_Bytes(t *testing.T) {
	tests := []struct {
		name         string
		inputTagList TagList
		expected     []byte
	}{
		{
			name: "All tags",
			inputTagList: TagList{
				AID:                                    true,
				ApplicationLifecycleState:              true,
				Privileges:                             true,
				ImplicitSelectionParameters:            true,
				ApplicationElfAID:                      true,
				ElfVersionNumber:                       true,
				ListOfEmAIDs:                           true,
				AssociatedSdAID:                        true,
				DisplayControlTemplate:                 true,
				UniformResourceLocator:                 true,
				ApplicationImageTemplate:               true,
				DisplayMessage:                         true,
				ApplicationGroupHeadApplication:        true,
				ApplicationGroupAuthorizationList:      true,
				CRELApplicationAIDList:                 true,
				PolicyRestrictedApplications:           true,
				ApplicationGroupMembers:                true,
				ApplicationDiscretionaryData:           true,
				ApplicationFamily:                      true,
				AssignedProtocolsImplicitSelection:     true,
				InitialContactlessActivationState:      true,
				ContactlessProtocolTypeState:           true,
				ContactlessProtocolParametersProfile:   true,
				RecognitionAlgorithm:                   true,
				ContinuousProcessing:                   true,
				CommunicationInterfaceAccessParameters: true,
				ProtocolDataTypeA:                      true,
				ProtocolDataTypeB:                      true,
				CumulativeGrantedNonVolatileMemory:     true,
				CumulativeGrantedVolatileMemory:        true,
				CumulativeRemainingNonVolatileMemory:   true,
				CumulativeRemainingVolatileMemory:      true,
				ProtocolDataTypeF:                      true,
				PrivacySensitiveIndicator:              true,
			},
			expected: []byte{0x5C, 0x21, 0x4F, 0x9F, 0x70, 0xC5, 0xCF, 0xC4, 0xCE, 0x84, 0xCC, 0x7F, 0x20, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x86, 0x87, 0x88, 0x89, 0xA9, 0x8A, 0x8B, 0xAC, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x96},
		},
		{
			name: "URL, Application Image Template, Display Message",
			inputTagList: TagList{
				UniformResourceLocator:   true,
				ApplicationImageTemplate: true,
				DisplayMessage:           true,
			},
			expected: []byte{0x5C, 0x05, 0x5F, 0x50, 0x6D, 0x5F, 0x45},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.inputTagList.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestGetStatusCommandDataField_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		cdf      GetStatusCommandDataField
		expected []byte
	}{
		{
			name: "AID as search criteria - without TagList",
			cdf: GetStatusCommandDataField{
				AID: aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
		{
			name: "AID and other search criteria - without TagList",
			cdf: GetStatusCommandDataField{
				AID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				OtherSearchCriteria: []byte{0xC5, 0x03, 0x00, 0x00, 0x10},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xC5, 0x03, 0x00, 0x00, 0x10},
		},
		{
			name: "AID and other search criteria - with TagList",
			cdf: GetStatusCommandDataField{
				AID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				OtherSearchCriteria: []byte{0xC5, 0x03, 0x00, 0x00, 0x10},
				TagList:             &TagList{AssociatedSdAID: true},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xC5, 0x03, 0x00, 0x00, 0x10, 0x5C, 0x01, 0xCC},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.cdf.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestTagListCRS_Bytes(t *testing.T) {
	tests := []struct {
		name         string
		inputTagList TagListCRS
		expected     []byte
	}{
		{
			name: "All tags",
			inputTagList: TagListCRS{
				AID:                                      true,
				ApplicationLifecycleState:                true,
				DisplayControlTemplate:                   true,
				UniformResourceLocator:                   true,
				ApplicationImageTemplate:                 true,
				DisplayMessage:                           true,
				ApplicationUpdateCounter:                 true,
				SelectionPriority:                        true,
				GroupHeadApplication:                     true,
				GroupMembersApplication:                  true,
				CRELApplicationAIDList:                   true,
				PolicyRestrictedApplications:             true,
				ApplicationDiscretionaryData:             true,
				ApplicationFamily:                        true,
				DisplayRequiredIndicator:                 true,
				ContactlessProtocolTypeState:             true,
				ContinuousProcessing:                     true,
				RecognitionAlgorithmForImplicitSelection: true,
				AssignedProtocolsForImplicitSelection:    true,
				ProtocolDataTypeA:                        true,
				ProtocolDataTypeB:                        true,
				ProtocolDataTypeF:                        true,
				ProtocolDataTypeFSystemCode:              true,
				CommunicationInterfaceAvailability:       true,
				PrivacySensitiveIndicator:                true,
			},
			expected: []byte{0x5C, 0x18, 0x4F, 0x9F, 0x70, 0x7F, 0x20, 0x80, 0x81, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x93, 0x94, 0x95, 0x96},
		},
		{
			name: "URL, Application Image Template, Display Message",
			inputTagList: TagListCRS{
				UniformResourceLocator:   true,
				ApplicationImageTemplate: true,
				DisplayMessage:           true,
			},
			expected: []byte{0x5C, 0x05, 0x5F, 0x50, 0x6D, 0x5F, 0x45},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.inputTagList.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestGetStatusCRSCommandDataField_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		cdf      GetStatusCRSCommandDataField
		expected []byte
	}{
		{
			name: "AID as search criteria - without TagList",
			cdf: GetStatusCRSCommandDataField{
				AID: aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
		{
			name: "AID and other search criteria - without TagList",
			cdf: GetStatusCRSCommandDataField{
				AID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				OtherSearchCriteria: []byte{0x9F, 0x70, 0x02, 0x07, 0x01},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x9F, 0x70, 0x02, 0x07, 0x01},
		},
		{
			name: "AID and other search criteria - with TagList",
			cdf: GetStatusCRSCommandDataField{
				AID:                 aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				OtherSearchCriteria: []byte{0x9F, 0x70, 0x02, 0x07, 0x01},
				TagListCRS:          &TagListCRS{CommunicationInterfaceAvailability: true},
			},
			expected: []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x9F, 0x70, 0x02, 0x07, 0x01, 0x5C, 0x01, 0x95},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.cdf.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestCommunicationInterfaceAccessParameters_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		ciap     CommunicationInterfaceAccessParameters
		expected []byte
	}{
		{
			name: "Restriction",
			ciap: CommunicationInterfaceAccessParameters{
				CommunicationInterfaceAccessRestriction: util.NullByte{
					Byte:  ContactBasedCommunication,
					Valid: true,
				},
			},
			expected: []byte{0x80, 0x01, 0x80},
		},
		{
			name: "Default",
			ciap: CommunicationInterfaceAccessParameters{
				CommunicationInterfaceAccessDefault: util.NullByte{
					Byte:  ProximityBasedCommunication,
					Valid: true,
				},
			},
			expected: []byte{0x81, 0x01, 0x40},
		},
		{
			name: "Per Instance",
			ciap: CommunicationInterfaceAccessParameters{
				CommunicationInterfaceAccessPerInstance: util.NullByte{
					Byte:  ContactAndProximityBasedCommunication,
					Valid: true,
				},
			},
			expected: []byte{0x82, 0x01, 0xC0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.ciap.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestContactlessProtocolParameters_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		cpp      ContactlessProtocolParameters
		expected []byte
	}{
		{
			name: "Protocol Data Type A",
			cpp: ContactlessProtocolParameters{
				AssignedProtocolsImplicitSelection:     []byte{ImplicitSelectionProtocolTypeA},
				InitialContactlessActivationState:      util.NullByte{Byte: InitialActivated, Valid: true},
				ContactlessProtocolParametersProfile:   []byte{0xA0, 0x03, 0x81, 0x01, 0x01},
				RecognitionAlgorithm:                   []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05},
				ContinuousProcessing:                   []byte{0x02},
				CommunicationInterfaceAccessParameters: &CommunicationInterfaceAccessParameters{CommunicationInterfaceAccessPerInstance: util.NullByte{Byte: ProximityBasedCommunication, Valid: true}},
				ProtocolDataTypeA: &ProtocolData{
					ProtocolParameterData:          []byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04},
					ProtocolParameterMandatoryMask: []byte{0x80, 0x01, 0x00},
				},
				ContactlessProtocolTypeState: util.NullByte{Byte: ContactlessProtocolTypeA, Valid: true},
			},
			expected: []byte{
				0x80, 0x01, 0x81, // Assigned Protocols for implicit selection
				0x81, 0x01, 0x01, // Initial Contactless Activation State
				0xA2, 0x05, 0xA0, 0x03, 0x81, 0x01, 0x01, // Contactless Protocol Parameters Profile
				0x83, 0x06, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, // Recognition Algorithm
				0x84, 0x01, 0x02, // Continuous Processing
				0xA5, 0x03, 0x82, 0x01, 0x40, // Communication Interface Access Parameters
				0x86, 0x0D, 0xA0, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA1, 0x03, 0x80, 0x01, 0x00, // Protocol Data Type A
				0x89, 0x01, 0x80}, // Contactless Protocol Type State
		},
		{
			name: "Protocol Data Type B",
			cpp: ContactlessProtocolParameters{
				AssignedProtocolsImplicitSelection:     []byte{ImplicitSelectionProtocolTypeB},
				InitialContactlessActivationState:      util.NullByte{Byte: InitialActivated, Valid: true},
				ContactlessProtocolParametersProfile:   []byte{0xA1, 0x03, 0x81, 0x01, 0x01},
				RecognitionAlgorithm:                   []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05},
				ContinuousProcessing:                   []byte{0x02},
				CommunicationInterfaceAccessParameters: &CommunicationInterfaceAccessParameters{CommunicationInterfaceAccessPerInstance: util.NullByte{Byte: ContactBasedCommunication, Valid: true}},
				ProtocolDataTypeB: &ProtocolData{
					ProtocolParameterData:          []byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04},
					ProtocolParameterMandatoryMask: []byte{0x80, 0x01, 0x00},
				},
				ContactlessProtocolTypeState: util.NullByte{Byte: ContactlessProtocolTypeB, Valid: true},
			},
			expected: []byte{
				0x80, 0x01, 0x82, // Assigned Protocols for implicit selection
				0x81, 0x01, 0x01, // Initial Contactless Activation State
				0xA2, 0x05, 0xA1, 0x03, 0x81, 0x01, 0x01, // Contactless Protocol Parameters Profile
				0x83, 0x06, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, // Recognition Algorithm
				0x84, 0x01, 0x02, // Continuous Processing
				0xA5, 0x03, 0x82, 0x01, 0x80, // Communication Interface Access Parameters
				0x87, 0x0D, 0xA0, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA1, 0x03, 0x80, 0x01, 0x00, // Protocol Data Type B
				0x89, 0x01, 0x40}, // Contactless Protocol Type State
		},
		{
			name: "Protocol Data Type F",
			cpp: ContactlessProtocolParameters{
				AssignedProtocolsImplicitSelection:     []byte{ImplicitSelectionProtocolTypeF},
				InitialContactlessActivationState:      util.NullByte{Byte: InitialActivated, Valid: true},
				ContactlessProtocolParametersProfile:   []byte{0xA1, 0x03, 0x81, 0x01, 0x01},
				RecognitionAlgorithm:                   []byte{0x01, 0x01, 0x02, 0x03, 0x04, 0x05},
				ContinuousProcessing:                   []byte{0x02},
				CommunicationInterfaceAccessParameters: &CommunicationInterfaceAccessParameters{CommunicationInterfaceAccessPerInstance: util.NullByte{Byte: ContactBasedCommunication, Valid: true}},
				ProtocolDataTypeF: &ProtocolData{
					ProtocolParameterData:          []byte{0x80, 0x04, 0x01, 0x02, 0x03, 0x04},
					ProtocolParameterMandatoryMask: []byte{0x80, 0x01, 0x00},
				},
				ContactlessProtocolTypeState: util.NullByte{Byte: ContactlessProtocolTypeF, Valid: true},
			},
			expected: []byte{
				0x80, 0x01, 0x84, // Assigned Protocols for implicit selection
				0x81, 0x01, 0x01, // Initial Contactless Activation State
				0xA2, 0x05, 0xA1, 0x03, 0x81, 0x01, 0x01, // Contactless Protocol Parameters Profile
				0x83, 0x06, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, // Recognition Algorithm
				0x84, 0x01, 0x02, // Continuous Processing
				0xA5, 0x03, 0x82, 0x01, 0x80, // Communication Interface Access Parameters
				0x88, 0x0D, 0xA0, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04, 0xA1, 0x03, 0x80, 0x01, 0x00, // Protocol Data Type F
				0x89, 0x01, 0x20}, // Contactless Protocol Type State
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.cpp.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestUserInteractionParameters_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		uip      UserInteractionParameters
		expected []byte
	}{
		{
			name: "bytes",
			uip: UserInteractionParameters{
				DisplayControlTemplate: []byte{0x5F, 0x45, 0x01},
				HeadApplication:        aid.AID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				AddToGroupAuthorizationList: []aid.AID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				},
				RemoveFromGroupAuthorizationList: []aid.AID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				},
				AddToCRELList: []aid.AID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				},
				RemoveFromCRELList: []aid.AID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				},
				PolicyRestrictedApplications: []aid.AID{
					{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				},
				ApplicationDiscretionaryData: []byte{0x01, 0x01, 0x01},
				ApplicationFamily:            util.NullByte{Byte: 0x01, Valid: true},
				DisplayRequiredIndicator:     util.NullByte{Byte: DisplayRequired, Valid: true},
			},
			expected: []byte{
				0x7F, 0x20, 0x03, 0x5F, 0x45, 0x01, // Display Control Template
				0xA0, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Head Application
				0xA1, 0x11, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x4F, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Add to Group Authorization List
				0xA2, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Remove from Group Authorization List
				0xA3, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Add to CREL List
				0xA4, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Remove from CREL List
				0xA5, 0x08, 0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Policy Restricted Applications
				0xA6, 0x03, 0x01, 0x01, 0x01, // Application Discretionary Data
				0x87, 0x01, 0x01, // Application Family
				0x88, 0x01, 0x00}, // Display Required Indicator
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.uip.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
