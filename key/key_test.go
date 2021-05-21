package key

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gobalplatform/internal/util"
)

func TestNewKeyComponentBasicEncrypted(t *testing.T) {
	tests := []struct {
		name               string
		inputKeyType       byte
		inputEncryptedKey  []byte
		inputKCV           []byte
		inputPaddingLength int
		expected           *ComponentBasic
		expectError        bool
	}{
		{
			name:               "Unpadded Block, DES key",
			inputKeyType:       0x80,
			inputEncryptedKey:  []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4},
			inputKCV:           []byte{0x51, 0xBB, 0xED},
			inputPaddingLength: 0,
			expected: &ComponentBasic{
				Type:  0x80,
				Block: ComponentUnpaddedBlock{Value: []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
				KCV:   []byte{0x51, 0xBB, 0xED},
			},
			expectError: false,
		},
		{
			name:               "Unpadded Block, AES key",
			inputKeyType:       0x88,
			inputEncryptedKey:  []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4},
			inputKCV:           []byte{0x17, 0x96, 0x72},
			inputPaddingLength: 0,
			expected: &ComponentBasic{
				Type:  0x88,
				Block: ComponentUnpaddedBlock{Value: []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
				KCV:   []byte{0x17, 0x96, 0x72},
			},
			expectError: false,
		},
		{
			name:               "Padded Block",
			inputKeyType:       0x55,
			inputEncryptedKey:  []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
			inputKCV:           nil,
			inputPaddingLength: 1,
			expected: &ComponentBasic{
				Type: 0x55,
				Block: ComponentPaddedBlock{
					Value:           []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
					LengthComponent: 16,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := NewComponentBasic(tc.inputKeyType, tc.inputEncryptedKey, tc.inputKCV, tc.inputPaddingLength)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestNewKeyComponentExtendedEncrypted(t *testing.T) {
	tests := []struct {
		name               string
		inputKeyType       byte
		inputKey           []byte
		inputKCV           []byte
		inputKeyUsage      UsageQualifier
		inputKeyAccess     util.NullByte
		inputPaddingLength int
		expected           *ComponentExtended
		expectError        bool
	}{
		{
			name:          "no error, padded block ",
			inputKeyType:  0x50,
			inputKey:      []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
			inputKCV:      nil,
			inputKeyUsage: UsageQualifier{Computation: true},
			inputKeyAccess: util.NullByte{
				Byte:  AccessSdOnly,
				Valid: true,
			},
			inputPaddingLength: 1,
			expected: &ComponentExtended{
				ComponentBasic: ComponentBasic{
					Type: 0x50,
					Block: ComponentPaddedBlock{
						Value:           []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
						LengthComponent: 16,
					},
				},
				UsageQualifier: UsageQualifier{Computation: true},
				Access: util.NullByte{
					Byte:  AccessSdOnly,
					Valid: true,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := NewComponentExtended(tc.inputKeyType, tc.inputKey, tc.inputKCV, tc.inputPaddingLength, tc.inputKeyUsage, tc.inputKeyAccess)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestUsageQualifier_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage UsageQualifier
		expected []byte
	}{
		{
			name: "all key usages, two byte",
			keyUsage: UsageQualifier{
				Verification:               true,
				Computation:                true,
				SecureMessagingResponse:    true,
				SecureMessagingCommand:     true,
				Confidentiality:            true,
				CryptographicChecksum:      true,
				DigitalSignature:           true,
				CryptographicAuthorization: true,
				KeyAgreement:               true,
			},
			expected: []byte{0xFF, 0x80},
		},
		{
			name: "all key usages, one byte ",
			keyUsage: UsageQualifier{
				Verification:               true,
				Computation:                true,
				SecureMessagingResponse:    true,
				SecureMessagingCommand:     true,
				Confidentiality:            true,
				CryptographicChecksum:      true,
				DigitalSignature:           true,
				CryptographicAuthorization: true,
			},
			expected: []byte{0xFF},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.keyUsage.Bytes()

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestKeyUsageForType(t *testing.T) {
	tests := []struct {
		name              string
		inputKeyUsageType UsageType
		expected          *UsageQualifier
	}{
		{
			name:              "CMAC key usage",
			inputKeyUsageType: CMac,
			expected:          &UsageQualifier{CryptographicChecksum: true, SecureMessagingCommand: true},
		},
		{
			name:              "RMAC key usage",
			inputKeyUsageType: RMac,
			expected:          &UsageQualifier{CryptographicChecksum: true, SecureMessagingResponse: true},
		},
		{
			name:              "CMAC+RMAC key usage",
			inputKeyUsageType: CMacRMac,
			expected:          &UsageQualifier{CryptographicChecksum: true, SecureMessagingCommand: true, SecureMessagingResponse: true},
		},
		{
			name:              "CENC key usage",
			inputKeyUsageType: CEnc,
			expected:          &UsageQualifier{SecureMessagingCommand: true, Confidentiality: true},
		},
		{
			name:              "RENC key usage",
			inputKeyUsageType: REnc,
			expected:          &UsageQualifier{SecureMessagingResponse: true, Confidentiality: true},
		},
		{
			name:              "CENC+RENC key usage",
			inputKeyUsageType: CEncREnc,
			expected:          &UsageQualifier{SecureMessagingCommand: true, SecureMessagingResponse: true, Confidentiality: true},
		},
		{
			name:              "DEK key usage",
			inputKeyUsageType: CDek,
			expected:          &UsageQualifier{Computation: true, Confidentiality: true},
		},
		{
			name:              "RDEK key usage",
			inputKeyUsageType: RDek,
			expected:          &UsageQualifier{Verification: true, Confidentiality: true},
		},
		{
			name:              "CDEK+RDEK key usage",
			inputKeyUsageType: CDekRDek,
			expected:          &UsageQualifier{Verification: true, Computation: true, Confidentiality: true},
		},
		{
			name:              "PK_SD_AUT key usage",
			inputKeyUsageType: PkSdAut,
			expected:          &UsageQualifier{Verification: true, DigitalSignature: true},
		},
		{
			name:              "SK_SD_AUT key usage",
			inputKeyUsageType: SkSdAut,
			expected:          &UsageQualifier{Computation: true, DigitalSignature: true},
		},
		{
			name:              "Token key usage",
			inputKeyUsageType: Token,
			expected:          &UsageQualifier{Verification: true, CryptographicAuthorization: true},
		},
		{
			name:              "Receipt key usage",
			inputKeyUsageType: Receipt,
			expected:          &UsageQualifier{Computation: true, CryptographicChecksum: true},
		},
		{
			name:              "DAP key usage",
			inputKeyUsageType: Dap,
			expected:          &UsageQualifier{Verification: true, CryptographicChecksum: true},
		},
		{
			name:              "PK_SD_AUT_Token key usage",
			inputKeyUsageType: PkSdAutToken,
			expected:          &UsageQualifier{Verification: true, DigitalSignature: true, CryptographicAuthorization: true},
		},
		{
			name:              "SK_SD_AUT_Receipt key usage",
			inputKeyUsageType: SkSdAutReceipt,
			expected:          &UsageQualifier{Computation: true, DigitalSignature: true, CryptographicAuthorization: true},
		},
		{
			name:              "PK_SD_AUT_DAP key usage",
			inputKeyUsageType: PkSdAutDap,
			expected:          &UsageQualifier{Verification: true, DigitalSignature: true, CryptographicChecksum: true},
		},
		{
			name:              "PK_SD_AUT_Token_DAP key usage",
			inputKeyUsageType: PkSdAutTokenDap,
			expected:          &UsageQualifier{Verification: true, DigitalSignature: true, CryptographicAuthorization: true, CryptographicChecksum: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := UsageForType(tc.inputKeyUsageType)

			if !cmp.Equal(tc.expected, received) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestKeyComponentPaddedBlock_Bytes(t *testing.T) {
	tests := []struct {
		name                    string
		keyComponentPaddedBlock ComponentPaddedBlock
		expected                []byte
		expectError             bool
	}{
		{
			name: "KeyComponentPadded 1B",
			keyComponentPaddedBlock: ComponentPaddedBlock{
				LengthComponent: 8,
				Value:           []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3},
			},
			expected:    []byte{0x08, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3},
			expectError: false,
		},
		{
			name: "Error: invalid component length",
			keyComponentPaddedBlock: ComponentPaddedBlock{
				LengthComponent: 65536,
				Value:           []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.keyComponentPaddedBlock.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestKeyComponentUnpaddedBlock_Bytes(t *testing.T) {
	tests := []struct {
		name                    string
		keyComponentPaddedBlock ComponentUnpaddedBlock
		expected                []byte
		expectError             bool
	}{
		{
			name: "KeyComponentPadded 1B",
			keyComponentPaddedBlock: ComponentUnpaddedBlock{
				Value: []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3},
			},
			expected:    []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.keyComponentPaddedBlock.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestKeyDataBasic_Bytes(t *testing.T) {
	tests := []struct {
		name         string
		keyDataBasic DataBasic
		expected     []byte
		expectError  bool
	}{
		{
			name: "Convert to byte",
			keyDataBasic: DataBasic{
				Component: []ComponentBasic{
					{
						Type:  TypeDES,
						Block: ComponentUnpaddedBlock{[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
						KCV:   []byte{0x51, 0xBB, 0xED},
					},
					{
						Type:  TypeAES,
						Block: ComponentUnpaddedBlock{[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
						KCV:   []byte{0x17, 0x96, 0x72},
					},
					{
						Type:  0x50,
						Block: ComponentUnpaddedBlock{[]byte{0xA1, 0xA2, 0xA3, 0xA4}},
						KCV:   nil,
					},
				},
			},
			expected: []byte{
				0x80, 0x10, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0x03, 0x51, 0xBB, 0xED,
				0x88, 0x10, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0x03, 0x17, 0x96, 0x72,
				0x50, 0x04, 0xA1, 0xA2, 0xA3, 0xA4, 0x00},
			expectError: false,
		},
		{
			name: "Error: invalid key component block",
			keyDataBasic: DataBasic{
				Component: []ComponentBasic{
					{
						Type: TypeDES,
						Block: ComponentPaddedBlock{
							65537,
							[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
						KCV: []byte{0x51, 0xBB, 0xED},
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid key component block",
			keyDataBasic: DataBasic{
				Component: []ComponentBasic{
					{
						Type: TypeDES,
						Block: ComponentPaddedBlock{
							65537,
							[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
						KCV: []byte{0x51, 0xBB, 0xED},
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid length of key component block",
			keyDataBasic: DataBasic{
				Component: []ComponentBasic{
					{
						Type:  TypeDES,
						Block: ComponentUnpaddedBlock{make([]byte, 65536)},
						KCV:   []byte{0x51, 0xBB, 0xED},
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.keyDataBasic.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestKeyDataExtended_Bytes(t *testing.T) {
	tests := []struct {
		name            string
		keyDataExtended DataExtended
		expected        []byte
		expectError     bool
	}{
		{
			name: "Convert to byte",
			keyDataExtended: DataExtended{
				Components: []ComponentExtended{
					{
						ComponentBasic: ComponentBasic{
							Type:  TypeAES,
							Block: ComponentUnpaddedBlock{[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
							KCV:   []byte{0x17, 0x96, 0x72},
						},
						UsageQualifier: UsageQualifier{SecureMessagingCommand: true},
						Access: util.NullByte{
							Byte:  AccessSdOnly,
							Valid: true,
						},
					},
					{
						ComponentBasic: ComponentBasic{
							Type:  0x50,
							Block: ComponentUnpaddedBlock{[]byte{0xA1, 0xA2, 0xA3, 0xA4}},
							KCV:   nil,
						},
						UsageQualifier: UsageQualifier{Confidentiality: true},
						Access: util.NullByte{
							Byte:  AccessSdAndApplication,
							Valid: true,
						},
					},
				},
			},
			expected: []byte{
				0xFF, 0x88, 0x10, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0x03, 0x17, 0x96, 0x72, 0x01, 0x10, 0x01, 0x01,
				0xFF, 0x50, 0x04, 0xA1, 0xA2, 0xA3, 0xA4, 0x00, 0x01, 0x08, 0x01, 0x00},
			expectError: false,
		},
		{
			name: "Error: invalid key component block",
			keyDataExtended: DataExtended{
				Components: []ComponentExtended{
					{
						ComponentBasic: ComponentBasic{
							Type: TypeDES,
							Block: ComponentPaddedBlock{
								65537,
								[]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4}},
							KCV: []byte{0x51, 0xBB, 0xED},
						},
						UsageQualifier: UsageQualifier{},
						Access:         util.NullByte{},
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "Error: invalid length of key component block",
			keyDataExtended: DataExtended{
				Components: []ComponentExtended{
					{
						ComponentBasic: ComponentBasic{
							Type:  TypeDES,
							Block: ComponentUnpaddedBlock{make([]byte, 65536)},
							KCV:   []byte{0x51, 0xBB, 0xED},
						},
						UsageQualifier: UsageQualifier{},
						Access:         util.NullByte{},
					},
				},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := tc.keyDataExtended.Bytes()

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestGetCurveParametersAk(t *testing.T) {
	tests := []struct {
		name           string
		inputCurveName string
		expectedA      *ComponentBasic
		expectedK      *ComponentBasic
		expectError    bool
	}{
		{
			name:           "P-224",
			inputCurveName: "P-224",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{secp224r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{secpr1k},
			},
			expectError: false,
		},
		{
			name:           "P-256",
			inputCurveName: "P-256",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{secp256r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{secpr1k},
			},
			expectError: false,
		},
		{
			name:           "P-384",
			inputCurveName: "P-384",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{secp384r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{secpr1k},
			},
			expectError: false,
		},
		{
			name:           "P-521",
			inputCurveName: "P-521",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{secp521r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{secpr1k},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP256t1",
			inputCurveName: "brainpoolP256t1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP256t1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP256r1",
			inputCurveName: "brainpoolP256r1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP256r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP384t1",
			inputCurveName: "brainpoolP384t1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP384t1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP384r1",
			inputCurveName: "brainpoolP384r1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP384r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP512r1",
			inputCurveName: "brainpoolP512r1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP512r1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "brainpoolP512t1",
			inputCurveName: "brainpoolP512t1",
			expectedA: &ComponentBasic{
				Type:  0xB3,
				Block: ComponentUnpaddedBlock{brainpoolP512t1A},
			},
			expectedK: &ComponentBasic{
				Type:  0xB7,
				Block: ComponentUnpaddedBlock{brainpool1K},
			},
			expectError: false,
		},
		{
			name:           "Error: unknown curve name",
			inputCurveName: "Unknown curve",
			expectedA:      nil,
			expectedK:      nil,
			expectError:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receivedA, receivedK, err := GetCurveParametersAk(tc.inputCurveName)

			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())

				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")

				return
			}

			if !cmp.Equal(receivedA, tc.expectedA) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expectedA, receivedA)
			}

			if !cmp.Equal(receivedK, tc.expectedK) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expectedK, receivedK)
			}
		})
	}
}

func TestCalculateKeyCheckValue(t *testing.T) {
	tests := []struct {
		name         string
		inputKeyType byte
		inputKey     []byte
		expected     [3]byte
		expectError  bool
	}{
		{
			name:         "DES",
			inputKeyType: TypeDES,
			inputKey:     []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4},
			expected:     [3]byte{0x51, 0xBB, 0xED},
			expectError:  false,
		},
		{
			name:         "AES",
			inputKeyType: TypeAES,
			inputKey:     []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4},
			expected:     [3]byte{0x17, 0x96, 0x72},
			expectError:  false,
		},
		{
			name:         "Error: Unsupported key type",
			inputKeyType: TypeECCPrivateKey,
			inputKey:     []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4},
			expected:     [3]byte{},
			expectError:  true,
		},
		{
			name:         "Error: Invalid AES key length",
			inputKeyType: TypeAES,
			inputKey:     []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
			expected:     [3]byte{},
			expectError:  true,
		},
		{
			name:         "Error: Invalid DES key length",
			inputKeyType: TypeDES,
			inputKey:     []byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
			expected:     [3]byte{},
			expectError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := KCV(tc.inputKeyType, tc.inputKey)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}
