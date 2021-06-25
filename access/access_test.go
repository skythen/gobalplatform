package access

import (
	"github.com/skythen/gobalplatform/internal/util"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/skythen/bertlv"
)

func TestParseRefArDo(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    *RefArDo
		expectError bool
	}{
		{name: "Valid REF-AR-DO",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected: &RefArDo{
				RefDo: RefDo{
					AidRefDo: AidRefDo{
						AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
						ImplicitlySelectedApplication: false,
					},
					DeviceAppIDRefDo: DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
				},
				ArDo: ArDo{
					ApduArDo: &ApduArDo{Never},
					NfcArDo:  &NfcArDo{Byte: Always, Valid: true},
				},
			},
			expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			inputBytes: []byte{0xE2, 0x02, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Missing REF-AR-DO tag",
			inputBytes: []byte{0xE1, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Too many children",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE1, 0x20,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
				0xE4, 0x01, 0x02,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid first child tag",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE2, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid second child tag",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE4, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid REF-DO",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4E, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AR-DO",
			inputBytes: []byte{0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xDC, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseRefArDo(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseAllRefArDo(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    []RefArDo
		expectError bool
	}{
		{name: "no REF-AR-DOs",
			inputBytes:  []byte{0xFF, 0x40, 0x00},
			expected:    nil,
			expectError: false,
		},
		{name: "Valid REF-AR-DOs",
			inputBytes: []byte{0xFF, 0x40, 0x52,
				// REF-AR-DO 1
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
				// REF-AR-DO 2
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected: []RefArDo{
				{RefDo: RefDo{
					AidRefDo: AidRefDo{
						AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
						ImplicitlySelectedApplication: false,
					},
					DeviceAppIDRefDo: DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
				},
					ArDo: ArDo{
						ApduArDo: &ApduArDo{Never},
						NfcArDo:  &NfcArDo{Byte: Always, Valid: true},
					},
				}, {
					RefDo: RefDo{
						AidRefDo: AidRefDo{
							AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
							ImplicitlySelectedApplication: false,
						},
						DeviceAppIDRefDo: DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
					},
					ArDo: ArDo{
						ApduArDo: &ApduArDo{Never},
						NfcArDo:  &NfcArDo{Byte: Always, Valid: true},
					},
				},
			},
			expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			inputBytes: []byte{0xFF, 0x52,
				// REF-AR-DO 1
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
				// REF-AR-DO 2
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid REF-AR-DO (wrong tag in REF-DO of second REF-AR-DO)",
			inputBytes: []byte{0xFF, 0x40, 0x52,
				// REF-AR-DO 1
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
				// REF-AR-DO 2
				0xE2, 0x27,
				// REF-DO (wrong tag)
				0xE5, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Missing ALL REF-AR-DOs Tag",
			inputBytes: []byte{0xFF, 0x42, 0x52,
				// REF-AR-DO 1
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
				// REF-AR-DO 2
				0xE2, 0x27,
				// REF-DO
				0xE1, 0x1D,
				// AID-REF-DO
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// DeviceAppID-REF-DO
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				// AR-DO
				0xE3, 0x06,
				// APDU-AR-DO
				0xD0, 0x01, 0x00,
				// NFC-AR-DO
				0xD1, 0x01, 0x01,
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseAllRefArDo(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseDeviceAppIDRefDO(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    *DeviceAppIDRefDo
		expectError bool
	}{
		{name: "DeviceAppID",
			inputBytes: []byte{
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected: &DeviceAppIDRefDo{
				DeviceAppID: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
				},
			}, expectError: false,
		},
		{name: "Apply to all",
			inputBytes:  []byte{0xC1, 0x00},
			expected:    &DeviceAppIDRefDo{[]byte{}},
			expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			inputBytes:  []byte{0xC1, 0x02, 0x01},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Missing DeviceAppId-REF-DO",
			inputBytes:  []byte{0xC2, 0x02, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid DeviceAppID length",
			inputBytes:  []byte{0xC1, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseDeviceAppIDRefDO(tc.inputBytes)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseDeviceAppIDRefDOFromTlv(t *testing.T) {
	tests := []struct {
		name        string
		input       bertlv.BerTLV
		expected    *DeviceAppIDRefDo
		expectError bool
	}{
		{name: "DeviceAppID",
			input: bertlv.BerTLV{
				Tag: bertlv.NewOneByteTag(0xC1),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expected: &DeviceAppIDRefDo{
				DeviceAppID: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
				},
			}, expectError: false,
		},
		{name: "Apply to all",
			input: bertlv.BerTLV{
				Tag:   bertlv.NewOneByteTag(0xC1),
				Value: []byte{},
			},
			expected:    &DeviceAppIDRefDo{[]byte{}},
			expectError: false,
		},
		{name: "Error: Missing DeviceAppId-REF-DO",
			input: bertlv.BerTLV{
				Tag: bertlv.NewOneByteTag(0xC2),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid DeviceAppID length",
			input: bertlv.BerTLV{
				Tag: bertlv.NewOneByteTag(0xC1),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := deviceAppIDRefDoFromTlv(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseAidRefDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *AidRefDo
		expectError bool
	}{
		{name: "AID (0x4F) reference ",
			input: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: &AidRefDo{
				AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				ImplicitlySelectedApplication: false,
			}, expectError: false,
		},
		{name: "AID (0x4F) wildcard ",
			input: []byte{0x4F, 0x00},
			expected: &AidRefDo{
				AID:                           []byte{},
				ImplicitlySelectedApplication: false,
			}, expectError: false,
		},
		{name: "Implicitly Selected (0xC0)",
			input: []byte{0xC0, 0x00},
			expected: &AidRefDo{
				AID:                           nil,
				ImplicitlySelectedApplication: true,
			}, expectError: false,
		},
		{name: "Both (explicit and implicit) present, only first is evaluated",
			input: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0C, 0x00},
			expected: &AidRefDo{
				AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				ImplicitlySelectedApplication: false,
			}, expectError: false,
		},
		{name: "Error: No required tag is present",
			input:       []byte{0x4E, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: non empty C0",
			input:       []byte{0xC0, 0x01, 0x01},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid BER-TLV",
			input:       []byte{0x4F, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AID",
			input:       []byte{0x4F, 0x04, 0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseAidRefDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseAidRefDoFromTlv(t *testing.T) {
	tests := []struct {
		name        string
		input       bertlv.BerTLV
		expected    *AidRefDo
		expectError bool
	}{
		{name: "AID (0x4F) tag ",
			input: bertlv.BerTLV{
				Tag:   bertlv.NewOneByteTag(0x4F),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expected: &AidRefDo{
				AID:                           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				ImplicitlySelectedApplication: false,
			}, expectError: false,
		},
		{name: "ImplicitlySelectedApplication (0xC0) tag ",
			input: bertlv.BerTLV{
				Tag:   bertlv.NewOneByteTag(0xC0),
				Value: []byte{},
			},
			expected: &AidRefDo{
				ImplicitlySelectedApplication: true,
			}, expectError: false,
		},
		{name: "Error: Missing Tags",
			input: bertlv.BerTLV{
				Tag:   bertlv.NewOneByteTag(0xAB),
				Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := aidRefDoFromTlv(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseRefDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *RefDo
		expectError bool
	}{
		{name: "Valid RefDo",
			input: []byte{0xE1, 0x1D,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected: &RefDo{
				AidRefDo: AidRefDo{
					AID: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				},
				DeviceAppIDRefDo: DeviceAppIDRefDo{[]byte{
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
					0x01, 0x02, 0x03, 0x04, 0x05,
				}},
			}, expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			input: []byte{0xE1, 0x05, 0x1D,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: no REF-DO tag",
			input: []byte{0xE2, 0x1D,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: AID-REF-DO not first child",
			input: []byte{0xE1, 0x1D,
				0x4E, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: DEVICE-APP-ID-REF-DO not second child",
			input: []byte{0xE1, 0x1D,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC2, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: invalid AID-REF-DO",
			input: []byte{0xE1, 0x1C,
				0x4F, 0x04, 0x01, 0x02, 0x03, 0x04,
				0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: invalid AID-REF-DO",
			input: []byte{0xE1, 0x1C,
				0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
				0xC1, 0x13, 0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseRefDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseApduArDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *ApduArDo
		expectError bool
	}{
		{name: "Valid APDU-AR-DO single byte NEVER",
			input:       []byte{0xD0, 0x01, 0x00},
			expected:    &ApduArDo{Never},
			expectError: false,
		},
		{name: "Valid APDU-AR-DO single byte ALWAYS",
			input:       []byte{0xD0, 0x01, 0x01},
			expected:    &ApduArDo{Always},
			expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			input:       []byte{0xDF, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid APDU-AR-DO single byte value",
			input:       []byte{0xD0, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Valid APDU-AR-DO multiple of 8 byte (8)",
			input:       []byte{0xD0, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected:    &ApduArDo{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expectError: false,
		},
		{name: "Valid APDU-AR-DO multiple of 8 byte (16)",
			input:       []byte{0xD0, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected:    &ApduArDo{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expectError: false,
		},
		{name: "Error: Invalid APDU-AR-DO not 1 or multiple of 8 byte",
			input:       []byte{0xD0, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseApduArDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseNfcArDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *NfcArDo
		expectError bool
	}{
		{name: "Valid NFC-AR-DO NEVER",
			input:       []byte{0xD1, 0x01, 0x00},
			expected:    &NfcArDo{Byte: Never, Valid: true},
			expectError: false,
		},
		{name: "Valid NFC-AR-DO ALWAYS",
			input:       []byte{0xD1, 0x01, 0x01},
			expected:    &NfcArDo{Byte: Always, Valid: true},
			expectError: false,
		},
		{name: "Error: Invalid NFC-AR-DO length",
			input:       []byte{0xD1, 0x02, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid BER-TLV",
			input:       []byte{0xDF, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid NFC-AR-DO tag",
			input:       []byte{0xD2, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid NFC-AR-DO value",
			input:       []byte{0xD1, 0x01, 0x02},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseNfcArDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseArDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *ArDo
		expectError bool
	}{
		{name: "Valid AR-DO with APDU-AR-DO",
			input: []byte{0xE3, 0x03, 0xD0, 0x01, 0x01},
			expected: &ArDo{
				ApduArDo: &ApduArDo{Always},
				NfcArDo:  nil,
			},
			expectError: false,
		},
		{name: "Valid AR-DO with NFC-AR-DO",
			input: []byte{0xE3, 0x03, 0xD1, 0x01, 0x01},
			expected: &ArDo{
				ApduArDo: nil,
				NfcArDo:  &NfcArDo{Byte: Always, Valid: true},
			},
			expectError: false,
		},
		{name: "Valid AR-DO with APDU-AR-DO and NFC-AR-DO",
			input: []byte{0xE3, 0x06, 0xD0, 0x01, 0x00, 0xD1, 0x01, 0x01},
			expected: &ArDo{
				ApduArDo: &ApduArDo{Never},
				NfcArDo:  &NfcArDo{Byte: Always, Valid: true},
			},
			expectError: false,
		},
		{name: "Error: Invalid BER-TLV",
			input:       []byte{0xFF, 0x03, 0xD0, 0x01, 0x0C},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Missing AR-DO Tag",
			input:       []byte{0xE2, 0x03, 0xD0, 0x01, 0x0C},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid child tag",
			input:       []byte{0xE3, 0x03, 0xD2, 0x01, 0x01},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid  second child tag",
			input:       []byte{0xE3, 0x06, 0xD0, 0x01, 0x01, 0xD2, 0x01, 0x01},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AR-DO with invalid APDU-AR-DO",
			input:       []byte{0xE3, 0x03, 0xD0, 0x01, 0x0C},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AR-DO with invalid NFC-AR-DO",
			input:       []byte{0xE3, 0x03, 0xD1, 0x01, 0x0C},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AR-DO with Invalid APDU-AR-DO and valid NFC-AR-DO",
			input:       []byte{0xE3, 0x06, 0xD0, 0x01, 0x02, 0xD1, 0x01, 0x01},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid AR-DO with valid APDU-AR-DO and invalid NFC-AR-DO",
			input:       []byte{0xE3, 0x06, 0xD0, 0x01, 0x01, 0xD1, 0x01, 0x0F},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseArDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestParseARAMConfigDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *AramConfigDo
		expectError bool
	}{
		{name: "Creates new AramConfigDo",
			input:       []byte{0xE5, 0x05, 0xE6, 0x03, 0x01, 0x02, 0x03},
			expected:    &AramConfigDo{DeviceInterfaceVersionDo{0x01, 0x02, 0x03}},
			expectError: false,
		},
		{name: "Error: Invalid tag",
			input:       []byte{0xE6, 0x05, 0xE6, 0x03, 0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid length",
			input:       []byte{0xE5, 0x05, 0xE6, 0x03, 0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid length value",
			input:       []byte{0xE5, 0x06, 0xE6, 0x03, 0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid DeviceInterfaceVersionDo",
			input:       []byte{0xE5, 0x05, 0xE8, 0x03, 0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseARAMConfigDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestNewDeviceInterfaceVersionDo(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *DeviceInterfaceVersionDo
		expectError bool
	}{
		{name: "Creates new DeviceInterfaceVersionDo",
			input:       []byte{0xE6, 0x03, 0x01, 0x02, 0x03},
			expected:    &DeviceInterfaceVersionDo{0x01, 0x02, 0x03},
			expectError: false,
		},
		{name: "Error: Invalid length",
			input:       []byte{0xE6, 0x04, 0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Invalid tag",
			input:       []byte{0xE5, 0x03, 0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseDeviceInterfaceVersionDo(tc.input)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestNewGenericApduArDo(t *testing.T) {
	tests := []struct {
		name        string
		inputRule   byte
		expected    *ApduArDo
		expectError bool
	}{
		{name: "Creates new ApduArDo NEVER",
			inputRule:   0x00,
			expected:    &ApduArDo{0x00},
			expectError: false,
		},
		{name: "Creates new ApduArDo ALWAYS",
			inputRule:   0x01,
			expected:    &ApduArDo{0x01},
			expectError: false,
		},

		{name: "Error: Invalid rule value",
			inputRule:   0x02,
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := NewGenericApduArDo(tc.inputRule)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestNewFilterApduArDo(t *testing.T) {
	tests := []struct {
		name        string
		inputHeader []byte
		inputMask   []byte
		expected    *ApduArDo
		expectError bool
	}{
		{name: "Creates new ApduArDo",
			inputHeader: []byte{0x01, 0x02, 0x03, 0x04},
			inputMask:   []byte{0x01, 0x02, 0x03, 0x04},
			expected:    &ApduArDo{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04},
			expectError: false,
		},
		{name: "Error: Header length != 4",
			inputHeader: []byte{0x01, 0x02, 0x03},
			inputMask:   []byte{0x01, 0x02, 0x03, 0x04},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Mask length != 4",
			inputHeader: []byte{0x01, 0x02, 0x03, 0x04},
			inputMask:   []byte{0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
		{name: "Error: Header and Mask length != 4",
			inputHeader: []byte{0x01, 0x02, 0x03},
			inputMask:   []byte{0x01, 0x02, 0x03},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := NewFilterApduArDo(tc.inputHeader, tc.inputMask)

			util.EvaluateTestWithError(t, tc.expectError, err, tc.expected, received)
		})
	}
}

func TestDeviceAppIdRefDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    DeviceAppIDRefDo
		expected []byte
	}{
		{name: "Converts DeviceAppIdRefDo with length 20 to bytes",
			input:    DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
			expected: []byte{0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{name: "Converts DeviceAppIdRefDo with 0 < length < 20  to bytes (pad FF)",
			input:    DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04}},
			expected: []byte{0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{name: "Converts DeviceAppIdRefDo with length == 0 to bytes",
			input:    DeviceAppIDRefDo{DeviceAppID: []byte{}},
			expected: []byte{0xC1, 0x00},
		},
		{name: "Returns nil for DeviceAppIdRefDo with length > 20 ",
			input:    DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01}},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRefArDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    RefArDo
		expected []byte
	}{
		{name: "Converts RefArDo to bytes",
			input: RefArDo{
				RefDo{
					AidRefDo{AID: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, ImplicitlySelectedApplication: false},
					DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
				},
				ArDo{
					&ApduArDo{0x01},
					&NfcArDo{Byte: Always, Valid: true},
				},
			},
			expected: []byte{0xE2, 0x27, 0xE1, 0x1D, 0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xE3, 0x06, 0xD0, 0x01, 0x01, 0xD1, 0x01, 0x01},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestArDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    ArDo
		expected []byte
	}{
		{name: "Converts ArDo with ApduArDo and NfcArDo to bytes",
			input: ArDo{
				&ApduArDo{0x01},
				&NfcArDo{Byte: Always, Valid: true},
			},
			expected: []byte{0xE3, 0x06, 0xD0, 0x01, 0x01, 0xD1, 0x01, 0x01},
		},
		{name: "Converts ArDo with ApduArDo to bytes",
			input: ArDo{
				ApduArDo: &ApduArDo{0x01},
			},
			expected: []byte{0xE3, 0x03, 0xD0, 0x01, 0x01},
		},
		{name: "Converts ArDo with NfcArDo to bytes",
			input:    ArDo{NfcArDo: &NfcArDo{Byte: Always, Valid: true}},
			expected: []byte{0xE3, 0x03, 0xD1, 0x01, 0x01},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestApduArDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    ApduArDo
		expected []byte
	}{
		{name: "Converts single byte ApduArDo to bytes",
			input:    ApduArDo{0x01},
			expected: []byte{0xD0, 0x01, 0x01},
		},
		{name: "Converts multiple bytes ApduArDo to bytes",
			input:    ApduArDo{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected: []byte{0xD0, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestNfcArDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    NfcArDo
		expected []byte
	}{
		{name: "Converts NfcArDo to bytes",
			input:    NfcArDo{Byte: Always, Valid: true},
			expected: []byte{0xD1, 0x01, 0x01},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRefDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    RefDo
		expected []byte
	}{
		{name: "Converts RefDo to bytes",
			input: RefDo{
				AidRefDo{AID: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, ImplicitlySelectedApplication: false},
				DeviceAppIDRefDo{DeviceAppID: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
			},
			expected: []byte{0xE1, 0x1D, 0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xC1, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestAidRefDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    AidRefDo
		expected []byte
	}{
		{name: "Converts AidRefDo with AID to bytes",
			input:    AidRefDo{AID: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, ImplicitlySelectedApplication: false},
			expected: []byte{0x4F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{name: "Converts AidRefDo with ImplicitlySelectedApplication to bytes",
			input:    AidRefDo{ImplicitlySelectedApplication: true},
			expected: []byte{0xC0, 0x00},
		},
		{name: "Converts AidRefDo with AID and ImplicitlySelectedApplication to bytes",
			input:    AidRefDo{AID: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, ImplicitlySelectedApplication: true},
			expected: []byte{0xC0, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestDeviceConfigDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    DeviceConfigDo
		expected []byte
	}{
		{name: "Converts DeviceConfigDo to bytes",
			input:    DeviceConfigDo{DeviceInterfaceVersionDo{0x01, 0x01, 0x00}},
			expected: []byte{0xE4, 0x05, 0xE6, 0x03, 0x01, 0x01, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestAramConfigDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    AramConfigDo
		expected []byte
	}{
		{name: "Converts AramConfigDo to bytes",
			input:    AramConfigDo{DeviceInterfaceVersionDo{0x01, 0x01, 0x00}},
			expected: []byte{0xE5, 0x05, 0xE6, 0x03, 0x01, 0x01, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestDeviceInterfaceVersionDoBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    DeviceInterfaceVersionDo
		expected []byte
	}{
		{name: "Converts DeviceInterfaceVersionDo to bytes",
			input:    DeviceInterfaceVersionDo{0x01, 0x01, 0x00},
			expected: []byte{0xE6, 0x03, 0x01, 0x01, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.input.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
