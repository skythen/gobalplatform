// Package key provides functions for preparing keys for import into a card.
package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"

	"github.com/pkg/errors"
	"gobalplatform/internal/util"
)

// UsageType is a key usage type that is used by GlobalPlatform.
type UsageType int

const (
	CMac            UsageType = iota
	RMac                      = iota
	CMacRMac                  = iota
	CEnc                      = iota
	REnc                      = iota
	CEncREnc                  = iota
	CDek                      = iota
	RDek                      = iota
	CDekRDek                  = iota
	PkSdAut                   = iota
	SkSdAut                   = iota
	Token                     = iota
	Receipt                   = iota
	Dap                       = iota
	PkSdAutToken              = iota
	SkSdAutReceipt            = iota
	PkSdAutDap                = iota
	PkSdAutTokenDap           = iota
)

const (
	TypeDES                      byte = 0x80
	TypeAES                      byte = 0x88
	AccessSdAndApplication       byte = 0x00
	AccessSdOnly                 byte = 0x01
	AccessApplicationOnly        byte = 0x02
	AccessNotAvailable           byte = 0xFF
	TypePreSharedTLS             byte = 0x85
	TypeHMACSHA1                 byte = 0x90
	TypeHMACSHA160               byte = 0x91
	TypeRSAPublicKeyE            byte = 0xA0
	TypeRSAPublicKeyN            byte = 0xA1
	TypeRSAPrivateKeyN           byte = 0xA2
	TypeRSAPrivateKeyD           byte = 0xA3
	TypeRSAPrivateKeyCRTP        byte = 0xA4
	TypeRSAPrivateKeyCRTQ        byte = 0xA5
	TypeRSAPrivateKeyCRTPQ       byte = 0xA6
	TypeRSAPrivateKeyCRTDP1      byte = 0xA7
	TypeRSAPrivateKeyCRTDQ1      byte = 0xA8
	TypeECCPublicKey             byte = 0xB0
	TypeECCPrivateKey            byte = 0xB1
	TypeECCFieldParameterP       byte = 0xB2
	TypeECCFieldParameterA       byte = 0xB3
	TypeECCFieldParameterB       byte = 0xB4
	TypeECCFieldParameterG       byte = 0xB5
	TypeECCFieldParameterN       byte = 0xB6
	TypeECCFieldParameterK       byte = 0xB7
	TypeECCKeyParameterReference byte = 0xF0
	TypeExtendedFormat           byte = 0xFF
)

// ComponentBasic is a key component in basic format.
type ComponentBasic struct {
	Type  byte           // Type of the Key Components.
	Block ComponentBlock // Block with a Key Components.
	KCV   []byte         // Optional Key Check Value.
}

// NewComponentBasic creates a new ComponentBasic.
//
// If the key component value needs be encrypted, it shall be encrypted with the DEK key of the current secure messaging session.
//
// Depending on the indicated padding length, the key component is either wrapped with a ComponentPaddedBlock (in case of applied padding)
// or a ComponentUnpaddedBlock (in case of no padding).
//
// For some key components it is required to provide a key check value (e.g. for AES or DES keys).
//
// If you want to provide details regarding key usage and key access, use NewComponentExtended.
func NewComponentBasic(keyComponentType byte, keyComponentValue, kcv []byte, paddingLength int) *ComponentBasic {
	cb := &ComponentBasic{}

	var block ComponentBlock

	cb.Type = keyComponentType

	if paddingLength != 0 {
		block = ComponentPaddedBlock{
			LengthComponent: len(keyComponentValue) - paddingLength,
			Value:           keyComponentValue,
		}
	} else {
		block = ComponentUnpaddedBlock{
			Value: keyComponentValue,
		}
	}

	cb.Block = block
	cb.KCV = kcv

	return cb
}

// ComponentBlock is the interface that encodes key component blocks on bytes.
type ComponentBlock interface {
	Bytes() ([]byte, error)
}

// ComponentPaddedBlock is a key component block that contains an encrypted key component and the length of
// padding that has been applied to the key component for encryption.
type ComponentPaddedBlock struct {
	LengthComponent int
	Value           []byte // For a public key component, the key component value does not need to be encrypted and the Key Components Block only contains the clear-text key component value.
}

//  Bytes implements the ComponentBlock interface and encodes ComponentPaddedBlock on LV-encoded bytes
func (block ComponentPaddedBlock) Bytes() ([]byte, error) {
	lengthComponent, err := util.BuildGPBerLength(uint(block.LengthComponent))
	if err != nil {
		return nil, errors.Wrap(err, "build BER length")
	}

	bytes := make([]byte, 0, len(lengthComponent)+len(block.Value))
	bytes = append(bytes, lengthComponent...)
	bytes = append(bytes, block.Value...)

	return bytes, nil
}

// ComponentUnpaddedBlock is a key component block that contains a key component that might have been encrypted, but not padded.
type ComponentUnpaddedBlock struct {
	Value []byte
}

// Bytes implements the ComponentBlock interface.
func (block ComponentUnpaddedBlock) Bytes() ([]byte, error) {
	return block.Value, nil
}

// ComponentExtended is a key component in extended format.
type ComponentExtended struct {
	ComponentBasic
	UsageQualifier UsageQualifier // Key Usage Qualifier.
	Access         util.NullByte  // Key Access.
}

// NewComponentExtended creates a new ComponentExtended with a key component.
// It calls NewComponentBasic and adds the extended data Key Usage Qualifier and Key Access.
//
// If the key component value needs to be encrypted, it shall be encrypted with the DEK key of the current secure messaging session.
//
// Depending on the indicated padding length, the key component is either wrapped with a ComponentPaddedBlock (in case of applied padding)
// or a ComponentUnpaddedBlock (in case of no padding).
//
// For some key components it is required to provide a key check value (e.g. for AES or DES keys).
func NewComponentExtended(keyComponentType byte, keyComponentValue, kcv []byte, paddingLength int, keyUsage UsageQualifier, keyAccess util.NullByte) *ComponentExtended {
	cb := NewComponentBasic(keyComponentType, keyComponentValue, kcv, paddingLength)

	return &ComponentExtended{
		ComponentBasic: *cb,
		UsageQualifier: keyUsage,
		Access:         keyAccess,
	}
}

// UsageQualifier contains usage qualifiers for keys.
type UsageQualifier struct {
	Verification               bool
	Computation                bool
	SecureMessagingResponse    bool
	SecureMessagingCommand     bool
	Confidentiality            bool
	CryptographicChecksum      bool
	DigitalSignature           bool
	CryptographicAuthorization bool
	KeyAgreement               bool
}

// Bytes encodes UsageQualifier on 1-2 bytes, depending on the presence of KeyAgreement.
func (uq UsageQualifier) Bytes() []byte {
	var bytes []byte

	if uq.KeyAgreement {
		bytes = make([]byte, 2)
		bytes[1] += 0x80
	} else {
		bytes = make([]byte, 1)
	}

	if uq.Verification {
		bytes[0] += 0x80
	}

	if uq.Computation {
		bytes[0] += 0x40
	}

	if uq.SecureMessagingResponse {
		bytes[0] += 0x20
	}

	if uq.SecureMessagingCommand {
		bytes[0] += 0x10
	}

	if uq.Confidentiality {
		bytes[0] += 0x08
	}

	if uq.CryptographicChecksum {
		bytes[0] += 0x04
	}

	if uq.DigitalSignature {
		bytes[0] += 0x02
	}

	if uq.CryptographicAuthorization {
		bytes[0] += 0x01
	}

	return bytes
}

// UsageForType returns UsageQualifier configured for the given UsageType.
func UsageForType(usage UsageType) *UsageQualifier {
	uqi := UsageQualifier{}

	switch usage {
	case CMac:
		uqi.CryptographicChecksum = true
		uqi.SecureMessagingCommand = true
	case RMac:
		uqi.CryptographicChecksum = true
		uqi.SecureMessagingResponse = true
	case CMacRMac:
		uqi.CryptographicChecksum = true
		uqi.SecureMessagingCommand = true
		uqi.SecureMessagingResponse = true
	case CEnc:
		uqi.Confidentiality = true
		uqi.SecureMessagingCommand = true
	case REnc:
		uqi.Confidentiality = true
		uqi.SecureMessagingResponse = true
	case CEncREnc:
		uqi.Confidentiality = true
		uqi.SecureMessagingResponse = true
		uqi.SecureMessagingCommand = true
	case CDek:
		uqi.Computation = true
		uqi.Confidentiality = true
	case RDek:
		uqi.Verification = true
		uqi.Confidentiality = true
	case CDekRDek:
		uqi.Computation = true
		uqi.Verification = true
		uqi.Confidentiality = true
	case PkSdAut:
		uqi.Verification = true
		uqi.DigitalSignature = true
	case SkSdAut:
		uqi.Computation = true
		uqi.DigitalSignature = true
	case Token:
		uqi.Verification = true
		uqi.CryptographicAuthorization = true
	case Receipt:
		uqi.Computation = true
		uqi.CryptographicChecksum = true
	case Dap:
		uqi.Verification = true
		uqi.CryptographicChecksum = true
	case PkSdAutToken:
		uqi.Verification = true
		uqi.DigitalSignature = true
		uqi.CryptographicAuthorization = true
	case SkSdAutReceipt:
		uqi.Computation = true
		uqi.DigitalSignature = true
		uqi.CryptographicAuthorization = true
	case PkSdAutDap:
		uqi.Verification = true
		uqi.DigitalSignature = true
		uqi.CryptographicChecksum = true
	case PkSdAutTokenDap:
		uqi.Verification = true
		uqi.DigitalSignature = true
		uqi.CryptographicChecksum = true
		uqi.CryptographicAuthorization = true
	}

	return &uqi
}

// DataBasic represents the data field of a PUT KEY command and contains a list of ComponentBasic.
type DataBasic struct {
	Components []ComponentBasic
}

// Bytes encodes DataBasic on LV-encoded bytes.
func (db DataBasic) Bytes() ([]byte, error) {
	var (
		length int
		err    error
	)

	bBlocks := make([][]byte, len(db.Components))
	bBlockLength := make([][]byte, len(db.Components))

	// calculate length
	for i, component := range db.Components {
		// length key type length field = 1 and length key check value length field = 1
		length += 2

		bBlocks[i], err = component.Block.Bytes()
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid key component block %d/%d", i, len(db.Components)))
		}

		bBlockLength[i], err = util.BuildGPBerLength(uint(len(bBlocks[i])))
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("build BER length for Key Components %d/%d", i, len(db.Components)))
		}

		length += len(bBlockLength[i])
		length += len(bBlocks[i])
		length += len(component.KCV)
	}

	bytes := make([]byte, 0, length)

	for i, com := range db.Components {
		bytes = append(bytes, com.Type)
		bytes = append(bytes, bBlockLength[i]...)
		bytes = append(bytes, bBlocks[i]...)
		bytes = append(bytes, byte(len(com.KCV)))
		bytes = append(bytes, com.KCV...)
	}

	return bytes, nil
}

// DataBasic represents the data field of a PUT KEY command and contains a list of ComponentExtended.
type DataExtended struct {
	Components []ComponentExtended
}

// Bytes encodes DataExtended on LV-encoded bytes.
func (de DataExtended) Bytes() ([]byte, error) {
	var (
		length int
		err    error
	)

	bBlocks := make([][]byte, len(de.Components))
	bBlockLength := make([][]byte, len(de.Components))
	bKeyUsage := make([][]byte, len(de.Components))

	for i, component := range de.Components {
		length += 6

		// Length of Key Components Block
		bBlocks[i], err = component.Block.Bytes()
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid key component block %d/%d", i+1, len(de.Components)))
		}

		bBlockLength[i], err = util.BuildGPBerLength(uint(len(bBlocks[i])))
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("build BER length for Key Components %d/%d", i, len(de.Components)))
		}

		bKeyUsage[i] = component.UsageQualifier.Bytes()

		length += len(bBlockLength[i])
		length += len(bBlocks[i])
		length += len(component.KCV)
		length += len(bKeyUsage[i])
	}

	bytes := make([]byte, 0, length)

	for i, com := range de.Components {
		bytes = append(bytes, []byte{0xFF, com.Type}...)
		bytes = append(bytes, bBlockLength[i]...)
		bytes = append(bytes, bBlocks[i]...)
		bytes = append(bytes, byte(len(com.KCV)))
		bytes = append(bytes, com.KCV...)
		bytes = append(bytes, byte(len(bKeyUsage[i])))
		bytes = append(bytes, bKeyUsage[i]...)

		if com.Access.Valid {
			bytes = append(bytes, 0x01)
			bytes = append(bytes, com.Access.Byte)
		}
	}

	return bytes, nil
}

var (
	secpr1k          = []byte{0x01} // cofactor of G is 1 for all Secp curves
	secp224r1A       = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}
	secp256r1A       = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC}
	secp384r1A       = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC}
	secp521r1A       = []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC}
	brainpool1K      = []byte{0x01} // cofactor of G is 1 for all bp curves
	brainpoolP256t1A = []byte{0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x74}
	brainpoolP256r1A = []byte{0x7D, 0x5A, 0x09, 0x75, 0xFC, 0x2C, 0x30, 0x57, 0xEE, 0xF6, 0x75, 0x30, 0x41, 0x7A, 0xFF, 0xE7, 0xFB, 0x80, 0x55, 0xC1, 0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9}
	brainpoolP384t1A = []byte{0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4, 0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x50}
	brainpoolP384r1A = []byte{0x7B, 0xC3, 0x82, 0xC6, 0x3D, 0x8C, 0x15, 0x0C, 0x3C, 0x72, 0x08, 0x0A, 0xCE, 0x05, 0xAF, 0xA0, 0xC2, 0xBE, 0xA2, 0x8E, 0x4F, 0xB2, 0x27, 0x87, 0x13, 0x91, 0x65, 0xEF, 0xBA, 0x91, 0xF9, 0x0F, 0x8A, 0xA5, 0x81, 0x4A, 0x50, 0x3A, 0xD4, 0xEB, 0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26}
	brainpoolP512r1A = []byte{0x78, 0x30, 0xA3, 0x31, 0x8B, 0x60, 0x3B, 0x89, 0xE2, 0x32, 0x71, 0x45, 0xAC, 0x23, 0x4C, 0xC5, 0x94, 0xCB, 0xDD, 0x8D, 0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA}
	brainpoolP512t1A = []byte{0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6, 0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF0}
	aesKCVInput      = []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	desKCVInput      = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

// GetCurveParametersAk returns field parameters A and k of an elliptic curve as ComponentBasic.
// Supported curve names are: P-224, P-256, P-384, P-521, brainpoolP256t1, brainpoolP256r1, brainpoolP384t1, brainpoolP384r1, brainpoolP512t1 and brainpoolP512r1
func GetCurveParametersAk(curvename string) (kcParameterA, kcParameterK *ComponentBasic, err error) {
	switch curvename {
	case "P-224":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, secp224r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, secpr1k, nil, 0)
	case "P-256":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, secp256r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, secpr1k, nil, 0)
	case "P-384":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, secp384r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, secpr1k, nil, 0)
	case "P-521":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, secp521r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, secpr1k, nil, 0)
	case "brainpoolP256t1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP256t1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	case "brainpoolP256r1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP256r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	case "brainpoolP384t1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP384t1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	case "brainpoolP384r1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP384r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	case "brainpoolP512t1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP512t1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	case "brainpoolP512r1":
		kcParameterA = NewComponentBasic(TypeECCFieldParameterA, brainpoolP512r1A, nil, 0)
		kcParameterK = NewComponentBasic(TypeECCFieldParameterK, brainpool1K, nil, 0)
	default:
		return nil, nil, errors.New("unsupported curve or unknown curve name")
	}

	return kcParameterA, kcParameterK, nil
}

// KCV calculates a key check value for AES and DES keys.
func KCV(keyType byte, key []byte) ([3]byte, error) {
	if keyType != TypeAES && keyType != TypeDES {
		return [3]byte{}, errors.Errorf("unknown key type - must be either DES '80' or AES '88, got %02X", keyType)
	}

	if keyType == TypeAES {
		return aesKCV(key)
	}

	return desKCV(key)
}

func aesKCV(key []byte) ([3]byte, error) {
	var kcv [3]byte

	ac, err := aes.NewCipher(key)
	if err != nil {
		return kcv, errors.Wrap(err, "create AES cipher for calculating KCV")
	}

	iv := make([]byte, 16)

	encCheckVal := make([]byte, 16)

	cbcEncData := cipher.NewCBCEncrypter(ac, iv)

	cbcEncData.CryptBlocks(encCheckVal, aesKCVInput)

	copy(kcv[:], encCheckVal[:3])

	return kcv, nil
}

func desKCV(key []byte) ([3]byte, error) {
	var kcv [3]byte

	if len(key) != 16 {
		return kcv, errors.Errorf("DES key for calculating KCV must be 16 byte long, got %d", len(key))
	}

	desKey := key[:8]

	dc, err := des.NewCipher(desKey)
	if err != nil {
		return kcv, errors.Wrap(err, "create DES cipher for calculating DES KCV")
	}

	iv := make([]byte, 8)

	encCheckVal := make([]byte, 8)

	cbcEncData := cipher.NewCBCEncrypter(dc, iv)

	cbcEncData.CryptBlocks(encCheckVal, desKCVInput)

	copy(kcv[:], encCheckVal[:3])

	return kcv, nil
}
