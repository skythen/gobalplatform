// Package resource provides functions for parsing additional card resources e.g. defined by ETSI.
package resource

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/tag"
)

// ExtendedCardResourcesInformation provides information about card resources as defined by ETSI TS 102 226 V16.0.0.
type ExtendedCardResourcesInformation struct {
	InstalledApplications int // Number of installed applications.
	FreeNVM               int // Free non volatile memory available for at least applications loaded via ISD.
	FreeVM                int // Free volatile memory available for at least applications loaded via ISD.
}

// ParseExtendedCardResourcesInformation parses the BER-TLV encoded Extended Card Resources KeyInformation and returns ExtendedCardResourcesInformation.
func ParseExtendedCardResourcesInformation(b []byte) (*ExtendedCardResourcesInformation, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvExtended := tlvs.FindFirstWithTag(tag.ExtendedCardResourcesInformation)
	if tlvExtended == nil {
		return nil, errors.New("mandatory tag 'FF21' for Extended Card Resources KeyInformation not present")
	}

	tlvInstalledApplications := tlvExtended.FirstChild(tag.ETSIInstalledApplications)
	if tlvInstalledApplications == nil {
		return nil, errors.New("mandatory tag '81' for installed applications not present")
	}

	numApplications, err := bytesToInt(tlvInstalledApplications.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid length of number of installed applications")
	}

	tlvFreeNVM := tlvExtended.FirstChild(tag.ETSIFreeNonVolatileMemory)
	if tlvFreeNVM == nil {
		return nil, errors.New("mandatory tag '82' for free non volatile memory not present")
	}

	freeNVM, err := bytesToInt(tlvFreeNVM.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid value of free NVM")
	}

	tlvFreeVM := tlvExtended.FirstChild(tag.ETSIFreeVolatileMemory)
	if tlvFreeVM == nil {
		return nil, errors.New("mandatory tag '83' for free volatile memory not present")
	}

	freeVM, err := bytesToInt(tlvFreeVM.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid value of free VM")
	}

	return &ExtendedCardResourcesInformation{
		InstalledApplications: numApplications,
		FreeNVM:               freeNVM,
		FreeVM:                freeVM,
	}, nil
}

func bytesToInt(b []byte) (int, error) {
	var res int

	switch len(b) {
	case 1:
		return int(b[0]), nil
	case 2:
		res = int(binary.BigEndian.Uint16(b))
	case 4:
		res = int(binary.BigEndian.Uint32(b))
	case 8:
		res = int(binary.BigEndian.Uint64(b))
	default:
		return 0, errors.New("invalid length of bytes")
	}

	return res, nil
}

// KeyInformationTemplate is a list of KeyInformation.
type KeyInformationTemplate []KeyInformation

// KeyInformation contains information about key components (without the value of the component).
// It combines Basic with optional ExtendedKeyData.
type KeyInformation struct {
	Basic    KeyInformationData
	Extended *ExtendedKeyData
}

// KeyInformationData contains basic information about a key component.
type KeyInformationData struct {
	ID            byte           // ID of the key.
	VersionNumber byte           // Version number of the key.
	Components    []KeyComponent // List of components that belong to the referenced key.
}

// KeyComponent provides information about a key component.
type KeyComponent struct {
	Type                    byte   // Type of the key component.
	Length                  int    // Length of the key component (in bytes).
	ParameterReferenceValue []byte // Optional parameter reference value.
}

// ExtendedKeyData contains extended information about a key component.
type ExtendedKeyData struct {
	KeyUsage  UsageQualifierInfo
	KeyAccess byte
}

// UsageQualifierInfo contains usage qualifiers for keys contained in InformationTemplate.
type UsageQualifierInfo struct {
	Verification               bool
	Computation                bool
	SecureMessagingResponse    bool
	SecureMessagingCommand     bool
	Confidentiality            bool
	CryptographicChecksum      bool
	DigitalSignature           bool
	CryptographicAuthorization bool
}

// ParseUsageQualifier parses key usage encoded on one byte and returns UsageQualifierInfo.
// Note: according to GPC 2.3.1, the UsageQualifierInfo contained in Key KeyInformation Data Structure – Extended
// shall have a length of 0 or 1, although UsageQualifierInfo itself can be encoded on 2 byte.
// It is therefore asserted, that usage is only encoded on one byte.
func ParseUsageQualifier(b byte) *UsageQualifierInfo {
	uqi := &UsageQualifierInfo{}

	if b&0x80 == 0x80 {
		uqi.Verification = true
	}

	if b&0x40 == 0x40 {
		uqi.Computation = true
	}

	if b&0x20 == 0x20 {
		uqi.SecureMessagingResponse = true
	}

	if b&0x10 == 0x10 {
		uqi.SecureMessagingCommand = true
	}

	if b&0x08 == 0x08 {
		uqi.Confidentiality = true
	}

	if b&0x04 == 0x04 {
		uqi.CryptographicChecksum = true
	}

	if b&0x02 == 0x02 {
		uqi.DigitalSignature = true
	}

	if b&0x01 == 0x01 {
		uqi.CryptographicAuthorization = true
	}

	return uqi
}

// ParseKeyInformationTemplate parses the BER-TLV encoded Key KeyInformation Template and returns KeyInformationTemplate.
func ParseKeyInformationTemplate(b []byte) (*KeyInformationTemplate, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvKeyInformationTemplate := tlvs.FindFirstWithTag(tag.KeyInformationTemplate)
	if tlvKeyInformationTemplate == nil {
		return nil, errors.New("mandatory tag 'E0' for Key KeyInformation Template not present")
	}

	template := KeyInformationTemplate{}

	tlvKeyInformationData := tlvKeyInformationTemplate.Children(tag.KeyInformationData)

	for i, tlv := range tlvKeyInformationData {
		kid, err := parseKeyInformationDataValue(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid key information data value %d/%d", i+1, len(tlvKeyInformationData)))
		}

		template = append(template, *kid)
	}

	return &template, nil
}

func parseKeyInformationDataValue(b []byte) (*KeyInformation, error) {
	if len(b) < 4 {
		return nil, errors.Errorf("minimum length of Key KeyInformation Data is 4 bytes, got %d", len(b))
	}

	informationData := KeyInformationData{}
	informationData.ID = b[0]
	informationData.VersionNumber = b[1]
	informationData.Components = make([]KeyComponent, 0, len(b)/2)

	isExtended := false

	leftIndex := 2

	for numComponent := 0; leftIndex < len(b); numComponent++ {
		if numComponent == 0 {
			isExtended = b[leftIndex] == 0xFF
		} else {
			if isExtended != (b[leftIndex] == 0xFF) {
				return nil, errors.New("invalid mixing of basic and extended key components")
			}
		}

		component, read, err := parseFirstComponent(b[leftIndex:])
		if err != nil {
			return nil, errors.Wrap(err, "invalid component")
		}

		leftIndex += read

		informationData.Components = append(informationData.Components, *component)

		// extended key data is followed by a maximum of 4 bytes
		if isExtended && leftIndex+4 >= len(b) {
			break
		}
	}

	if !isExtended {
		return &KeyInformation{
			Basic:    informationData,
			Extended: nil,
		}, nil
	}

	extendedKeyData := ExtendedKeyData{}

	// check if key usage length is present
	if leftIndex >= len(b) {
		return nil, errors.New("key type indicates extended format, but key usage length is not present")
	}

	// check key usage length
	if b[leftIndex] != 0x00 {
		if b[leftIndex] != 0x01 {
			return nil, errors.Errorf("key usage length must be 0 or 1, indicated length: %d", b[leftIndex])
		}

		// check if value of key usage is present
		if len(b[leftIndex:])-1 == 0 {
			return nil, errors.New("key usage indicated but not present")
		}

		leftIndex++

		extendedKeyData.KeyUsage = *ParseUsageQualifier(b[leftIndex])
	}

	// check if at least one byte remains for encoding the length of key access
	if len(b[leftIndex:])-1 < 1 {
		return nil, errors.New("indicated extended key data but mandatory key access length not present")
	}

	leftIndex++

	// check key access length
	if b[leftIndex] != 0x00 {
		if b[leftIndex] != 0x01 {
			return nil, errors.Errorf("key access length must be 0 or 1, indicated length: %d", b[leftIndex])
		}

		// check if value of key access is present
		if len(b[leftIndex:])-1 == 0 {
			return nil, errors.New("key access indicated but not present")
		}

		leftIndex++

		extendedKeyData.KeyAccess = b[leftIndex]
	}

	return &KeyInformation{
		Basic:    informationData,
		Extended: &extendedKeyData,
	}, nil
}

func parseFirstComponent(data []byte) (component *KeyComponent, read int, err error) {
	var keyType byte

	// key type encoded on one byte
	// basic format
	if data[0] != 0xFF {
		keyType = data[0]

		if keyType != 0xF0 {
			return &KeyComponent{
				Type:                    keyType,
				Length:                  int(data[1]),
				ParameterReferenceValue: nil,
			}, 2, nil
		}

		// additional rule for key type 'F0'
		// For key type 'F0' (Key Parameter Reference), the length of the component is replaced by the value of the Key Parameter Reference (coded on 1 or 2 bytes).
		if len(data[1:]) != 1 && len(data[1:]) != 2 {
			return nil, 0, errors.New("when Key Type is Key Parameter Reference ('F0'), the value must be encoded with one or two byte")
		}

		return &KeyComponent{
			Type:                    keyType,
			Length:                  0,
			ParameterReferenceValue: data[1:],
		}, 1 + len(data[1:]), nil
	}

	// extended format
	keyType = data[1]

	// length is encoded on two byte
	if len(data[2:]) < 2 {
		return nil, 0, errors.Errorf("invalid length encoding of component in extended format")
	}

	if data[2] > 0x7F && data[3] == 0xFF {
		return nil, 0, errors.Errorf("indicated length of key component length must not be greater than 0x7FFF")
	}

	return &KeyComponent{
		Type:                    keyType,
		Length:                  int(binary.BigEndian.Uint16([]byte{data[2], data[3]})),
		ParameterReferenceValue: nil,
	}, 4, nil
}
