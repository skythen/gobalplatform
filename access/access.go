// Package access implements parsing and creation of objects specified by GlobalPlatform Secure Element Access Control v1.1.
package access

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/tag"
)

var (
	// AramElfAid is the AID of the Executable Load File of Access Rule Application Master.
	AramElfAid = aid.AID{0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C}
	// AramEmAid is the AID of the Executable Module of Access Rule Application Master.
	AramEmAid = aid.AID{0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00}
	// AramAid is the AID of the Access Rule Application Master instance.
	AramAid = aid.AID{0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00}
	// Pkcs15Aid is the AID of the PKCS#15 file structure or application.
	Pkcs15Aid = aid.AID{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35}
)

const (
	// Never is the value for NEVER in access rules.
	Never byte = 0x00
	// Always is the value for ALWAYS in access rules.
	Always byte = 0x01
)

// RefArDo is a REF-AR-DO and contains an ArDo and the corresponding RefDo.
type RefArDo struct {
	RefDo RefDo
	ArDo  ArDo
}

// ArDo is an AR-DO and contains one or two access rules of type APDU or NFC.
type ArDo struct {
	ApduArDo *ApduArDo
	NfcArDo  *NfcArDo
}

// ApduArDo is an APDU-AR-DO and defines an access rule for APDU access.
// The APDU access can either be restricted by a generic rule based on an “access is NEVER/ALWAYS allowed” policy (one byte length)
// or by a specific rule based on APDU filters which defines the range of allowed APDUs more precisely (eight byte length).
type ApduArDo []byte

// NfcArDo is a NFC-AR-DO which defines an access rule for generating NFC events for a specific device application.
// The NFC event access can be restricted by a rule based on an “event access is NEVER/ALWAYS allowed” policy.
type NfcArDo util.NullByte

// RefDo is a REF-DO which contains a pair of an AID-REF-DO and a DeviceAppId-REF-DO.
type RefDo struct {
	AidRefDo         AidRefDo
	DeviceAppIDRefDo DeviceAppIDRefDo
}

// AidRefDo is an AID-REF-DO which is used for storing and retrieving the corresponding access rules for an SE application (which is identified by its AID) to and from the ARA
// Two different reference data objects exist and one of these can be chosen and applied for a GET DATA and STORE DATA command
// If the AidRefDo shall be interpreted as implicitly selected application, the value of AID is set to nil and ImplicitlySelectedApplication to true.
// If it indicates a wildcard for SE applications, the AID is set to an empty []byte and ImplicitlySelectedApplication to false.
// If it indicates a specific AID (or partial AID), the value of AID contains the AID and ImplicitlySelectedApplication is set to false.
type AidRefDo struct {
	AID                           []byte
	ImplicitlySelectedApplication bool
}

// DeviceAppIDRefDo is a DeviceAppID-REF-DO which identifies the specific device application that an access rule applies to
// It contains one of following values:
// • Hash of the certificate of the Application Provider: Used in most cases when the application is running in the REE.
// • Unique identifier (this could be a TA UUID or Windows Phone 8 AppID) of the application:
// Empty:
// Indicates that the rules apply to all device applications not covered by a specific rule.
type DeviceAppIDRefDo struct {
	DeviceAppID []byte
}

// DeviceConfigDo is a Device-Config-DO.
type DeviceConfigDo struct {
	DeviceInterfaceVersionDo DeviceInterfaceVersionDo
}

// AramConfigDo is a ARAM-Config-DO.
type AramConfigDo struct {
	DeviceInterfaceVersionDo DeviceInterfaceVersionDo
}

// DeviceInterfaceVersionDo is a Device-Interface-Version-DO.
type DeviceInterfaceVersionDo []byte

// NewGenericApduArDo creates an ApduArDo from a given byte.
// This ApduArDo contains a generic APDU access rule:
// NEVER ('00'): APDU access is not allowed
// ALWAYS('01'): APDU access is allowed.
func NewGenericApduArDo(rule byte) (*ApduArDo, error) {
	if rule != Never && rule != Always {
		return nil, errors.Errorf("value must be either 0 (NEVER) or 1 (ALWAYS), got %d", rule)
	}

	return &ApduArDo{rule}, nil
}

// NewFilterApduArDo creates an ApduArDo struct containing an APDU filter for a given header and mask
// This ApduArDo contains a specific APDU access rule based on one or more APDU filter(SCP):
// APDU filter: 8-byte APDU filter consists of:
// 4-byte APDU filter header (defines the header of allowed APDUs, i.e. CLA, INS, P1, and P2 as defined in [7816-4])
// 4-byte APDU filter mask (bit set defines the bits which shall be considered for the APDU header comparison)
// An APDU filter shall be applied to the header of the APDU being checked, as follows:
// if((APDU_header & APDU_filter_mask) == APDU_filter_header) then allow APDU.
func NewFilterApduArDo(header []byte, mask []byte) (*ApduArDo, error) {
	if len(header) != 4 || len(mask) != 4 {
		return nil, errors.New("len of header and mask must be 4 bytes")
	}

	rule := make(ApduArDo, 0, 8)
	rule = append(rule, header...)
	rule = append(rule, mask...)

	return &rule, nil
}

// ParseAllRefArDo parses BER-TLV encoded ALL-REF-AR-DO and returns a slice of RefArDo.
func ParseAllRefArDo(b []byte) ([]RefArDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse ALL-REF-AR-DO - invalid BER-TLV")
	}

	refArDos, err := allRefArDosFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse ALL-REF-AR-DO")
	}

	return refArDos, nil
}

func allRefArDosFromTlv(t bertlv.BerTLV) ([]RefArDo, error) {
	if !bytes.Equal(t.Tag, tag.AllRefDo[:]) {
		return nil, errors.Errorf("ALL-REF-AR-DO must have tag 'FF40', got: %02X", t.Tag)
	}

	tRefArDos := t.Children(tag.RefArDo)
	if len(tRefArDos) == 0 {
		return nil, nil
	}

	refArDos := make([]RefArDo, 0, len(tRefArDos))

	for _, child := range tRefArDos {
		refArDo, err := refArDoFromTlv(child)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid AR-DO: %02X", child.Bytes()))
		}

		refArDos = append(refArDos, *refArDo)
	}

	return refArDos, nil
}

// ParseRefArDo parses BER-TLV encoded REF-AR-DO and returns RefArDo.
func ParseRefArDo(b []byte) (*RefArDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse REF-AR-DO - invalid BER-TLV")
	}

	refArDo, err := refArDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse REF-AR-DO")
	}

	return refArDo, nil
}

func refArDoFromTlv(t bertlv.BerTLV) (*RefArDo, error) {
	if !bytes.Equal(t.Tag, tag.RefArDo) {
		return nil, errors.Errorf("REF-AR-DO must have tag 'E2', got: %02X", t.Tag)
	}

	c := t.Children(nil)
	if !(len(c) == 2) ||
		!bytes.Equal(c[0].Tag, tag.RefDo) ||
		!bytes.Equal(c[1].Tag, tag.ArDo) {
		return nil, errors.New("object must consist of the concatenation of REF-DO ('E1') | AR-DO ('E3')")
	}

	refDo, err := refDoFromTlv(c[0])
	if err != nil {
		return nil, errors.Wrap(err, "object contains invalid REF-DO")
	}

	arDo, err := arDoFromTlv(c[1])
	if err != nil {
		return nil, errors.Wrap(err, "object contains invalid AR-DO")
	}

	return &RefArDo{
		RefDo: *refDo,
		ArDo:  *arDo,
	}, nil
}

// ParseRefDo parses BER-TLV encoded REF-DO and returns RefDo.
func ParseRefDo(b []byte) (*RefDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse REF-DO - invalid BER-TLV")
	}

	refDo, err := refDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse REF-DO")
	}

	return refDo, err
}

func refDoFromTlv(t bertlv.BerTLV) (*RefDo, error) {
	if !bytes.Equal(t.Tag, tag.RefDo) {
		return nil, errors.Errorf("REF-DO must have tag 'E1', got: %02X", t.Tag)
	}

	c := t.Children(nil)
	if !(len(c) == 2) ||
		(!bytes.Equal(c[0].Tag, tag.AID)) && !bytes.Equal(c[0].Tag, tag.ImplicitlySelectedApplication) ||
		!bytes.Equal(c[1].Tag, tag.DeviceAppIDRefDo) {
		return nil, errors.New("object must consist of the concatenation of AID-REF-DO ('4F'/'C0') | DEVICE-APP-ID-REF-DO ('C1')")
	}

	var (
		aidRefDo *AidRefDo
		err      error
	)

	tAidRefDo := c[0]
	// AID-REF-DO without value is used for wild card rules
	if len(tAidRefDo.Value) != 0 {
		aidRefDo, err = aidRefDoFromTlv(tAidRefDo)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid AID-REF-DO: %02X", tAidRefDo.Bytes()))
		}
	}

	tDeviceAppIDRefDo := c[1]

	devAppIDRefDo, err := deviceAppIDRefDoFromTlv(tDeviceAppIDRefDo)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid DeviceAppID-REF-DO : %02X", tDeviceAppIDRefDo.Bytes()))
	}

	return &RefDo{
		AidRefDo:         *aidRefDo,
		DeviceAppIDRefDo: *devAppIDRefDo,
	}, nil
}

// ParseDeviceAppIDRefDO parses BER-TLV encoded DeviceAppID-REF-DO and returns DeviceAppIDRefDo.
func ParseDeviceAppIDRefDO(b []byte) (*DeviceAppIDRefDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse DeviceAppID-REF-DO - invalid BER-TLV")
	}

	devAppIDRefDo, err := deviceAppIDRefDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse DeviceAppID-REF-DO")
	}

	return devAppIDRefDo, nil
}

func deviceAppIDRefDoFromTlv(t bertlv.BerTLV) (*DeviceAppIDRefDo, error) {
	if !bytes.Equal(t.Tag, tag.DeviceAppIDRefDo) {
		return nil, errors.Errorf("DeviceAppID-REF-DO must have tag 'C1', got: %02X", t.Tag)
	}

	if len(t.Value) == 0 {
		return &DeviceAppIDRefDo{DeviceAppID: []byte{}}, nil
	}

	if len(t.Value) != 20 {
		return nil, errors.Errorf("if a DeviceAppID-REF-DO contains a value, it must be 20 bytes long, got %d", len(t.Value))
	}

	return &DeviceAppIDRefDo{DeviceAppID: t.Value}, nil
}

// ParseArDo parses BER-TLV encoded AR-DO and returns an ArDo.
func ParseArDo(b []byte) (*ArDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse AR-DO - invalid BER-TLV")
	}

	arDo, err := arDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse AR-DO")
	}

	return arDo, nil
}

func arDoFromTlv(t bertlv.BerTLV) (*ArDo, error) {
	if !bytes.Equal(t.Tag, tag.ArDo) {
		return nil, errors.Errorf("AR-DO must have tag 'E3', got: %02X", t.Tag)
	}

	var (
		apduArDo *ApduArDo
		nfcArDo  *NfcArDo
		err      error
	)

	// AR-DO with one child must contain either a APDU-AR-DO or NFC-AR-DO
	if len(t.Children(nil)) == 1 {
		c := t.FirstChild(nil)

		if bytes.Equal(c.Tag, tag.ApduArDo) {
			apduArDo, err = apduArdoFromTlv(*c)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid DeviceAppID-REF-DO : %02X", c.Bytes()))
			}
		} else if bytes.Equal(c.Tag, tag.NfcArDo) {
			nfcArDo, err = nfcArDoFromTlv(*c)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid NFC-AR-DO : %02X", c.Bytes()))
			}
		} else {
			return nil, errors.Errorf("if an AR-DO contains only one child, it must either be an APDU-AR-DO ('D0') or NFC-AR-DO ('D1'), got: %02X", c.Tag)
		}
	} else if len(t.Children(nil)) == 2 { // AR-DO with two children must be a concatenation of APDU-AR-DO | NFC-AR-DO
		c := t.Children(nil)

		if !bytes.Equal(c[0].Tag, tag.ApduArDo) ||
			!bytes.Equal(c[1].Tag, tag.NfcArDo) {
			return nil, errors.New("object must consist of the concatenation APDU-AR-DO ('D0') | NFC-AR-DO ('D1')")
		}

		apduArDo, err = apduArdoFromTlv(c[0])
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid APDU-AR-DO: %02X", c[0].Bytes()))
		}

		nfcArDo, err = nfcArDoFromTlv(c[1])
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("object contains invalid NFC-AR-DO: %02X", c[1].Bytes()))
		}
	}

	return &ArDo{
		ApduArDo: apduArDo,
		NfcArDo:  nfcArDo,
	}, nil
}

// ParseApduArDo parses BER-TLV encoded APDU-AR-DO and returns an ApduArDo.
func ParseApduArDo(b []byte) (*ApduArDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse APDU-AR-DO - invalid BER-TLV")
	}

	apduArDo, err := apduArdoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse APDU-AR-DO")
	}

	return apduArDo, nil
}

func apduArdoFromTlv(t bertlv.BerTLV) (*ApduArDo, error) {
	if len(t.Value) != 1 && len(t.Value)%8 != 0 {
		return nil, errors.Errorf("object has invalid length - must be either 1 or a multiple of 8, got %d", len(t.Value))
	}

	var ruleValue ApduArDo

	if len(t.Value) == 1 {
		if t.Value[0] != 0x00 && t.Value[0] != 0x01 {
			return nil, errors.Errorf("invalid value of APDU-AR-DO - must be 0 (NEVER) or 1 (ALWAYS), got: %d", t.Value[0])
		}

		ruleValue = t.Value
	} else {
		ruleValue = t.Value
	}

	return &ruleValue, nil
}

// ParseNfcArDo parses BER-TLV encoded bytes and returns an NfcArDo.
func ParseNfcArDo(b []byte) (*NfcArDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse NFC-AR-DO - invalid BER-TLV")
	}

	nfcArDo, err := nfcArDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse NFC-AR-DO")
	}

	return nfcArDo, nil
}

func nfcArDoFromTlv(t bertlv.BerTLV) (*NfcArDo, error) {
	if !bytes.Equal(t.Tag, tag.NfcArDo) {
		return nil, errors.Errorf("NFC-AR-DO must have tag 'D1', got: %02X", t.Value)
	}

	if len(t.Value) != 1 {
		return nil, errors.Errorf("invalid length of NFC-AR-DO value - must be 1 byte, got: %d", len(t.Value))
	}

	if t.Value[0] != 0 && t.Value[0] != 1 {
		return nil, errors.Errorf("invalid value of NFC-AR-DO - must be 0 (NEVER) or 1 (ALWAYS), got: %d", t.Value[0])
	}

	return &NfcArDo{
		Byte:  t.Value[0],
		Valid: true,
	}, nil
}

// ParseARAMConfigDo parses BER-TLV encoded ARAM-CONFIG-DO and returns an AramConfigDo.
func ParseARAMConfigDo(b []byte) (*AramConfigDo, error) {
	// since the tag of DeviceInterfaceVersion-DO (E6) indicates a constructed structure, but is not constructed,
	// the ARAMConfig-DO cannot be parsed with bertlv.Parse() since this would throw errors
	if len(b) != 7 {
		return nil, errors.Errorf("parse ARAM-Config-DO - invalid length: must be 7 byte long, got: %d", len(b))
	}

	if b[0] != tag.AramConfigDo[0] {
		return nil, errors.Errorf("parse ARAM-Config-DO - must have tag 'E5', got: %02X", b[0])
	}

	if b[1] != 0x05 {
		return nil, errors.Errorf("parse ARAM-Config-DO - invalid encoding of length: must be 5, got: %d", b[1])
	}

	deviceInterfaceVersionDo, err := ParseDeviceInterfaceVersionDo(b[2:])
	if err != nil {
		return nil, errors.Errorf("parse ARAM-Config-DO - object contains invalid Device-Interface-Version-DO: %02X", b[2:])
	}

	return &AramConfigDo{DeviceInterfaceVersionDo: *deviceInterfaceVersionDo}, nil
}

// ParseDeviceInterfaceVersionDo parses BER-TLV encoded Device-Interface-Version-DO and returns an DeviceInterfaceVersionDo.
func ParseDeviceInterfaceVersionDo(b []byte) (*DeviceInterfaceVersionDo, error) {
	if len(b) != 5 {
		return nil, errors.Errorf("parse Device-Interface-Version-DO - invalid length: must be 5 byte long, got: %d", len(b))
	}

	if b[0] != tag.DeviceInterfaceVersionDo[0] {
		return nil, errors.Errorf("parse Device-Interface-Version-DO - must have tag 'E6', got: %d", b[0])
	}

	return &DeviceInterfaceVersionDo{b[2], b[3], b[4]}, nil
}

// ParseAidRefDo parses BER-TLV encoded AID-REF-DO and returns an AidRefDo.
func ParseAidRefDo(b []byte) (*AidRefDo, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "parse AID-REF-DO - invalid BER-TLV")
	}

	aidRefDo, err := aidRefDoFromTlv(tlvs[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse AID-REF-DO")
	}

	return aidRefDo, nil
}

func aidRefDoFromTlv(t bertlv.BerTLV) (*AidRefDo, error) {
	if !bytes.Equal(t.Tag, tag.AID) && !bytes.Equal(t.Tag, tag.ImplicitlySelectedApplication) {
		return nil, errors.Errorf("AID-REF-DO must have either the '4F' or the 'C0' tag, got %02X", t.Tag)
	}

	// check for implicitly selected first
	if t.Tag[0] == tag.ImplicitlySelectedApplication[0] {
		if len(t.Value) != 0 {
			return nil, errors.New("AID-REF-DO contains invalid value for object with tag 'C0' - must be empty")
		}

		return &AidRefDo{
			AID:                           nil,
			ImplicitlySelectedApplication: true,
		}, nil
	}

	// handle 4F tag
	appID := t.Value

	// wildcard
	if len(appID) == 0 {
		return &AidRefDo{
			AID:                           []byte{}, // return empty slice for indicating non-nil but empty value
			ImplicitlySelectedApplication: false,
		}, nil
	}

	// full or partial AID
	if len(appID) < 5 || len(appID) > 16 {
		return nil, errors.Errorf("AID-REF-DO contains invalid value for object with tag '4F' - must be 0, or 5-16 byte long, got %d", len(appID))
	}

	return &AidRefDo{
		AID:                           appID,
		ImplicitlySelectedApplication: false,
	}, nil
}

// Bytes returns DeviceAppIDRefDo as BER-TLV encoded bytes.
func (dev DeviceAppIDRefDo) Bytes() []byte {
	if len(dev.DeviceAppID) == 0 {
		return bertlv.Builder{}.AddEmpty(tag.DeviceAppIDRefDo).Bytes()
	}

	// 	Unique identifier (this could be a TA UUID or Windows Phone 8 AppID) of the application:
	//	Used when the application is running in the TEE or when it is running
	//	in the REE but the certificate is not an appropriate identifier.
	//	This unique identifier shall be padded with 'FF' in order to provide a length of 20 bytes.
	if len(dev.DeviceAppID) < 20 {
		result := make([]byte, 0, 20)
		result = append(result, dev.DeviceAppID...)

		for i := len(dev.DeviceAppID); i < cap(result); i++ {
			result = append(result, 0xFF)
		}

		return bertlv.Builder{}.AddBytes(tag.DeviceAppIDRefDo, result).Bytes()
	}

	//	Hash of the certificate of the Application Provider
	if len(dev.DeviceAppID) == 20 {
		return bertlv.Builder{}.AddBytes(tag.DeviceAppIDRefDo, dev.DeviceAppID).Bytes()
	}

	return nil
}

// Bytes returns RefArDo as BER-TLV encoded bytes.
func (ref RefArDo) Bytes() []byte {
	deviceAppIDRefDo := ref.RefDo.Bytes()
	arDo := ref.ArDo.Bytes()
	result := make([]byte, 0, len(deviceAppIDRefDo)+len(arDo))
	result = append(result, deviceAppIDRefDo...)
	result = append(result, arDo...)

	return bertlv.Builder{}.AddBytes(tag.RefArDo, result).Bytes()
}

// Bytes returns ArDo as BER-TLV encoded bytes.
func (ar ArDo) Bytes() []byte {
	var apduArdo []byte

	var nfcArDo []byte

	if ar.ApduArDo != nil {
		apduArdo = ar.ApduArDo.Bytes()
	}

	if ar.NfcArDo != nil {
		nfcArDo = ar.NfcArDo.Bytes()
	}

	result := make([]byte, 0, len(apduArdo)+len(nfcArDo))
	result = append(result, apduArdo...)
	result = append(result, nfcArDo...)

	return bertlv.Builder{}.AddBytes(tag.ArDo, result).Bytes()
}

// Bytes returns ApduArDo as BER-TLV encoded bytes.
func (ap ApduArDo) Bytes() []byte {
	if len(ap) == 1 {
		return bertlv.Builder{}.AddByte(tag.ApduArDo, ap[0]).Bytes()
	}

	return bertlv.Builder{}.AddBytes(tag.ApduArDo, ap).Bytes()
}

// Bytes returns NfcArDo as BER-TLV encoded bytes.
func (nfc NfcArDo) Bytes() []byte {
	return bertlv.Builder{}.AddByte(tag.NfcArDo, nfc.Byte).Bytes()
}

// Bytes returns RefDo as BER-TLV encoded bytes.
func (ref RefDo) Bytes() []byte {
	aidRefDo := ref.AidRefDo.Bytes()

	deviceAppIDRefDo := ref.DeviceAppIDRefDo.Bytes()

	result := make([]byte, 0, len(aidRefDo)+len(deviceAppIDRefDo))
	result = append(result, aidRefDo...)
	result = append(result, deviceAppIDRefDo...)

	return bertlv.Builder{}.AddBytes(tag.RefDo, result).Bytes()
}

// Bytes returns AidRefDo as BER-TLV encoded bytes.
// If AidRefDo.ImplicitlySelectedApplication is true, the AidRefDo.AID will be ignored.
func (ai AidRefDo) Bytes() []byte {
	if !ai.ImplicitlySelectedApplication {
		return bertlv.Builder{}.AddBytes(tag.AID, ai.AID).Bytes()
	}

	return bertlv.Builder{}.AddEmpty(tag.ImplicitlySelectedApplication).Bytes()
}

// Bytes returns DeviceConfigDo as BER-TLV encoded bytes.
func (dev DeviceConfigDo) Bytes() []byte {
	return bertlv.Builder{}.AddBytes(tag.DeviceConfigDo, dev.DeviceInterfaceVersionDo.Bytes()).Bytes()
}

// Bytes returns AramConfigDo as BER-TLV encoded bytes.
func (ar AramConfigDo) Bytes() []byte {
	return bertlv.Builder{}.AddBytes(tag.AramConfigDo, ar.DeviceInterfaceVersionDo.Bytes()).Bytes()
}

// Bytes returns DeviceInterfaceVersionDo as BER-TLV encoded bytes.
func (dev DeviceInterfaceVersionDo) Bytes() []byte {
	return bertlv.Builder{}.AddBytes(tag.DeviceInterfaceVersionDo, dev).Bytes()
}
