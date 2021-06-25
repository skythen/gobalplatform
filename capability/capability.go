// Package capability provides functions for parsing Card and Security Domain capabilities.
package capability

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/open"
	"github.com/skythen/gobalplatform/security"
	"github.com/skythen/gobalplatform/tag"
)

// SCPParameters contains information about supported SCPs and their implementation options of a Card or Security Domain.
type SCPParameters struct {
	SCP02 []security.SCP02Parameter // List of supported SCP02 options.
	SCP03 []security.SCP03Parameter // List of supported SCP03 options.
	SCP10 []security.SCP10Parameter // List of supported SCP10 options.
	Other []security.SCPParameter   // SCPs and their options that are unknown to the current implementation of this package.
}

// CardRecognitionData provides information about a Card such as the supported SCPs and parameters.
type CardRecognitionData struct {
	GPVersion                          string         // Version of the GlobalPlatform Card Specification a card conforms to.
	CardIdentificationSchemeOID        []byte         // Indicates a card that is uniquely identified by an IIN and CIN.
	SCPOptions                         *SCPParameters // Supported SCPs and options.
	CardConfigurationDetails           []byte         // BER-TLV encoded GlobalPlatform implementation details or commonly used Card Issuer parameter.
	CardAndChipDetails                 []byte         // BER-TLV encoded information about card and chip implementation, such as the operating system/runtime environment or a security kernel.
	SDTrustPointCertificateInformation []byte         // BER-TLV encoded TP-ISD related certificate information for SCP10.
	SDCertificateInformation           []byte         // BER-TLV encoded SD-related certificate information for SCP10.
}

// ParseCardRecognitionData parses the BER-TLV encoded Card Recognition Data and returns CardRecognitionData.
func ParseCardRecognitionData(b []byte) (*CardRecognitionData, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvCardData := tlvs.FindFirstWithTag(tag.CardData)
	if tlvCardData == nil {
		return nil, errors.New("mandatory tag '66' for Card Data not present")
	}

	tlvCardRecognitionData := tlvCardData.FirstChild(tag.CardRecognitionData)
	if tlvCardRecognitionData == nil {
		return nil, errors.New("mandatory tag '73' for Card Recognition Data not present")
	}

	crd, err := cardRecognitionDataFromTLV(tlvCardRecognitionData)
	if err != nil {
		return nil, errors.Wrap(err, "invalid Card Recognition Data")
	}

	return crd, nil
}

// SCPInformation provides information about a Secure Channel Protocol supported by a card.
// In case of SCP03 or SCP81 additional information is present.
type SCPInformation struct {
	Type                          byte                // Type of the SCP e.g. '02', '03, '11'.
	SupportedOptions              []byte              // Implementation options of the SCP.
	SCP03SupportedKeys            *SCP03SupportedKeys // Indicates supported key lengths for SCP03.
	SCP81SupportedTLSCipherSuites [][]byte            // Concatenation of 2-byte cipher suite numbers.
	SCP81MaxLengthPreSharedKey    util.NullByte       // Maximum length of a pre-shared key for SCP81.
}

// SCP03SupportedKeys provides supported key lengths for SCP03.
type SCP03SupportedKeys struct {
	AES128 bool // 128 bit key.
	AES192 bool // 192 bit key.
	AES256 bool // 256 bit key.
}

// ParseSCPInformation parses the BER-TLV encoded SCP information of one SCP and returns SCPInformation.
// If the SCP type is SCP03, SCP03SupportedKeys is present, otherwise nil.
// If the SCP type is SCP81, Supported TLS Cipher Suites SCP81 and Max Length Pre Shared Key SCP81 is present, otherwise nil.
func ParseSCPInformation(b []byte) (*SCPInformation, error) {
	si := &SCPInformation{}

	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvSCPInfo := tlvs.FindFirstWithTag(tag.SCPInformation)
	if tlvSCPInfo == nil {
		return nil, errors.New("mandatory tag 'A0' for SCP Information not present")
	}

	tlvSCPType := tlvSCPInfo.FirstChild(tag.SCPType)
	if tlvSCPType == nil {
		return nil, errors.New("mandatory tag '80' for SCP Type not present")
	}

	if len(tlvSCPType.Value) != 1 {
		return nil, errors.Errorf("SCP Type must be encoded with one byte, got %d", len(tlvSCPType.Value))
	}

	si.Type = tlvSCPType.Value[0]

	tlvSuppOpts := tlvSCPInfo.FirstChild(tag.SCPOptions)
	if tlvSuppOpts == nil {
		return nil, errors.New("mandatory tag '81' for SCP Option not present")
	}

	si.SupportedOptions = tlvSuppOpts.Value

	if si.Type == 0x03 {
		tlvSuppKeys := tlvSCPInfo.FirstChild(tag.SCP03SupportedKeys)
		if tlvSuppKeys == nil {
			return nil, errors.New("conditional tag '82' for supported SCP03 keys not present")
		}

		if len(tlvSuppKeys.Value) != 1 {
			return nil, errors.Errorf("supported SCP03 keys must be encoded in one byte, got %d", len(tlvSuppKeys.Value))
		}

		si.addSupportedKeysSCP03(tlvSuppKeys.Value[0])
	}

	if si.Type == 0x81 {
		err := si.addSCP81Information(tlvSCPInfo)
		if err != nil {
			return nil, errors.Wrap(err, "invalid SCP81 information")
		}
	}

	return si, nil
}

func (info *SCPInformation) addSupportedKeysSCP03(b byte) {
	info.SCP03SupportedKeys = &SCP03SupportedKeys{}

	if (b & 0x01) == 0x01 {
		info.SCP03SupportedKeys.AES128 = true
	}

	if (b & 0x02) == 0x02 {
		info.SCP03SupportedKeys.AES192 = true
	}

	if (b & 0x04) == 0x04 {
		info.SCP03SupportedKeys.AES256 = true
	}
}

func (info *SCPInformation) addSCP81Information(tlv *bertlv.BerTLV) error {
	tlvSuppTLSCipher := tlv.FirstChild(tag.SCP81SupportedCipherSuites)
	if tlvSuppTLSCipher == nil {
		return errors.New("conditional tag '81' for supported SCP81 cipher suites not present ")
	}

	if len(tlvSuppTLSCipher.Value)%2 != 0 {
		return errors.New("uneven number of bytes - each supported cipher suite for SCP81 must be encoded with two byte")
	}

	numSuites := len(tlvSuppTLSCipher.Value) / 2

	info.SCP81SupportedTLSCipherSuites = make([][]byte, 0, numSuites)

	for i := 0; i < len(tlvSuppTLSCipher.Value); i += 2 {
		info.SCP81SupportedTLSCipherSuites = append(info.SCP81SupportedTLSCipherSuites, []byte{tlvSuppTLSCipher.Value[i], tlvSuppTLSCipher.Value[i+1]})
	}

	tlvMaxLength := tlv.FirstChild(tag.SCP81PreSharedKeyMaxLength)
	if tlvMaxLength == nil {
		return errors.New("conditional tag '84' for SCP81 maximum length of pre shared key not present")
	}

	if len(tlvMaxLength.Value) != 1 {
		return errors.New("maximum length of pre shared key must be encoded with one byte ")
	}

	info.SCP81MaxLengthPreSharedKey = util.NullByte{Byte: tlvMaxLength.Value[0], Valid: true}

	return nil
}

// SecurityDomainManagementData contains information about a Security Domain such as supported SCPs and their parameters.
// The structure of SecurityDomainManagementData is similar to the structure of CardRecognitionData.
type SecurityDomainManagementData = CardRecognitionData

// ParseSecurityDomainManagementData parses the BER-TLV encoded Security Domain Management Data and returns SecurityDomainManagementData.
func ParseSecurityDomainManagementData(b []byte) (*SecurityDomainManagementData, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	// check for tag '73'
	tlvCardRecognitionData := tlvs.FindFirstWithTag(tag.CardRecognitionData)
	if tlvCardRecognitionData == nil {
		return nil, errors.New("mandatory tag '73' for Card Recognition Data not present")
	}

	return cardRecognitionDataFromTLV(tlvCardRecognitionData)
}

var (
	gpOID1 = []byte{0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01}
	gpOID2 = []byte{0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02}
	gpOID3 = []byte{0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03}
	gpOID4 = []byte{0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04}
)

func cardRecognitionDataFromTLV(ber *bertlv.BerTLV) (*CardRecognitionData, error) {
	crd := &CardRecognitionData{}

	tlvOIDGp1 := ber.FirstChild(tag.OID)
	if tlvOIDGp1 == nil {
		return nil, errors.New("mandatory tag '06' for GlobalPlatform OID not present")
	}

	// OID 1
	if !bytes.Equal(tlvOIDGp1.Value, gpOID1) {
		return nil, errors.Errorf("object with tag '06' does not contain the GlobalPlatform OID 1 - expected: %02X got: %02X", gpOID1, tlvOIDGp1.Value)
	}

	// application tag 0
	tlvApplication0 := ber.FirstChild(tag.GPOID2)
	if tlvApplication0 != nil {
		// gp 2 oid
		tlvOIDGp2 := tlvApplication0.FirstChild(tag.OID)
		if tlvOIDGp2 != nil {
			ver := tlvOIDGp2.Value[len(gpOID2):]

			err := crd.addGPVersion(ver)
			if err != nil {
				return nil, err
			}
		}
	}

	// application tag 3
	if tlv := ber.FirstChild(tag.GPOID3); tlv != nil {
		// gp 3 oid
		tlvOIDGp3 := tlv.FirstChild(tag.OID)
		if tlvOIDGp3 != nil {
			err := crd.addCardIdentificationScheme(tlvOIDGp3.Value)
			if err != nil {
				return nil, errors.Wrap(err, "invalid Card Identification Scheme")
			}
		}
	}

	// application tag 4
	tlvApplication4s := ber.Children(tag.GPOID4)
	for _, application4 := range tlvApplication4s {
		tlvOIDsGp4 := application4.Children(tag.OID)

		err := crd.addSCPParameters(tlvOIDsGp4)
		if err != nil {
			return nil, err
		}
	}

	tlvCardConfigurationDetails := ber.FirstChild(tag.GPCardConfigurationDetails)
	if tlvCardConfigurationDetails != nil {
		crd.CardConfigurationDetails = tlvCardConfigurationDetails.Bytes()
	}

	tlvCardAndChipDetails := ber.FirstChild(tag.CardAndChipDetails)
	if tlvCardAndChipDetails != nil {
		crd.CardAndChipDetails = tlvCardAndChipDetails.Bytes()
	}

	tlvISDTrustPoint := ber.FirstChild(tag.ISDTrustPoint)
	if tlvISDTrustPoint != nil {
		crd.SDTrustPointCertificateInformation = tlvISDTrustPoint.Bytes()
	}

	tlvISDDomainCertificate := ber.FirstChild(tag.ISDCertificateInformation)
	if tlvISDDomainCertificate != nil {
		crd.SDCertificateInformation = tlvISDDomainCertificate.Bytes()
	}

	return crd, nil
}

func (crd *CardRecognitionData) addCardIdentificationScheme(b []byte) error {
	if !bytes.Equal(b, gpOID3) {
		return errors.Errorf("invalid OID for Card Identification Scheme, expected: %02X got: %02X", gpOID3, b)
	}

	crd.CardIdentificationSchemeOID = b

	return nil
}

func (crd *CardRecognitionData) addGPVersion(version []byte) error {
	if len(version) == 2 {
		crd.GPVersion = strconv.Itoa(int(version[0])) + "." + strconv.Itoa(int(version[1]))
	} else if len(version) == 3 {
		crd.GPVersion = strconv.Itoa(int(version[0])) + "." + strconv.Itoa(int(version[1])) + "." + strconv.Itoa(int(version[2]))
	} else {
		return errors.Errorf("GlobalPlatform Version must be encoded with 2 or 3 byte, got: %d", len(version))
	}

	return nil
}

func (crd *CardRecognitionData) addSCPParameters(tlvOIDsGp4 []bertlv.BerTLV) error {
	for _, t := range tlvOIDsGp4 {
		if !bytes.Equal(t.Value[:len(gpOID4)], gpOID4) {
			return errors.Errorf("invalid GlobalPlatform OID, expected: %02X got: %02X", gpOID4, t.Value[:len(gpOID4)])
		}

		// oid must contain the SCP identifier + i param
		// the specification is not clear about whether multiple i params can be present in one oid
		if len(t.Value) != len(gpOID4)+2 {
			return errors.New("GlobalPlatform 4 OID must contain an SCP identifier")
		}

		scpTag := t.Value[len(gpOID4)]
		// get the i param
		i := t.Value[len(gpOID4)+1]

		if crd.SCPOptions == nil {
			crd.SCPOptions = &SCPParameters{}
		}

		switch scpTag {
		case 0x02:
			if crd.SCPOptions.SCP02 == nil {
				crd.SCPOptions.SCP02 = make([]security.SCP02Parameter, 0, len(gpOID4))
			}

			crd.SCPOptions.SCP02 = append(crd.SCPOptions.SCP02, *security.ParseSCP02Parameter(i))
		case 0x03:
			if crd.SCPOptions.SCP03 == nil {
				crd.SCPOptions.SCP03 = make([]security.SCP03Parameter, 0, len(gpOID4))
			}

			crd.SCPOptions.SCP03 = append(crd.SCPOptions.SCP03, *security.ParseSCP03Parameter(i))
		case 0x10:
			if crd.SCPOptions.SCP10 == nil {
				crd.SCPOptions.SCP10 = make([]security.SCP10Parameter, 0, len(gpOID4))
			}

			crd.SCPOptions.SCP10 = append(crd.SCPOptions.SCP10, *security.ParseSCP10Parameter(i))
		default:
			if crd.SCPOptions.Other == nil {
				crd.SCPOptions.Other = make([]security.SCPParameter, 0, len(tlvOIDsGp4))
			}

			crd.SCPOptions.Other = append(crd.SCPOptions.Other, security.SCPParameter{
				ID:     scpTag,
				Option: i,
			})
		}
	}

	return nil
}

// CardCapabilityInformation provides information complementary to CardRecognitionData about the SCPs, cipher suites and algorithms actually supported by a card.
type CardCapabilityInformation struct {
	SCPInformation                  []SCPInformation               // Indicates support of a Secure Channel Protocol by the card (at least one).
	AssignableSSDPrivileges         open.Privileges                // Indicates the privileges that may actually be assigned to Supplementary Security Domains on this card if the card supports Supplementary Security Domains.
	AssignableApplicationPrivileges open.Privileges                // Indicates the privileges that may actually be assigned to Applications on this card.
	LFDBHAlgorithms                 SupportedLFDBHAlgorithms       // Indicates the algorithms supported by the card to compute the Load File Data Block Hash.
	CipherSuitesLFDBEnc             *CipherSuitesForLFDBEncryption // Indicates the encryption schemes supported by the card if the card supports Ciphered Load File Data Block.
	CipherSuitesTokens              *CipherSuitesForSignature      // Indicates the signature schemes for Token Verification supported by the card if the card supports Delegated Management.
	CipherSuitesReceipts            *CipherSuitesForSignature      // Indicates the signature schemes for Receipt Generation supported by the card if the card supports Delegated Management.
	CipherSuitesDAPs                *CipherSuitesForSignature      // Indicates the signature schemes supported by the card for DAP Verification if the card supports Supplementary Security Domains.
	KeyParameterReferenceList       *KeyParameterReferenceValues   // Indicates the supported Key Parameter Reference Values by the card if the card supports Delegated Management and/or DAP Verification schemes based on EC cryptography.
}

// ParseCardCapabilityInformation parses the BER-TLV encoded Card Capability Information and returns CardCapabilityInformation.
func ParseCardCapabilityInformation(b []byte) (*CardCapabilityInformation, error) {
	cci := &CardCapabilityInformation{}

	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvCardCapabilityInformation := tlvs.FindFirstWithTag(tag.CardCapabilityInformation)
	if tlvCardCapabilityInformation == nil {
		return nil, errors.New("mandatory tag '67' for Card Capability Information not present")
	}

	tlvsSCPInformation := tlvCardCapabilityInformation.Children(tag.SCPInformation)
	if len(tlvsSCPInformation) == 0 {
		return nil, errors.New("at least one tag 'A0' for SCP Information must be present")
	}

	err = cci.addSCPInformation(tlvsSCPInformation)
	if err != nil {
		return nil, errors.Wrap(err, "invalid SCP Information")
	}

	tlvAppPrivileges := tlvCardCapabilityInformation.FirstChild(tag.ApplicationPrivileges)
	if tlvAppPrivileges == nil {
		return nil, errors.New("mandatory tag '82' for assignable application privileges not present")
	}

	err = cci.addAssignableApplicationPrivileges(tlvAppPrivileges.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid assignable Application Privileges")
	}

	tlvLFDBHAlgorithms := tlvCardCapabilityInformation.FirstChild(tag.LFDBHAlgorithms)
	if tlvLFDBHAlgorithms == nil {
		return nil, errors.New("mandatory tag '83' for supported LFDBH Algorithms not present")
	}

	cci.addLFDBHAlgorithms(tlvLFDBHAlgorithms.Value)

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.SSDPrivileges); tlv != nil {
		err = cci.addAssignableSSDPrivileges(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Assignable SSD Privileges")
		}
	}

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.CipherSuitesForLFDBEncryption); tlv != nil {
		err = cci.addCipherSuitesLFDBEncryption(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Cipher Suites for LFDB Encryption")
		}
	}

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.CipherSuitesForTokens); tlv != nil {
		err = cci.addCipherSuitesTokens(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Cipher Suites for Tokens")
		}
	}

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.CipherSuitesForReceipts); tlv != nil {
		err = cci.addCipherSuitesReceipts(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Cipher Suites for Receipts")
		}
	}

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.CipherSuitesForDAPs); tlv != nil {
		err = cci.addCipherSuitesDAPs(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Cipher Suites for DAPs")
		}
	}

	if tlv := tlvCardCapabilityInformation.FirstChild(tag.KeyParameterReferenceList); tlv != nil {
		err = cci.addKeyParameterReferenceList(tlv.Value)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Key Parameter Reference List")
		}
	}

	return cci, nil
}

func (cci *CardCapabilityInformation) addLFDBHAlgorithms(b []byte) {
	for _, b := range b {
		switch b {
		case 0x01:
			cci.LFDBHAlgorithms.SHA1 = true
		case 0x02:
			cci.LFDBHAlgorithms.SHA256 = true
		case 0x03:
			cci.LFDBHAlgorithms.SHA384 = true
		case 0x04:
			cci.LFDBHAlgorithms.SHA512 = true
		}
	}
}

func (cci *CardCapabilityInformation) addSCPInformation(tlvs []bertlv.BerTLV) error {
	for i, tlvScpInformation := range tlvs {
		var scpInfo, err = ParseSCPInformation(tlvScpInformation.Bytes())
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("invalid SCP Information %d/%d", i+1, len(tlvs)))
		}

		cci.SCPInformation = append(cci.SCPInformation, *scpInfo)
	}

	return nil
}

func (cci *CardCapabilityInformation) addAssignableApplicationPrivileges(b []byte) error {
	if len(b) != 3 {
		return errors.Errorf("assignable application privileges must be encoded with 3 byte, got %d", len(b))
	}

	cci.AssignableApplicationPrivileges = open.ParsePrivileges([3]byte{b[0], b[1], b[2]})

	return nil
}

func (cci *CardCapabilityInformation) addAssignableSSDPrivileges(b []byte) error {
	if len(b) != 3 {
		return errors.Errorf("assignable SSD privileges must be encoded with 3 byte, got %d", len(b))
	}

	cci.AssignableSSDPrivileges = open.ParsePrivileges([3]byte{b[0], b[1], b[2]})

	return nil
}

func (cci *CardCapabilityInformation) addCipherSuitesLFDBEncryption(b []byte) error {
	if len(b) != 1 {
		return errors.Errorf("supported cipher suites for LFDB encryption must be encoded with 1 byte, got %d", len(b))
	}

	cci.CipherSuitesLFDBEnc = ParseCipherSuitesForLFDBEncryption(b[0])

	return nil
}

func (cci *CardCapabilityInformation) addCipherSuitesTokens(b []byte) error {
	if len(b) == 0 || len(b) > 2 {
		return errors.Errorf("supported cipher suites for tokens must be encoded with 1 or 2 byte, got  %d", len(b))
	}

	if len(b) == 2 {
		cci.CipherSuitesTokens = ParseCipherSuitesForSignature([2]byte{b[0], b[1]})
	} else {
		cci.CipherSuitesTokens = ParseCipherSuitesForSignature([2]byte{b[0], 0x00})
	}

	return nil
}

func (cci *CardCapabilityInformation) addCipherSuitesReceipts(b []byte) error {
	if len(b) == 0 || len(b) > 2 {
		return errors.Errorf("supported cipher suites for receipts must be encoded with 2 byte, got %d", len(b))
	}

	if len(b) == 2 {
		cci.CipherSuitesReceipts = ParseCipherSuitesForSignature([2]byte{b[0], b[1]})
	} else {
		cci.CipherSuitesReceipts = ParseCipherSuitesForSignature([2]byte{b[0], 0x00})
	}

	return nil
}

func (cci *CardCapabilityInformation) addCipherSuitesDAPs(b []byte) error {
	if len(b) == 0 || len(b) > 2 {
		return errors.Errorf("supported cipher suites for DAPs must be encoded with 2 byte, got %d", len(b))
	}

	if len(b) == 2 {
		cci.CipherSuitesDAPs = ParseCipherSuitesForSignature([2]byte{b[0], b[1]})
	} else {
		cci.CipherSuitesDAPs = ParseCipherSuitesForSignature([2]byte{b[0], 0x00})
	}

	return nil
}

func (cci *CardCapabilityInformation) addKeyParameterReferenceList(b []byte) error {
	kprv, err := ParseKeyParameterReferenceValues(b)
	if err != nil {
		return errors.Wrap(err, "invalid Key Parameter Reference List")
	}

	cci.KeyParameterReferenceList = kprv

	return nil
}

// CipherSuitesForLFDBEncryption provids the supported cipher suites for Load File Data Block encryption.
type CipherSuitesForLFDBEncryption struct {
	TripleDES16Byte      bool // Triple DES with 16 byte key length.
	AES128               bool // AES-128.
	AES192               bool // AES-192.
	AES256               bool // AES-256.
	ICVForLFDBEncryption bool // ICV supported for LFDB encryption.
}

// ParseCipherSuitesForLFDBEncryption parses a byte and returns CipherSuitesForLFDBEncryption.
func ParseCipherSuitesForLFDBEncryption(b byte) *CipherSuitesForLFDBEncryption {
	cs := &CipherSuitesForLFDBEncryption{}

	if b&0x01 == 0x01 {
		cs.TripleDES16Byte = true
	}

	if b&0x02 == 0x02 {
		cs.AES128 = true
	}

	if b&0x04 == 0x04 {
		cs.AES192 = true
	}

	if b&0x08 == 0x08 {
		cs.AES256 = true
	}

	if b&0x80 == 0x80 {
		cs.ICVForLFDBEncryption = true
	}

	return cs
}

// CipherSuitesForSignature provides the supported cipher suites for signature calculation.
type CipherSuitesForSignature struct {
	Rsa1024SsaPkcsV15SHA1            bool // RSA-1024 / RSASSA-PKCS-v1_5 / SHA-1.
	RsaSsaPssSHA256                  bool // RSA >1024 / RSASSA-PSS / SHA-256.
	SingleDESPlusFinalTripleDESMac16 bool // 16 byte key / Single DES plus Final Triple DES MAC.
	CmacAES128                       bool // CMAC using AES-128.
	CmacAES192                       bool // CMAC using AES-192.
	CmacAES256                       bool // CMAC using AES-256.
	ECDSAWithEC256AndSHA256          bool // ECDSA using ECC-256 and SHA-256.
	ECDSAWithEC384AndSHA384          bool // ECDSA using ECC-384 and SHA-384.
	ECDSAWithEC512AndSHA512          bool // ECDSA using ECC-512 and SHA-512.
	ECDSAWithEC521AndSHA512          bool // ECDSA using ECC-521 and SHA-512.
}

// ParseCipherSuitesForSignature parses cipher suites encoded on two bytes and returns CipherSuitesForSignature.
func ParseCipherSuitesForSignature(b [2]byte) *CipherSuitesForSignature {
	cs := &CipherSuitesForSignature{}

	if b[0]&0x01 == 0x01 {
		cs.Rsa1024SsaPkcsV15SHA1 = true
	}

	if b[0]&0x02 == 0x02 {
		cs.RsaSsaPssSHA256 = true
	}

	if b[0]&0x04 == 0x04 {
		cs.SingleDESPlusFinalTripleDESMac16 = true
	}

	if b[0]&0x08 == 0x08 {
		cs.CmacAES128 = true
	}

	if b[0]&0x10 == 0x10 {
		cs.CmacAES192 = true
	}

	if b[0]&0x20 == 0x20 {
		cs.CmacAES256 = true
	}

	if b[0]&0x40 == 0x40 {
		cs.ECDSAWithEC256AndSHA256 = true
	}

	if b[0]&0x80 == 0x80 {
		cs.ECDSAWithEC384AndSHA384 = true
	}

	if b[1]&0x01 == 0x01 {
		cs.ECDSAWithEC512AndSHA512 = true
	}

	if b[1]&0x02 == 0x02 {
		cs.ECDSAWithEC521AndSHA512 = true
	}

	return cs
}

// SupportedLFDBHAlgorithms represents the supported hash algorithms for Load File Data Block Hash calculation.
type SupportedLFDBHAlgorithms struct {
	SHA1   bool
	SHA256 bool
	SHA384 bool
	SHA512 bool
}

// KeyParameterReferenceValues contains the Key Parameter Reference Values that can be used to refer to a set of curve parameters.
type KeyParameterReferenceValues struct {
	P256                        bool
	P384                        bool
	P521                        bool
	BrainpoolP256r1             bool
	BrainpoolP256t1             bool
	BrainpoolP384r1             bool
	BrainpoolP384t1             bool
	BrainpoolP512r1             bool
	BrainpoolP512t1             bool
	ProprietaryGlobalReferences [][]byte
	LocalKeyParameterReferences [][]byte
}

// ParseKeyParameterReferenceValues parses the concatenated Key Parameter Reference Values and returns KeyParameterReferenceValues.
func ParseKeyParameterReferenceValues(b []byte) (*KeyParameterReferenceValues, error) {
	kprv := &KeyParameterReferenceValues{}

	for i := 0; i < len(b); i++ {
		switch b[i] {
		case 0x00:
			kprv.P256 = true
		case 0x01:
			kprv.P384 = true
		case 0x02:
			kprv.P521 = true
		case 0x03:
			kprv.BrainpoolP256r1 = true
		case 0x04:
			kprv.BrainpoolP256t1 = true
		case 0x05:
			kprv.BrainpoolP384r1 = true
		case 0x06:
			kprv.BrainpoolP384t1 = true
		case 0x07:
			kprv.BrainpoolP512r1 = true
		case 0x08:
			kprv.BrainpoolP512t1 = true
		default:
			if b[i] >= 0x40 && b[i] <= 0x5F {
				kprv.ProprietaryGlobalReferences = append(kprv.ProprietaryGlobalReferences, []byte{b[i]})

				continue
			}

			if b[i] >= 0x60 && b[i] <= 0x7F {
				kprv.LocalKeyParameterReferences = append(kprv.LocalKeyParameterReferences, []byte{b[i]})

				continue
			}

			if b[i] >= 0xC0 && b[i] <= 0xDF {
				// value must be encoded with two byte
				if len(b)-1 < i+1 {
					return nil, errors.New("expected encoding of proprietary global references with two byte but got only one")
				}

				kprv.ProprietaryGlobalReferences = append(kprv.ProprietaryGlobalReferences, []byte{b[i], b[i+1]})
				i++

				continue
			}

			if b[i] >= 0xE0 {
				// value must be encoded with two byte
				if len(b)-1 < i+1 {
					return nil, errors.New("expected encoding of local key parameter references with two byte but got only one")
				}

				kprv.LocalKeyParameterReferences = append(kprv.LocalKeyParameterReferences, []byte{b[i], b[i+1]})
				i++

				continue
			}
		}
	}

	return kprv, nil
}

// FileControlInformation is the FCI template for Security Domains.
type FileControlInformation struct {
	AID             aid.AID // AID of the Security Domain.
	ProprietaryData ProprietaryData
}

// ParseFileControlInformation parses the BER-TLV encoded File Control Information and returns FileControlInformation.
func ParseFileControlInformation(b []byte) (*FileControlInformation, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	// search for fci tag
	tlvFci := tlvs.FindFirstWithTag(tag.FCI)
	if tlvFci == nil {
		return nil, errors.New("FCI tag not found in data")
	}

	tlvAid := tlvFci.FirstChild(tag.FileAID)
	if tlvAid == nil {
		return nil, errors.New("FCI does not contain the mandatory AID")
	}

	appAid, err := aid.ParseAID(tlvAid.Value)
	if err != nil {
		return nil, errors.New("invalid AID")
	}

	tlvProp := tlvFci.FirstChild(tag.ProprietaryData)
	if tlvProp == nil {
		return nil, errors.New("FCI does not contain mandatory proprietary data")
	}

	data, err := proprietaryDataFromTLV(tlvProp)
	if err != nil {
		return nil, errors.New("invalid proprietary data")
	}

	return &FileControlInformation{
		AID:             *appAid,
		ProprietaryData: *data,
	}, nil
}

// ProprietaryData contains proprietary data contained in File Control Information.
type ProprietaryData struct {
	SecurityDomainManagementData       *SecurityDomainManagementData
	ApplicationProductionLifeCycleData []byte
	MaximumCommandDataFieldLength      uint64
}

func parseProprietaryData(b []byte) (*ProprietaryData, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvProp := tlvs.FindFirstWithTag(tag.ProprietaryData)
	if tlvProp == nil {
		return nil, errors.New("mandatory tag 'A5' for proprietary data must be present")
	}

	return proprietaryDataFromTLV(tlvProp)
}

func proprietaryDataFromTLV(ber *bertlv.BerTLV) (*ProprietaryData, error) {
	proprietaryData := &ProprietaryData{}

	if tlv := ber.FirstChild(tag.CardRecognitionData); tlv != nil {
		smd, err := cardRecognitionDataFromTLV(tlv)
		if err != nil {
			return nil, errors.Wrap(err, "invalid Security Domain Management Data")
		}

		proprietaryData.SecurityDomainManagementData = smd
	}

	if tlv := ber.FirstChild(tag.ApplicationProductionLifeCycleData); tlv != nil {
		proprietaryData.ApplicationProductionLifeCycleData = tlv.Value
	}

	tlvMaxCmdLen := ber.FirstChild(tag.MaximumCommandDataLength)
	if tlvMaxCmdLen == nil {
		return nil, fmt.Errorf("mandatory tag '9F65' for maximum command length must be present")
	}

	proprietaryData.MaximumCommandDataFieldLength = uint64(tlvMaxCmdLen.Value[0])

	return proprietaryData, nil
}
