// Package open provides functions for handling data related to the GlobalPlatform Environment OPEN.
package open

import (
	"fmt"
	"math/bits"

	"github.com/pkg/errors"
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/tag"
)

const (
	LCSElfLoaded                       byte = 0x01
	LCSApplicationInstalled            byte = 0x03
	LCSApplicationSelectable           byte = 0x07
	LCSApplicationLockedFromInstalled  byte = 0x83
	LCSApplicationLockedFromSelectable byte = 0x87
	LCSSDInstalled                     byte = 0x03
	LCSSDSelectable                    byte = 0x07
	LCSSDPersonalized                  byte = 0x0F
	LCSSDLockedFromInstalled           byte = 0x83
	LCSSDLockedFromSelectable          byte = 0x87
	LCSSDLockedFromPersonalized        byte = 0x8F
	LCSCardOpReady                     byte = 0x01
	LCSCardInitialized                 byte = 0x07
	LCSCardSecured                     byte = 0x0F
	LCSCardLocked                      byte = 0x7F
	LCSCardTerminated                  byte = 0xFF
)

// ImplicitSelectionParameters represents parameters that can be assigned to an application for implicit selection.
// Setting both ContactlessIO and ContactIO to false indicates that this Application is to be selectable only explicitly
// with a SELECT [by name] command and the logical channel number shall be ignored by the card.
type ImplicitSelectionParameters struct {
	ContactlessIO  bool // Implicit selection on contactless interface.
	ContactIO      bool // Implicit selection on contact interface.
	LogicalChannel int  // ID of the logical Channel the application is implicit selected on.
}

// ParseImplicitSelectionParameters parses ImplicitSelectionParameters encoded on a byte.
func ParseImplicitSelectionParameters(b byte) *ImplicitSelectionParameters {
	isp := &ImplicitSelectionParameters{}

	if b&0x80 == 0x80 {
		isp.ContactlessIO = true
	}

	if b&0x40 == 0x40 {
		isp.ContactIO = true
	}

	isp.LogicalChannel = int(b & 0x1F)

	return isp
}

// ApplicationData represents application related data that can be retrieved from the GlobalPlatform Registry.
type ApplicationData struct {
	AID                         aid.AID                       // AID of the application.
	LifeCycleState              byte                          // Life Cycle State of the application.
	Privileges                  Privileges                    // Assigned privileges of the application.
	ImplicitSelectionParameters []ImplicitSelectionParameters // List of Implicit Selection Parameters of the application.
	ELFAID                      aid.AID                       // AID of the ELF that belongs to the application.
	AssociatedSecurityDomainAID aid.AID                       // AID of the currently associated Security Domain.
}

// ParseApplicationData parses the BER-TLV encoded application data and returns a list of ApplicationData.
func ParseApplicationData(b []byte) ([]ApplicationData, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvRegistryData := tlvs.FindAllWithTag(tag.RegistryRelatedData)
	if tlvRegistryData == nil {
		return nil, errors.New("mandatory tag 'E3' for GlobalPlatform Registry related data not present")
	}

	applicationData := make([]ApplicationData, 0, len(tlvRegistryData))

	for i, ad := range tlvRegistryData {
		data, err := applicationDataFromTLV(ad)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid application data %d/%d", i, len(tlvRegistryData)))
		}

		applicationData = append(applicationData, *data)
	}

	return applicationData, nil
}

func applicationDataFromTLV(ad bertlv.BerTLV) (*ApplicationData, error) {
	data := &ApplicationData{}

	tlvAID := ad.FirstChild(tag.AID)
	if tlvAID == nil {
		return nil, errors.New("mandatory tag '4F' for AID not present")
	}

	applicationID, err := aid.ParseAID(tlvAID.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AID")
	}

	data.AID = *applicationID

	tlvLCS := ad.FirstChild(tag.LifeCycleState)
	if tlvLCS == nil {
		return nil, errors.New("mandatory tag '9F70' for Life Cycle State not present")
	}

	// TODO some SCs return the life cycle state encoded on 2 byte, with the second byte being 0 ?!
	if len(tlvLCS.Value) != 1 && len(tlvLCS.Value) != 2 {
		return nil, fmt.Errorf("life cycle state must be encoded with one or two byte, got %d", len(tlvLCS.Value))
	}

	data.LifeCycleState = tlvLCS.Value[0]

	tlvPrivs := ad.FirstChild(tag.Privileges)
	if tlvPrivs == nil {
		return nil, errors.New("mandatory tag 'C5' for Privileges not present")
	}

	if len(tlvPrivs.Value) != 3 {
		return nil, fmt.Errorf("privileges must be encoded with three byte, got %d", len(tlvPrivs.Value))
	}

	data.Privileges = ParsePrivileges([3]byte{tlvPrivs.Value[0], tlvPrivs.Value[1], tlvPrivs.Value[2]})

	tlvELFAID := ad.FirstChild(tag.ApplicationELFAID)
	if tlvELFAID == nil {
		return nil, errors.New("mandatory tag 'C4' for Executable Load File AID not present")
	}

	elfAID, err := aid.ParseAID(tlvELFAID.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AID for Executable Load File")
	}

	data.ELFAID = *elfAID

	tlvSDAID := ad.FirstChild(tag.AssociatedSDAID)
	if tlvSDAID == nil {
		return nil, errors.New("mandatory tag 'CC' for Associated Security Domain AID not present")
	}

	sdAID, err := aid.ParseAID(tlvSDAID.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AID")
	}

	data.AssociatedSecurityDomainAID = *sdAID

	if tlvISPs := ad.Children(tag.ImplicitSelectionParameter); tlvISPs != nil {
		isps := make([]ImplicitSelectionParameters, 0, len(tlvISPs))

		for _, isp := range tlvISPs {
			if len(isp.Value) != 1 {
				return nil, fmt.Errorf("implicit selection parameters must be encoded with one byte each, got %d", len(isp.Value))
			}

			isps = append(isps, *ParseImplicitSelectionParameters(isp.Value[0]))
		}

		data.ImplicitSelectionParameters = isps
	}

	return data, nil
}

// MajorMinorVersion represents the encoding of a version in the format 'Major.Minor'.
type MajorMinorVersion struct {
	Major int
	Minor int
}

// ExecutableLoadFileData represents executable load file related data that can be retrieved from the GlobalPlatform Registry.
type ExecutableLoadFileData struct {
	AID             aid.AID           // AID of the ELF.
	LifeCycleState  byte              // Life Cycle State of the ELF.
	VersionNumber   MajorMinorVersion // Version of the ELF.
	EMAIDs          []aid.AID         // List of AIDs of the contained Executable Modules if present.
	AssociatedSDAID aid.AID           // AID of the currently associated Security Domain.
}

// ParseExecutableLoadFileData parses the BER-TLV encoded Executable Load File Data and returns a list of ExecutableLoadFileData.
func ParseExecutableLoadFileData(b []byte) ([]ExecutableLoadFileData, error) {
	tlvs, err := bertlv.Parse(b)
	if err != nil {
		return nil, errors.Wrap(err, "invalid BER-TLV")
	}

	tlvRegistryData := tlvs.FindAllWithTag(tag.RegistryRelatedData)
	if tlvRegistryData == nil {
		return nil, errors.New("mandatory tag 'E3' for GlobalPlatform Registry related data not present")
	}

	elfData := make([]ExecutableLoadFileData, 0, len(tlvRegistryData))

	for i, elf := range tlvRegistryData {
		data, err := executableLoadFileDataFromTLV(elf)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid Executable Load File data %d/%d", i, len(tlvRegistryData)))
		}

		elfData = append(elfData, *data)
	}

	return elfData, nil
}

func executableLoadFileDataFromTLV(elf bertlv.BerTLV) (*ExecutableLoadFileData, error) {
	data := &ExecutableLoadFileData{}

	tlvAID := elf.FirstChild(tag.AID)
	if tlvAID == nil {
		return nil, errors.New("mandatory tag '4F' for AID not present")
	}

	elfAID, err := aid.ParseAID(tlvAID.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AID")
	}

	data.AID = *elfAID

	tlvLCS := elf.FirstChild(tag.LifeCycleState)
	if tlvLCS == nil {
		return nil, errors.New("mandatory tag '9F70' for Life Cycle State not present")
	}

	// TODO some SCs return the life cycle state encoded on 2 byte, with the second byte being 0 ?!
	if len(tlvLCS.Value) != 1 && len(tlvLCS.Value) != 2 {
		return nil, fmt.Errorf("life cycle state must be encoded with one or two byte, got %d", len(tlvLCS.Value))
	}

	data.LifeCycleState = tlvLCS.Value[0]

	tlvVersion := elf.FirstChild(tag.ELFVersion)
	if tlvVersion == nil {
		return nil, errors.New("mandatory tag 'CE' for Executable Load File version number not present")
	}

	if len(tlvVersion.Value) != 2 {
		return nil, fmt.Errorf("ELF version must be encoded with 2 bytes, got %d", len(tlvVersion.Value))
	}

	data.VersionNumber = MajorMinorVersion{
		Major: int(tlvVersion.Value[0]),
		Minor: int(tlvVersion.Value[1]),
	}

	tlvSDAID := elf.FirstChild(tag.AssociatedSDAID)
	if tlvSDAID == nil {
		return nil, errors.New("mandatory tag 'CC' for Associated Security Domain AID not present")
	}

	sdAID, err := aid.ParseAID(tlvSDAID.Value)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AID")
	}

	data.AssociatedSDAID = *sdAID

	if tlvEMAIDs := elf.Children(tag.EMAID); tlvEMAIDs != nil {
		emAIDs := make([]aid.AID, 0, len(tlvEMAIDs))

		for i, emAID := range tlvEMAIDs {
			id, err := aid.ParseAID(emAID.Value)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("invalid AID for executable module %d/%d", i, len(tlvEMAIDs)))
			}

			emAIDs = append(emAIDs, *id)
		}

		data.EMAIDs = emAIDs
	}

	return data, nil
}

// Restrict represents the restrict parameter that is used to disable functionalities.
type Restrict struct {
	RegistryUpdate  bool
	Personalization bool
	Extradition     bool
	MakeSelectable  bool
	Install         bool
	Load            bool
	Delete          bool
}

// ParseRestrictParameter parses the restrict parameter encoded on a byte and returns Restrict.
func ParseRestrictParameter(b byte) *Restrict {
	restrict := &Restrict{}

	if (b & 0x40) == 0x40 {
		restrict.RegistryUpdate = true
	}

	if (b & 0x20) == 0x20 {
		restrict.Personalization = true
	}

	if (b & 0x10) == 0x10 {
		restrict.Extradition = true
	}

	if (b & 0x08) == 0x08 {
		restrict.MakeSelectable = true
	}

	if (b & 0x04) == 0x04 {
		restrict.Install = true
	}

	if (b & 0x02) == 0x02 {
		restrict.Load = true
	}

	if (b & 0x01) == 0x01 {
		restrict.Delete = true
	}

	return restrict
}

// Byte encodes Restrict on a byte.
func (r Restrict) Byte() byte {
	b := byte(0x00)

	if r.RegistryUpdate {
		b += 0x40
	}

	if r.Personalization {
		b += 0x20
	}

	if r.Extradition {
		b += 0x10
	}

	if r.MakeSelectable {
		b += 0x08
	}

	if r.Install {
		b += 0x04
	}

	if r.Load {
		b += 0x02
	}

	if r.Delete {
		b += 0x01
	}

	return b
}

// Privilege that can be or is assigned to an application.
type Privilege int

const (
	// SecurityDomain qualifies an application as a Security Domain.
	SecurityDomain Privilege = iota
	// DAPVerification qualifies a Security Domain as capable of verifying a DAP.
	DAPVerification
	// DelegatedManagement qualifies a Security Domain as capable of delegated management.
	DelegatedManagement
	// CardLock qualifies an application as capable of locking the card.
	CardLock
	// CardTerminate qualifies an application as capable of terminating the card.
	CardTerminate
	// CardReset qualifies an application as capable of modifying the historical bytes.
	CardReset
	// CVMManagement qualifies an application as capable of managing a sdmd CVM of a CVM Application.
	CVMManagement
	// MandatedDAPVerification qualifies a Security Domain as capable of and requires the verification of a DAP for all load operations.
	MandatedDAPVerification
	// TrustedPath qualifies an application as a Trusted Path for inter- application communication.
	TrustedPath
	// AuthorizedManagement qualifies a Security Domain as capable of card content management.
	AuthorizedManagement
	// TokenVerification qualifies a Security Domain as capable of verifying a token for Delegated Management.
	TokenVerification
	// GlobalDelete qualifies an application as capable of deleting any card content.
	GlobalDelete
	// GlobalLock qualifies an application as capable of locking/unlocking any application.
	GlobalLock
	// GlobalRegistry qualifies an application as capable of accessing any entry in the GlobalPlatform Registry.
	GlobalRegistry
	// FinalApplication qualifies an application as the only Application selectable in card Life Cycle State CARD_LOCKED and TERMINATED.
	FinalApplication
	// GlobalService qualifies an application as a Global Service that provides services to other Applications on the card.
	GlobalService
	// ReceiptGeneration qualifies a Security Domain as capable of generating a receipt for Delegated Management.
	ReceiptGeneration
	// CipheredLoadFileDataBlock qualifies a Security Domain as requiring that the Load File being associated to it is to be loaded ciphered.
	CipheredLoadFileDataBlock
	// ContactlessActivation qualifies an application as capable of activating and deactivating other any Applications (including itself) on the contactless interface.
	ContactlessActivation
	// ContactlessSelfActivation qualifies an application as capable of activating itself on the contactless interface without a prior request to the Application with the Contactless Activation privilege.
	ContactlessSelfActivation
	// PrivacyTrusted is an application that implements its own specific Privacy Protocol and is not impacted by the rules of the OPEN Privacy Extension.
	PrivacyTrusted
)

// Privileges is a list of Privilege.
type Privileges []Privilege

// Bytes returns a set of Privileges encoded on 3 bytes.
// An error will be returned if DAPVerification and MandatedDAPVerification are present at the same time.
// Other privileges may be mutually exclusive as well (e.g. AuthorizedManagement and DelegatedManagement) but since they can
// be encoded at the same time, no error will be returned.
func (p Privileges) Bytes() ([]byte, error) {
	result := make([]byte, 3)
	dap := false

	for _, priv := range p {
		switch priv {
		case SecurityDomain:
			if result[0]&0x80 != 0x80 {
				result[0] += 0x80
			}
		case DAPVerification:
			if !dap {
				dap = true
			} else {
				return nil, errors.New("set of privileges must contain either DAPVerification or MandatedDAPVerification")
			}

			if result[0]&0x80 != 0x80 {
				result[0] += 0x80
			}

			if result[0]&0x40 != 0x40 {
				result[0] += 0x40
			}
		case DelegatedManagement:
			if result[0]&0x80 != 0x80 {
				result[0] += 0x80
			}

			if result[0]&0x20 != 0x20 {
				result[0] += 0x20
			}
		case CardLock:
			if result[0]&0x10 != 0x10 {
				result[0] += 0x10
			}
		case CardTerminate:
			if result[0]&0x08 != 0x08 {
				result[0] += 0x08
			}
		case CardReset:
			if result[0]&0x04 != 0x04 {
				result[0] += 0x04
			}
		case CVMManagement:
			if result[0]&0x02 != 0x02 {
				result[0] += 0x02
			}
		case MandatedDAPVerification:
			if !dap {
				dap = true
			} else {
				return nil, errors.New("set of privileges must contain either DAPVerification or MandatedDAPVerification")
			}

			if result[0]&0x80 != 0x80 {
				result[0] += 0x80
			}

			if result[0]&0x40 != 0x40 {
				result[0] += 0x40
			}

			if result[0]&0x01 != 0x01 {
				result[0] += 0x01
			}
		case TrustedPath:
			if result[1]&0x80 != 0x80 {
				result[1] += 0x80
			}
		case AuthorizedManagement:
			if result[1]&0x40 != 0x40 {
				result[1] += 0x40
			}
		case TokenVerification:
			if result[1]&0x20 != 0x20 {
				result[1] += 0x20
			}
		case GlobalDelete:
			if result[1]&0x10 != 0x10 {
				result[1] += 0x10
			}
		case GlobalLock:
			if result[1]&0x08 != 0x08 {
				result[1] += 0x08
			}
		case GlobalRegistry:
			if result[1]&0x04 != 0x04 {
				result[1] += 0x04
			}
		case FinalApplication:
			if result[1]&0x02 != 0x02 {
				result[1] += 0x02
			}
		case GlobalService:
			if result[1]&0x01 != 0x01 {
				result[1] += 0x01
			}
		case ReceiptGeneration:
			if result[2]&0x80 != 0x80 {
				result[2] += 0x80
			}
		case CipheredLoadFileDataBlock:
			if result[2]&0x40 != 0x40 {
				result[2] += 0x40
			}
		case ContactlessActivation:
			if result[2]&0x20 != 0x20 {
				result[2] += 0x20
			}
		case ContactlessSelfActivation:
			if result[2]&0x10 != 0x10 {
				result[2] += 0x10
			}
		case PrivacyTrusted:
			if result[2]&0x08 != 0x08 {
				result[2] += 0x08
			}
		}
	}

	return result, nil
}

// ParsePrivileges parses privileges encoded on three bytes and returns Privileges.
func ParsePrivileges(b [3]byte) Privileges {
	numPrivileges := bits.OnesCount(uint(b[0])) + bits.OnesCount(uint(b[1])) + bits.OnesCount(uint(b[2]))
	privileges := make([]Privilege, 0, numPrivileges)

	if b[0]&0x80 == 0x80 {
		privileges = append(privileges, SecurityDomain)
	}

	if b[0]&0xC1 == 0xC0 {
		privileges = append(privileges, DAPVerification)
	} else if b[0]&0xC1 == 0xC1 {
		privileges = append(privileges, MandatedDAPVerification)
	}

	if b[0]&0xA0 == 0xA0 {
		privileges = append(privileges, DelegatedManagement)
	}

	if b[0]&0x10 == 0x10 {
		privileges = append(privileges, CardLock)
	}

	if b[0]&0x08 == 0x08 {
		privileges = append(privileges, CardTerminate)
	}

	if b[0]&0x04 == 0x04 {
		privileges = append(privileges, CardReset)
	}

	if b[0]&0x02 == 0x02 {
		privileges = append(privileges, CVMManagement)
	}

	if b[1]&0x80 == 0x80 {
		privileges = append(privileges, TrustedPath)
	}

	if b[1]&0x40 == 0x40 {
		privileges = append(privileges, AuthorizedManagement)
	}

	if b[1]&0x20 == 0x20 {
		privileges = append(privileges, TokenVerification)
	}

	if b[1]&0x10 == 0x10 {
		privileges = append(privileges, GlobalDelete)
	}

	if b[1]&0x08 == 0x08 {
		privileges = append(privileges, GlobalLock)
	}

	if b[1]&0x04 == 0x04 {
		privileges = append(privileges, GlobalRegistry)
	}

	if b[1]&0x02 == 0x02 {
		privileges = append(privileges, FinalApplication)
	}

	if b[1]&0x01 == 0x01 {
		privileges = append(privileges, GlobalService)
	}

	if b[2]&0x80 == 0x80 {
		privileges = append(privileges, ReceiptGeneration)
	}

	if b[2]&0x40 == 0x40 {
		privileges = append(privileges, CipheredLoadFileDataBlock)
	}

	if b[2]&0x20 == 0x20 {
		privileges = append(privileges, ContactlessActivation)
	}

	if b[2]&0x10 == 0x10 {
		privileges = append(privileges, ContactlessSelfActivation)
	}

	if b[2]&0x08 == 0x08 {
		privileges = append(privileges, PrivacyTrusted)
	}

	return privileges
}
