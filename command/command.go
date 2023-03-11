package command

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/skythen/apdu"
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/open"
	"github.com/skythen/gobalplatform/tag"
)

const (
	claIso byte = 0x00
	claGp  byte = 0x80
)

const (
	beginRMACSessionINS          byte = 0x7A
	deleteINS                    byte = 0xE4
	endRMACSessionINS            byte = 0x78
	externalAuthenticateINS      byte = 0x82
	getDataINSEven               byte = 0xCA
	getDataINSOdd                byte = 0xCB
	getStatusINS                 byte = 0xF2
	installINS                   byte = 0xE6
	initializeUpdateINS          byte = 0x50
	internalAuthenticateINS      byte = 0x88
	loadINS                      byte = 0xE8
	manageChannelINS             byte = 0x70
	manageSecurityEnvironmentINS byte = 0x22
	performSecurityOperationINS  byte = 0x2A
	putKeyINS                    byte = 0xD8
	selectINS                    byte = 0xA4
	setStatusINS                 byte = 0xF0
	storeDataINS                 byte = 0xE2
)

// DeleteCardContent returns a apdu.Capdu that contains a DELETE command that is used to delete a uniquely identifiable
// object such as an Executable Load File, an Application or an Executable Load File and its related Applications.
//
// A token or a cryptographic reference template for digital signature can be added.
func DeleteCardContent(relatedObjects bool, elfOrAppAID aid.AID, token []byte, crtSignature *CRTDigitalSignature) apdu.Capdu {
	builder := bertlv.Builder{}.AddBytes(tag.AID, elfOrAppAID)
	if token != nil {
		builder = builder.AddBytes(tag.DeleteToken, token)
	}

	if crtSignature != nil {
		builder = builder.AddRaw(crtSignature.Bytes())
	}

	capdu := apdu.Capdu{
		Cla:  claGp,
		Ins:  deleteINS,
		P1:   0x00,
		P2:   0x00,
		Data: builder.Bytes(),
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	if relatedObjects {
		capdu.P2 += 0x80
	}

	return capdu
}

// DeleteRootSecurityDomain returns a apdu.Capdu that contains a DELETE command that is used to delete a root security domain
// and all associated applications.
//
// Delete command will be rejected, if the aid.AID does not refer to a root security domain or the Global Delete Privilege is missing.
func DeleteRootSecurityDomain(sdAID aid.AID, token []byte, crtSignature *CRTDigitalSignature) apdu.Capdu {
	builder := bertlv.Builder{}.AddBytes(tag.AID, sdAID)
	if token != nil {
		builder = builder.AddBytes(tag.DeleteToken, token)
	}

	if crtSignature != nil {
		builder = builder.AddRaw(crtSignature.Bytes())
	}

	capdu := apdu.Capdu{
		Cla:  claGp,
		Ins:  deleteINS,
		P1:   0x00,
		P2:   0x00,
		Data: builder.Bytes(),
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	return capdu
}

// DeleteKey returns a apdu.Capdu that contains a DELETE command that is used to delete a key
// identified by the Key ID and Key Version Number.
//
// A single key is deleted when both the Key Identifier and the Key Version Number are provided.
//
// Multiple keys may be deleted if one of these values is omitted.
func DeleteKey(relatedObjects bool, keyID, kvn util.NullByte) apdu.Capdu {
	builder := &bertlv.Builder{}

	if keyID.Valid {
		builder = builder.AddByte(tag.KeyIdentifier, keyID.Byte)
	}

	if kvn.Valid {
		builder = builder.AddByte(tag.KeyVersionNumber, kvn.Byte)
	}

	capdu := apdu.Capdu{
		Cla:  claGp,
		Ins:  deleteINS,
		P1:   0x00,
		P2:   0x00,
		Data: builder.Bytes(),
		Ne:   apdu.MaxLenResponseDataStandard,
	}

	if relatedObjects {
		capdu.P2 += 0x80
	}

	return capdu
}

const (
	InstallP1ForRegistryUpdate               byte = 0x40
	InstallP1ForPersonalization              byte = 0x20
	InstallP1ForForExtradition               byte = 0x10
	InstallP1ForMakeSelectable               byte = 0x08
	InstallP1ForInstall                      byte = 0x04
	InstallP1ForLoad                         byte = 0x02
	InstallP1ForLoadInstallAndMakeSelectable byte = 0x0E
	InstallP1ForInstallAndMakeSelectable     byte = 0x0C
	InstallP2NoInfo                          byte = 0x00
	InstallP2BeginningOfCombinedProcess      byte = 0x01
	InstallP2EndOfCombinedProcess            byte = 0x03
)

// InstallForLoad returns a apdu.Capdu that contains an INSTALL [for load] command that is used to prepare the loading of an ELF.
//
// A Load File Data Block Hash, LoadParameters or a token can be added.
func InstallForLoad(p2 byte, loadFileAID, sdAID aid.AID, lfdbh []byte, loadParameters []byte, token []byte) (apdu.Capdu, error) {
	paramsLen, err := util.BuildGPBerLength(uint(len(loadParameters)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid parameters length")
	}

	tokenLen, err := util.BuildGPBerLength(uint(len(token)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid token length")
	}

	dataLen := 3 + len(sdAID) + len(loadFileAID) + len(lfdbh) + len(paramsLen) + len(loadParameters) + len(tokenLen) + len(token)

	data := make([]byte, 0, dataLen)
	data = append(data, byte(len(loadFileAID)))
	data = append(data, loadFileAID...)
	data = append(data, byte(len(sdAID)))
	data = append(data, sdAID...)
	data = append(data, byte(len(lfdbh)))
	data = append(data, lfdbh...)
	data = append(data, paramsLen...)
	data = append(data, loadParameters...)
	data = append(data, tokenLen...)
	data = append(data, token...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   InstallP1ForLoad,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// LoadBlock returns a apdu.Capdu that contains a LOAD command that can be used to load the given block onto the card.
func LoadBlock(lastBlock bool, blockNum byte, block []byte) apdu.Capdu {
	var p1 byte

	if lastBlock {
		p1 = 0x80
	}

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  loadINS,
		P1:   p1,
		P2:   blockNum,
		Data: block,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

// InstallForInstall returns a apdu.Capdu that contains an INSTALL [for installation] command.
func InstallForInstall(p2 byte, makeSelectable bool, elfAID, emAID, instanceAID aid.AID, privs open.Privileges, installParameters []byte, token []byte) (apdu.Capdu, error) {
	var (
		bPrivs []byte
		err    error
		p1     byte
	)

	if privs != nil {
		bPrivs, err = privs.Bytes()
		if err != nil {
			return apdu.Capdu{}, errors.New("invalid privileges")
		}
	} else {
		bPrivs = []byte{0x00}
	}

	if makeSelectable {
		p1 = InstallP1ForInstallAndMakeSelectable
	} else {
		p1 = InstallP1ForInstall
	}

	if len(installParameters) == 0 {
		installParameters = []byte{0xC9, 0x00}
	}

	paramsLen, err := util.BuildGPBerLength(uint(len(installParameters)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid parameters length")
	}

	tokenLen, err := util.BuildGPBerLength(uint(len(token)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid token length")
	}

	data := make([]byte, 0, 4+len(elfAID)+len(emAID)+len(instanceAID)+len(privs)+len(paramsLen)+len(installParameters)+len(tokenLen)+len(token))
	data = append(data, byte(len(elfAID)))
	data = append(data, elfAID...)
	data = append(data, byte(len(emAID)))
	data = append(data, emAID...)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, byte(len(bPrivs)))
	data = append(data, bPrivs...)
	data = append(data, paramsLen...)
	data = append(data, installParameters...)
	data = append(data, tokenLen...)
	data = append(data, token...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// InstallForMakeSelectable returns a apdu.Capdu that contains an INSTALL [for make selectable] command that is used to make an application selectable.
//
// Make selectable parameters or a token can be added.
func InstallForMakeSelectable(p2 byte, instanceAID aid.AID, privs open.Privileges, makeSelectableParameters []byte, token []byte) (apdu.Capdu, error) {
	var (
		bPrivs []byte
		err    error
	)

	if privs != nil {
		bPrivs, err = privs.Bytes()
		if err != nil {
			return apdu.Capdu{}, errors.New("invalid privileges")
		}
	}

	paramsLen, err := util.BuildGPBerLength(uint(len(makeSelectableParameters)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid parameters length")
	}

	tokenLen, err := util.BuildGPBerLength(uint(len(token)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid token length")
	}

	data := make([]byte, 0, 4+len(instanceAID)+len(privs)+len(paramsLen)+len(makeSelectableParameters)+len(tokenLen)+len(token))
	data = append(data, 0x00)
	data = append(data, 0x00)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, byte(len(bPrivs)))
	data = append(data, bPrivs...)
	data = append(data, paramsLen...)
	data = append(data, makeSelectableParameters...)
	data = append(data, tokenLen...)
	data = append(data, token...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   InstallP1ForMakeSelectable,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// InstallForRegistryUpdate returns a apdu.Capdu that contains an INSTALL [for registry update] command.
//
// Registry update parameters or a token can be added.
func InstallForRegistryUpdate(targetSDAID, instanceAID *aid.AID, privs *open.Privileges, regUpdateParameters []byte, token []byte) (apdu.Capdu, error) {
	var (
		sdAID          aid.AID
		applicationAID aid.AID
		bPrivs         []byte
		err            error
	)

	if privs != nil {
		bPrivs, err = privs.Bytes()
		if err != nil {
			return apdu.Capdu{}, errors.New("invalid privileges")
		}
	}

	paramsLen, err := util.BuildGPBerLength(uint(len(regUpdateParameters)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid parameters length")
	}

	tokenLen, err := util.BuildGPBerLength(uint(len(token)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid token length")
	}

	if targetSDAID != nil {
		sdAID = *targetSDAID
	}

	if instanceAID != nil {
		applicationAID = *instanceAID
	}

	data := make([]byte, 0, 6+len(sdAID)+len(applicationAID)+len(bPrivs)+len(paramsLen)+len(regUpdateParameters)+len(tokenLen)+len(token))
	data = append(data, byte(len(sdAID)))
	data = append(data, sdAID...)
	data = append(data, 0x00)
	data = append(data, byte(len(applicationAID)))
	data = append(data, applicationAID...)
	data = append(data, byte(len(bPrivs)))
	data = append(data, bPrivs...)
	data = append(data, byte(len(regUpdateParameters)))
	data = append(data, regUpdateParameters...)
	data = append(data, byte(len(token)))
	data = append(data, token...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   InstallP1ForRegistryUpdate,
		P2:   InstallP2NoInfo,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// InstallForPersonalization returns a apdu.Capdu that contains an INSTALL [for personalization] command.
func InstallForPersonalization(instanceAID aid.AID) apdu.Capdu {
	data := make([]byte, 0, 6+len(instanceAID))
	data = append(data, []byte{0x00, 0x00}...)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, []byte{0x00, 0x00, 0x00}...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   InstallP1ForPersonalization,
		P2:   InstallP2NoInfo,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

// InstallForExtradition returns a apdu.Capdu that contains an INSTALL [for extradition] command.
// Extradition parameters or a token will be added if present.
func InstallForExtradition(targetSDAID aid.AID, appAID aid.AID, extraditionParameters []byte, token []byte) (apdu.Capdu, error) {
	paramsLen, err := util.BuildGPBerLength(uint(len(extraditionParameters)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid parameters length")
	}

	tokenLen, err := util.BuildGPBerLength(uint(len(token)))
	if err != nil {
		return apdu.Capdu{}, errors.Wrap(err, "invalid token length")
	}

	data := make([]byte, 0, 4+len(targetSDAID)+len(appAID)+len(paramsLen)+len(extraditionParameters)+len(tokenLen)+len(token))
	data = append(data, byte(len(targetSDAID)))
	data = append(data, targetSDAID...)
	data = append(data, 0x00)
	data = append(data, byte(len(appAID)))
	data = append(data, appAID...)
	data = append(data, 0x00)
	data = append(data, paramsLen...)
	data = append(data, extraditionParameters...)
	data = append(data, tokenLen...)
	data = append(data, token...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  installINS,
		P1:   InstallP1ForForExtradition,
		P2:   InstallP2NoInfo,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}, nil
}

// PutKey returns a apdu.Capdu that contains a PUT KEY command that is used either:
// to replace an existing key with a new key: The new key has the same or a different Key Version Number but the same Key Identifier as the key being replaced;
// to replace multiple existing keys with new keys: The new keys have the same or a different Key Version Number (identical for all new keys) but the same Key Identifiers as the keys being replaced;
// to Add a single new key: The new key has a different combination Key Identifier / Key Version Number than that of the existing keys;
// to add multiple new keys: The new keys have different combinations of Key Identifiers / Key Version Number (identical to all new keys) than that of the existing keys.
func PutKey(new, multipleKeys bool, keyData []byte, keyVersionNum, keyID byte) apdu.Capdu {
	p1 := byte(0x00)
	p2 := keyID

	if !new {
		p1 += keyVersionNum
	}

	if multipleKeys {
		p2 += 0x80
	}

	// add kvn of contained keys to the data field
	data := make([]byte, 0, len(keyData)+1)
	data = append(data, keyVersionNum)
	data = append(data, keyData...)

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  putKeyINS,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	GetDataP2IssuerIdentificationNumber   byte = 0x42
	GetDataP2CardImageNumber              byte = 0x45
	GetDataP2CardData                     byte = 0x66
	GetDataP2SecurityDomainManagementData byte = 0x73
	GetDataP2CardCapabilityInformation    byte = 0x67
	GetDataP2CurrentSecurityLevel         byte = 0xD3
	GetDataP2KeyInformationTemplate       byte = 0xE0
)

// GetData returns a apdu.Capdu that contains a GET DATA command with Ins = CA (even) that is used to retrieve data.
// Data can be added if a GET DATA command requires the passing of additional data.
func GetData(p1, p2 byte, data []byte) apdu.Capdu {
	return apdu.Capdu{
		Cla:  claGp,
		Ins:  getDataINSEven,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	GetStatusP1ISD                byte = 0x80
	GetStatusP1ApplicationsAndSSD byte = 0x40
	GetStatusP1ELF                byte = 0x20
	GetStatusP1ELFAndEM           byte = 0x10
	GetStatusP1LogicallyDeleted   byte = 0x08
	GetStatusP1OPEN               byte = 0x04
	GetStatusP2FormatGpTLV        byte = 0x02
)

// GetStatus returns a apdu.Capdu that contains a GET STATUS command with P2 = format BER-TLV.
// Data can be added if a GET STATUS command requires the passing of additional data (e.g. for filter).
// GetStatusCommandDataField can be used to construct data field.
func GetStatus(p1 byte, next bool, data []byte) apdu.Capdu {
	p2 := byte(0x02)
	if next {
		p2 += 0x01
	}

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  getStatusINS,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	GetStatusCRSP1Applications byte = 0x40
	GetStatusCRSP1OPEN         byte = 0x04
)

// GetStatusCRS is used to retrieve information about applications that are registered in Contactless Registry Service (CRS).
// Information about non-contactless applications are not available through this command.
// Data can be added if a GET STATUS command requires the passing of additional data (e.g. for filter).
// GetStatusCRSCommandDataField can be used to construct data field.
func GetStatusCRS(p1 byte, next bool, data []byte) apdu.Capdu {
	p2 := byte(0x00)
	if next {
		p2 += 0x01
	}

	return apdu.Capdu{
		Cla:  claGp,
		Ins:  getStatusINS,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	manageChannelP1CloseSupplementaryLogicalChannel             byte = 0x80
	manageChannelP1OpenNextAvailableSupplementaryLogicalChannel byte = 0x00
)

// ManageChannelOpen returns a apdu.Capdu that contains a MANAGE CHANNEL command for opening a logical channel.
// A card supporting logical channel assignment by off-card entities may accept a reference control parameter P2.
func ManageChannelOpen(p2 byte) apdu.Capdu {
	return apdu.Capdu{
		Cla: claIso,
		Ins: manageChannelINS,
		P1:  manageChannelP1OpenNextAvailableSupplementaryLogicalChannel,
		P2:  p2,
		Ne:  apdu.MaxLenResponseDataStandard,
	}
}

// ManageChannelClose returns a apdu.Capdu that contains a MANAGE CHANNEL command for closing a logical channel.
func ManageChannelClose(p2 byte) apdu.Capdu {
	return apdu.Capdu{
		Cla: claIso,
		Ins: manageChannelINS,
		P1:  manageChannelP1CloseSupplementaryLogicalChannel,
		P2:  p2,
		Ne:  apdu.MaxLenResponseDataStandard,
	}
}

const (
	SetStatusP1ISD                         byte = 0x80
	SetStatusP1ApplicationOrSSD            byte = 0x40
	SetStatusP1SdAndAssociatedApplications byte = 0x60

	SetStatusP1AvailabilityStateContactless      byte = 0x01 // Availability State over Contactless Interface
	SetStatusP1PriorityOrderApplicationSelection byte = 0x02 // Priority Order for Application Selection
	SetStatusP1CommunicationInterfaceAccess      byte = 0x04 // Communication Interface Access
	SetStatusP1ContactlessProtocolTypeState      byte = 0x08 // Contactless Protocol Type State
	SetStatusP1RemainingResponseData             byte = 0x80 // Remaining Response Data

	SetStatusP2NotAvailableContactless        byte = 0x00 // OPEN shall not attempt to activate
	SetStatusP2AvailableContactless           byte = 0x01 // OPEN shall attempt to activate
	SetStatusP2AssignHighestPriority          byte = 0x01 // Assign Highest Priority
	SetStatusP2AssignLowestPriority           byte = 0x81 // Assign Lowest Priority
	SetStatusP2AssignVolatilePriority         byte = 0x02 // Assign Volatile Priority
	SetStatusP2ResetVolatilePriority          byte = 0x82 // Reset Volatile Priority
	SetStatusP2CommunicationInterfaceON       byte = 0x80 // Communication Interface switched ON
	SetStatusP2CommunicationInterfaceOFF      byte = 0x00 // Communication Interface switched OFF
	SetStatusP2EnableContactlessProtocolType  byte = 0x80 // Enable Contactless Protocol Type
	SetStatusP2DisableContactlessProtocolType byte = 0x00 // Disable Contactless Protocol Type
)

// SetStatus returns a apdu.Capdu that contains a SET STATUS command.
// Data can be added if a SET STATUS command requires passing additional data.
func SetStatus(p1, p2 byte, data []byte) apdu.Capdu {
	return apdu.Capdu{
		Cla:  claGp,
		Ins:  setStatusINS,
		P1:   p1,
		P2:   p2,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	selectP1ByName                byte = 0x04
	selectP2FirstOrOnlyOccurrence byte = 0x00
	selectP2NextOccurrence        byte = 0x02
)

// Select returns a apdu.Capdu that contains a SELECT command for selecting the application with the given aid.AID.
func Select(firstOccurrence bool, appAID aid.AID) apdu.Capdu {
	var p2 byte

	if !firstOccurrence {
		p2 = selectP2NextOccurrence
	}

	return apdu.Capdu{
		Cla:  claIso,
		Ins:  selectINS,
		P1:   selectP1ByName,
		P2:   p2,
		Data: appAID,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

const (
	StoreDataP1MoreBlocks              byte = 0x00
	StoreDataP1LastBlock               byte = 0x80
	StoreDataP1NoEncInfo               byte = 0x00
	StoreDataP1EncApplicationDependent byte = 0x20
	StoreDataP1EncryptedData           byte = 0x60
	StoreDataP1NoStructureInformation  byte = 0x00
	StoreDataP1DGIFormat               byte = 0x08
	StoreDataP1BERTlvFormat            byte = 0x10
	StoreDataP1ISOCase3                byte = 0x00
	StoreDataP1ISOCase4                byte = 0x01
)

// StoreData returns a apdu.Capdu that contains a STORE DATA command for storing data in the given format in the currently selected application.
func StoreData(p1, blockNumber byte, data []byte) apdu.Capdu {
	return apdu.Capdu{
		Cla:  claGp,
		Ins:  storeDataINS,
		P1:   p1,
		P2:   blockNumber,
		Data: data,
		Ne:   apdu.MaxLenResponseDataStandard,
	}
}

// OnLogicalChannel returns the modified CLA byte that indicates the specified logical channel ID.
// Note: Values for channel ID > 0x13 (19) will be set to 0x13 since this is the highest supported value.
func OnLogicalChannel(channelID, cla byte) byte {
	if channelID <= 3 {
		return cla | channelID
	}

	if cla&0x40 != 0x40 {
		cla += 0x40
	}

	if channelID > 0x13 {
		channelID = 0x13
	}

	channelID -= 4

	return cla | (channelID & 0x0F)
}

// AsChain splits a given extended length apdu.Capdu into a chain of standard length
// apdu.Capdu with data fields with a maximum size of 255 byte.
// P1 will be modified to indicate whether more blocks follow or not.
//
// If the given apdu.Capdu has no extended length, it will be the only element in the chain.
func AsChain(capdu apdu.Capdu) []apdu.Capdu {
	if !capdu.IsExtendedLength() {
		if capdu.P1&0x80 != 0x00 {
			capdu.P1 -= 0x80
		}

		return []apdu.Capdu{capdu}
	}

	blocks := len(capdu.Data) / 255

	if len(capdu.Data)%255 != 0 {
		blocks++
	}

	chain := make([]apdu.Capdu, 0, blocks)
	index := 0
	rightIndex := 0

	for numBlock := 1; numBlock <= blocks; numBlock++ {
		p1 := capdu.P1

		// set b7 of p1 for last block to 0
		if numBlock == blocks {
			if p1&0x80 != 0x00 {
				p1 -= 0x80
			}

			rightIndex = len(capdu.Data)
		} else {
			if p1&0x80 != 0x80 {
				p1 += 0x80
			}
			rightIndex += 255
		}

		cmd := apdu.Capdu{
			Cla:  capdu.Cla,
			Ins:  capdu.Ins,
			P1:   p1,
			P2:   capdu.P2,
			Data: capdu.Data[index:rightIndex],
			Ne:   apdu.MaxLenResponseDataStandard,
		}

		chain = append(chain, cmd)
		index += len(cmd.Data)
	}

	return chain
}

// ResponseStatus contains the hex encoded status words of a response and a human readable description of their meaning.
type ResponseStatus struct {
	SW          string // Status words of the response.
	Description string // Description of the meaning of the status words.
}

// LookupResponseStatus resolves the status words of the given RAPDU according to the given INS byte
// and returns ResponseStatus.
func LookupResponseStatus(ins byte, resp apdu.Rapdu) ResponseStatus {
	description := ""

	switch ins {
	case deleteINS:
		if resp.SW1 == 0x65 && resp.SW2 == 0x81 {
			description = "[Delete] Memory failure"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[Delete] Referenced data not found"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x82 {
			description = "[Delete] Application not found"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[Delete] Incorrect values in command data"
		}
	case getDataINSEven:
		fallthrough
	case getDataINSOdd:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[GetData] Referenced data not found"
		}
	case getStatusINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[GetStatus] Referenced data not found"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[GetStatus] Incorrect values in command data"
		}
	case installINS:
		if resp.SW1 == 0x65 && resp.SW2 == 0x81 {
			description = "[Install] Memory failure"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[Install] Incorrect parameters in data field"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x84 {
			description = "[Install] Not enough memory space"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[Install] Referenced data not found"
		}
	case loadINS:
		if resp.SW1 == 0x65 && resp.SW2 == 0x81 {
			description = "[Load] Memory failure"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x84 {
			description = "[Load] Not enough memory space"
		}
	case manageChannelINS:
		if resp.SW1 == 0x68 && resp.SW2 == 0x82 {
			description = "[ManageChannel] Secure messaging not supported"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x81 {
			description = "[ManageChannel] Function not supported"
		}
	case putKeyINS:
		if resp.SW1 == 0x65 && resp.SW2 == 0x81 {
			description = "[PutKey] Memory failure"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[PutKey] Wrong data"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x84 {
			description = "[PutKey] Not enough memory space"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[PutKey] Referenced data not found"
		} else if resp.SW1 == 0x94 && resp.SW2 == 0x84 {
			description = "[PutKey] Algorithm not supported"
		} else if resp.SW1 == 0x94 && resp.SW2 == 0x85 {
			description = "[PutKey] Invalid key check value"
		} else if resp.SW1 == 0x69 && resp.SW2 == 0x82 {
			description = "[PutKey] Invalid key check value"
		}
	case selectINS:
		if resp.SW1 == 0x68 && resp.SW2 == 0x82 {
			description = "[Select] Secure messaging not supported"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x81 {
			description = "[Select] Function not supported"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x82 {
			description = "[Select] Selected Application / file not found"
		}
	case setStatusINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[SetStatus] Incorrect values in command data"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[SetStatus] Referenced data not found"
		}
	case storeDataINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[StoreData] Incorrect values in command data"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x84 {
			description = "[StoreData] Not enough memory space"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[StoreData] Referenced data not found"
		}
	case initializeUpdateINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[InitializeUpdate] Referenced data not found"
		}
	case internalAuthenticateINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[InternalAuthenticate] Incorrect values in command data"
		}
	case externalAuthenticateINS:
		if resp.SW1 == 0x63 && resp.SW2 == 0x00 {
			description = "[ExternalAuthenticate] Authentication of host cryptogram failed"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[ExternalAuthenticate] Referenced data not found"
		} else if resp.SW1 == 0x94 && resp.SW2 == 0x84 {
			description = "[ExternalAuthenticate] Algorithm not supported"
		}
	case beginRMACSessionINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[BeginRMACSession] Referenced data not found"
		}
	case endRMACSessionINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[EndRMACSession] Referenced data not found"
		}
	case manageSecurityEnvironmentINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x88 {
			description = "[ManageSecurityEnvironment] Referenced data not found"
		} else if resp.SW1 == 0x94 && resp.SW2 == 0x84 {
			description = "[ManageSecurityEnvironment] Algorithm not supported"
		}
	case performSecurityOperationINS:
		if resp.SW1 == 0x6A && resp.SW2 == 0x80 {
			description = "[PerformSecurityOperation] Incorrect values in command data"
		} else if resp.SW1 == 0x63 && resp.SW2 == 0x00 {
			description = "[PerformSecurityOperation] Verification of the certificate failed"
		} else if resp.SW1 == 0x68 && resp.SW2 == 0x83 {
			description = "[PerformSecurityOperation] The last command of the chain was expected"
		}
	}

	if description == "" {
		if resp.SW1 == 0x63 && resp.SW2 == 0x00 {
			description = "[General] No specific diagnosis"
		} else if resp.SW1 == 0x67 && resp.SW2 == 0x00 {
			description = "[General] Wrong length in Lc"
		} else if resp.SW1 == 0x68 && resp.SW2 == 0x81 {
			description = "[General] Logical channel not supported or is not active"
		} else if resp.SW1 == 0x69 && resp.SW2 == 0x82 {
			description = "[General] Security status not satisfied"
		} else if resp.SW1 == 0x69 && resp.SW2 == 0x85 {
			description = "[General] Conditions of use not satisfied"
		} else if resp.SW1 == 0x6A && resp.SW2 == 0x86 {
			description = "[General] Incorrect P1 P2"
		} else if resp.SW1 == 0x6D && resp.SW2 == 0x00 {
			description = "[General] Invalid instruction"
		} else if resp.SW1 == 0x6E && resp.SW2 == 0x00 {
			description = "[General] Invalid class"
		} else {
			return ResponseStatus{SW: resp.String(), Description: "[Unknown]"}
		}
	}

	return ResponseStatus{SW: resp.String(), Description: description}
}

// ToString returns the human-readable response status.
func (rs ResponseStatus) ToString() string {
	return fmt.Sprintf("SW: %s Description: %s", rs.SW, rs.Description)
}

// AppendSWDetails calls LookupResponseStatus and ResponseStatus.ToString on the returned ResponseStatus and appends it
// to the given string.
func AppendSWDetails(str string, ins byte, rapdu apdu.Rapdu) string {
	return fmt.Sprintf("%s - %s", str, LookupResponseStatus(ins, rapdu).ToString())
}
