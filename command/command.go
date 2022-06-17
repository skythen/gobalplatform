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

// DeleteCardContent returns an apdu.Capdu that contains a DELETE command that is used to delete a uniquely identifiable
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

// DeleteKey returns an apdu.Capdu that contains a DELETE command that is used to delete a key
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

// InstallForLoad returns an apdu.Capdu that contains an INSTALL [for load] command that is used to prepare the loading of an ELF.
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

// LoadBlock returns an apdu.Capdu that contains a LOAD command that can be used to load the given block onto the card.
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

// InstallForInstall returns an apdu.Capdu that contains an INSTALL [for installation] command.
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

// InstallForMakeSelectable returns an apdu.Capdu that contains an INSTALL [for make selectable] command that is used to make an application selectable.
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

// InstallForRegistryUpdate returns an apdu.Capdu that contains an INSTALL [for registry update] command.
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

// InstallForPersonalization returns an apdu.Capdu that contains an INSTALL [for personalization] command.
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

// InstallForExtradition returns an apdu.Capdu that contains an INSTALL [for extradition] command.
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

// PutKey returns an apdu.Capdu that contains a PUT KEY command that is used either:
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

// GetData returns an apdu.Capdu that contains a GET DATA command with Ins = CA (even) that is used to retrieve data.
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
	GetStatusP2FormatGpTLV        byte = 0x02
)

// GetStatus returns an apdu.Capdu that contains a GET STATUS command with P2 = format BER-TLV.
// Data can be added if a GET STATUS command requires the passing of additional data (e.g. for filter).
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
	manageChannelP1CloseSupplementaryLogicalChannel             byte = 0x80
	manageChannelP1OpenNextAvailableSupplementaryLogicalChannel byte = 0x00
)

// ManageChannelOpen returns an apdu.Capdu that contains a MANAGE CHANNEL command for opening a logical channel.
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

// ManageChannelClose returns an apdu.Capdu that contains a MANAGE CHANNEL command for closing a logical channel.
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
)

// SetStatus returns an apdu.Capdu that contains a SET STATUS command.
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

// Select returns an apdu.Capdu that contains a SELECT command for selecting the application with the given aid.AID.
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

// StoreData returns an apdu.Capdu that contains a STORE DATA command for storing data in the given format in the currently selected application.
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

// LoadFileStructure represents a GlobalPlatform Load File that can be loaded to a SE with a LOAD command.
type LoadFileStructure struct {
	DAPBlocks                 []DAPBlock // Blocks to be verified by a Security Domain with the DAP Verification or Mandated DAP Verification privilege.
	LoadFileDataBlock         []byte     // Plaintext platform specific code of a Load File - shall not be present when CipheredLoadFileDataBlock is present.
	CipheredLoadFileDataBlock []byte     // Ciphered platform specific code of a Load File that can be decrypted by a Security Domain with the Ciphered Load File Data Block privilege - shall not be present when LoadFileDataBlock is present
	ICV                       []byte     // May be present if CipheredLoadFileDataBlock is present and has been encrypted with an ICV other than the zero ICV.
}

// Bytes returns LoadFileStructure as BER-TLV encoded bytes.
func (lfs LoadFileStructure) Bytes() []byte {
	builder := &bertlv.Builder{}

	for _, dapBlock := range lfs.DAPBlocks {
		d := dapBlock.Bytes()
		builder = builder.AddRaw(d)
	}

	if lfs.LoadFileDataBlock != nil {
		builder = builder.AddBytes(tag.LoadFileDataBlock, lfs.LoadFileDataBlock)
	}

	if lfs.ICV != nil {
		builder = builder.AddBytes(tag.ICV, lfs.ICV)
	}

	if lfs.CipheredLoadFileDataBlock != nil {
		builder = builder.AddBytes(tag.CipheredLoadFileDataBlock, lfs.CipheredLoadFileDataBlock)
	}

	return builder.Bytes()
}

// DAPBlock represents a Data Authentication Pattern block (Load File Data Block Signature) and contains the AID of the Security Domain that shall verify
// this block as well as the signature over a Load File Data Block that shall be loaded.
type DAPBlock struct {
	SDAID         aid.AID // AID of the Security Domain with the (Mandated) DAP Verification privilege.
	LFDBSignature []byte  // Signature over the Load File Data Block.
}

// Bytes returns DAPBlock as BER-TLV bytes.
func (dapBlock DAPBlock) Bytes() []byte {
	return bertlv.Builder{}.AddBytes(tag.DAPBlock,
		bertlv.Builder{}.
			AddBytes(tag.AID, dapBlock.SDAID).
			AddBytes(tag.LoadFileDataBlockSignature, dapBlock.LFDBSignature).
			Bytes()).
		Bytes()
}

// CRTDigitalSignature is the Cryptographic Reference Template for Digital Signature and is especially recommended to use with SCP10.
type CRTDigitalSignature struct {
	SDIdentificationNumber        []byte // Identification Number of the Security Domain with the Token Verification privilege.
	SDImageNumber                 []byte // Image Number of the Security Domain with the Token Verification privilege.
	ApplicationProviderIdentifier []byte // Application Provider identifier.
	TokenIdentifier               []byte // Token identifier/number (digital signature counter).
}

// Bytes returns CRTDigitalSignature as BER-TLV encoded bytes.
func (crt CRTDigitalSignature) Bytes() []byte {
	builder := &bertlv.Builder{}

	if crt.SDIdentificationNumber != nil {
		builder = builder.AddBytes(tag.SDIdentificationNumber, crt.SDIdentificationNumber)
	}

	if crt.SDImageNumber != nil {
		builder = builder.AddBytes(tag.SDImageNumber, crt.SDImageNumber)
	}

	if crt.ApplicationProviderIdentifier != nil {
		builder = builder.AddBytes(tag.ApplicationProviderIdentifier, crt.ApplicationProviderIdentifier)
	}

	if crt.TokenIdentifier != nil {
		builder = builder.AddBytes(tag.TokenIdentification, crt.TokenIdentifier)
	}

	return bertlv.Builder{}.AddBytes(tag.ControlReferenceTemplateForDigitalSignature, builder.Bytes()).Bytes()
}

// PrivacyRequirements may be specified for an Application using tag 'E0' as part of System Specific Install Parameters.
type PrivacyRequirements struct {
	RequiredPrivacyStatus    []RequiredPrivacyStatus   // 0 to N occurrences allowed
	RequiredPrivacyCondition *RequiredPrivacyCondition // structure is not specified by GPC Privacy Framework, 0 to 1 occurrences allowed
}

// RequiredPrivacyStatus is the Privacy Status that must have been reached in the execution of the Global Privacy Protocol
// and is maintained by the GPP service.
type RequiredPrivacyStatus struct {
	Constructed bool   // indicates whether Value consists of constructed data objects or not
	Value       []byte // structure is not specified by GPC Privacy Framework
}

// Bytes returns RequiredPrivacyStatus as BER-TLV encoded bytes.
func (req RequiredPrivacyStatus) Bytes() []byte {
	builder := &bertlv.Builder{}

	if req.Constructed {
		builder = builder.AddBytes(tag.RequiredPrivacyStatusConstructed, req.Value)
	} else {
		builder = builder.AddBytes(tag.RequiredPrivacyStatus, req.Value)
	}

	return builder.Bytes()
}

// RequiredPrivacyCondition defines a condition for an application about the Current Privacy Status before the OPEX allows the selection of that application.
type RequiredPrivacyCondition struct {
	Constructed bool   // indicates whether Value consists of constructed data objects or not
	Value       []byte // structure is not specified by GPC Privacy Framework
}

// Bytes returns RequiredPrivacyCondition as BER-TLV encoded bytes.
func (req RequiredPrivacyCondition) Bytes() []byte {
	builder := &bertlv.Builder{}

	if req.Constructed {
		builder = builder.AddBytes(tag.RequiredPrivacyConditionConstructed, req.Value)
	} else {
		builder = builder.AddBytes(tag.RequiredPrivacyCondition, req.Value)
	}

	return builder.Bytes()
}

// Bytes returns PrivacyRequirements as BER-TLV encoded bytes.
func (req PrivacyRequirements) Bytes() []byte {
	outerBuilder := &bertlv.Builder{}
	innerBuilder := &bertlv.Builder{}

	for _, ps := range req.RequiredPrivacyStatus {
		innerBuilder = innerBuilder.AddRaw(ps.Bytes())
	}

	if req.RequiredPrivacyCondition != nil {
		innerBuilder = innerBuilder.AddRaw(req.RequiredPrivacyCondition.Bytes())
	}

	return outerBuilder.AddBytes(tag.PrivacyRequirements, innerBuilder.Bytes()).Bytes()
}

// SystemSpecificParameters provides additional parameters that can be used for an INSTALL command, although their presence might be ignored.
// If both tag 'C6' and 'C8' are present and the implementation does not make any distinction between Non-Volatile Code and Non-Volatile Data Memory
// then the required minimum shall be the sum of both values.
type SystemSpecificParameters struct {
	NonVolatileCodeMinimumRequirement   []byte               // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	VolatileMemoryMinimumRequirement    []byte               // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	NonVolatileMemoryMinimumRequirement []byte               // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	VolatileReservedMemory              []byte               // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	NonVolatileReservedMemory           []byte               // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	GlobalServiceParameters             []byte               // One or more two-byte service parameters.
	TS102226SpecificParameters          []byte               // UICC specific parameters.
	LoadFileDataBlockFormatID           util.NullByte        // Proprietary Load File Data Block format ID.
	LoadFileDataBlockParameters         []byte               // Proprietary Load File Data Block parameters.
	RestrictParameter                   *open.Restrict       // Lists functionalities that shall be disabled.
	ImplicitSelectionParameter          util.NullByte        // Implicit selection parameter.
	PrivacyRequirements                 *PrivacyRequirements // Privacy Requirements for an application.
}

// Bytes returns SystemSpecificParameters as BER-TLV encoded bytes.
func (ssp SystemSpecificParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if ssp.NonVolatileCodeMinimumRequirement != nil {
		builder = builder.AddBytes(tag.NonVolatileCodeMinimumRequirement, ssp.NonVolatileCodeMinimumRequirement)
	}

	if ssp.VolatileMemoryMinimumRequirement != nil {
		builder = builder.AddBytes(tag.VolatileMemoryQuota, ssp.VolatileMemoryMinimumRequirement)
	}

	if ssp.NonVolatileMemoryMinimumRequirement != nil {
		builder = builder.AddBytes(tag.NonVolatileMemoryQuota, ssp.NonVolatileMemoryMinimumRequirement)
	}

	if ssp.GlobalServiceParameters != nil {
		builder = builder.AddBytes(tag.GlobalServiceParameters, ssp.GlobalServiceParameters)
	}

	if ssp.LoadFileDataBlockFormatID.Valid {
		builder = builder.AddByte(tag.LoadFileDataBlockFormatID, ssp.LoadFileDataBlockFormatID.Byte)
	}

	if ssp.VolatileReservedMemory != nil {
		builder = builder.AddBytes(tag.VolatileReservedMemory, ssp.VolatileReservedMemory)
	}

	if ssp.NonVolatileReservedMemory != nil {
		builder = builder.AddBytes(tag.NonVolatileReservedMemory, ssp.NonVolatileReservedMemory)
	}

	if ssp.RestrictParameter != nil {
		builder = builder.AddByte(tag.Restrict, ssp.RestrictParameter.Byte())
	}

	if ssp.LoadFileDataBlockParameters != nil {
		builder = builder.AddBytes(tag.LoadFileDataBlockParameter, ssp.LoadFileDataBlockParameters)
	}

	if ssp.TS102226SpecificParameters != nil {
		builder = builder.AddBytes(tag.TS102226SpecificParameters, ssp.TS102226SpecificParameters)
	}

	if ssp.ImplicitSelectionParameter.Valid {
		builder = builder.AddByte(tag.ImplicitSelectionParameter, ssp.ImplicitSelectionParameter.Byte)
	}

	if ssp.PrivacyRequirements != nil {
		builder = builder.AddRaw(ssp.PrivacyRequirements.Bytes())
	}

	return bertlv.Builder{}.AddBytes(tag.SystemSpecificParameter, builder.Bytes()).Bytes()
}

// LoadParameters provide additional parameters that can be used for an INSTALL [for load] command.
type LoadParameters struct {
	SystemSpecificParameters                    *SystemSpecificParameters
	ControlReferenceTemplateForDigitalSignature *CRTDigitalSignature
}

// Bytes returns LoadParameters as BER-TLV encoded bytes.
func (lp LoadParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if lp.SystemSpecificParameters != nil {
		builder = builder.AddRaw(lp.SystemSpecificParameters.Bytes())
	}

	if lp.ControlReferenceTemplateForDigitalSignature != nil {
		builder = builder.AddRaw(lp.ControlReferenceTemplateForDigitalSignature.Bytes())
	}

	return builder.Bytes()
}

// InstallParameters provide additional parameters that can be used for commands containing the INSTALL [for installation] step.
type InstallParameters struct {
	ApplicationSpecificParameters               []byte
	SystemSpecificParameters                    *SystemSpecificParameters
	TS102226SpecificTemplate                    []byte
	ControlReferenceTemplateForDigitalSignature *CRTDigitalSignature
}

// Bytes returns InstallParameters as BER-TLV encoded bytes.
func (ip InstallParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if len(ip.ApplicationSpecificParameters) == 0 {
		builder = builder.AddEmpty(tag.ApplicationSpecificParameters)
	} else {
		builder = builder.AddBytes(tag.ApplicationSpecificParameters, ip.ApplicationSpecificParameters)
	}

	if ip.SystemSpecificParameters != nil {
		builder = builder.AddRaw(ip.SystemSpecificParameters.Bytes())
	}

	if ip.TS102226SpecificTemplate != nil {
		builder = builder.AddBytes(tag.TS102226SpecificTemplate, ip.TS102226SpecificTemplate)
	}

	if ip.ControlReferenceTemplateForDigitalSignature != nil {
		builder = builder.AddRaw(ip.ControlReferenceTemplateForDigitalSignature.Bytes())
	}

	return builder.Bytes()
}

// MakeSelectableParameters provides additional parameters that can be used for an INSTALL [for make selectable] command.
type MakeSelectableParameters struct {
	SystemSpecificParameters                    *SystemSpecificParameters
	ControlReferenceTemplateForDigitalSignature *CRTDigitalSignature
}

// Bytes returns MakeSelectableParameters as BER-TLV encoded bytes.
func (mp MakeSelectableParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if mp.SystemSpecificParameters != nil {
		builder = builder.AddRaw(mp.SystemSpecificParameters.Bytes())
	}

	if mp.ControlReferenceTemplateForDigitalSignature != nil {
		builder = builder.AddRaw(mp.ControlReferenceTemplateForDigitalSignature.Bytes())
	}

	return builder.Bytes()
}

// ExtraditionParameters provides additional parameters that can be used for an INSTALL [for extradition] command.
type ExtraditionParameters struct {
	ControlReferenceTemplateForDigitalSignature *CRTDigitalSignature
}

// Bytes returns ExtraditionParameters as BER-TLV encoded bytes.
func (ep ExtraditionParameters) Bytes() []byte {
	if ep.ControlReferenceTemplateForDigitalSignature != nil {
		return bertlv.Builder{}.AddRaw(ep.ControlReferenceTemplateForDigitalSignature.Bytes()).Bytes()
	}

	return nil
}

// RegistryUpdateParameters provides additional parameters that can be used for an INSTALL [for registry update] command.
type RegistryUpdateParameters struct {
	SystemSpecificParameters                    *SystemSpecificParameters
	ControlReferenceTemplateForDigitalSignature *CRTDigitalSignature
}

// Bytes returns RegistryUpdateParameters as BER-TLV encoded bytes.
func (rup RegistryUpdateParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if rup.SystemSpecificParameters != nil {
		builder = builder.AddRaw(rup.SystemSpecificParameters.Bytes())
	}

	if rup.ControlReferenceTemplateForDigitalSignature != nil {
		builder = builder.AddRaw(rup.ControlReferenceTemplateForDigitalSignature.Bytes())
	}

	return builder.Bytes()
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
