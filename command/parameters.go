package command

import (
	"github.com/skythen/bertlv"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/open"
	"github.com/skythen/gobalplatform/tag"
)

// TagList indicates to the card how to construct the response data for each on-card entity matching the search criteria.
// It can be used as filter criteria in GetStatusCommandDataField.
type TagList struct {
	AID                                    bool
	ApplicationLifecycleState              bool
	Privileges                             bool
	ImplicitSelectionParameters            bool
	ApplicationElfAID                      bool
	ElfVersionNumber                       bool
	ListOfEmAIDs                           bool
	AssociatedSdAID                        bool
	DisplayControlTemplate                 bool
	UniformResourceLocator                 bool
	ApplicationImageTemplate               bool
	DisplayMessage                         bool
	ApplicationGroupHeadApplication        bool
	ApplicationGroupAuthorizationList      bool
	CRELApplicationAIDList                 bool
	PolicyRestrictedApplications           bool
	ApplicationGroupMembers                bool
	ApplicationDiscretionaryData           bool
	ApplicationFamily                      bool
	AssignedProtocolsImplicitSelection     bool
	InitialContactlessActivationState      bool
	ContactlessProtocolTypeState           bool
	ContactlessProtocolParametersProfile   bool
	RecognitionAlgorithm                   bool
	ContinuousProcessing                   bool
	CommunicationInterfaceAccessParameters bool
	ProtocolDataTypeA                      bool
	ProtocolDataTypeB                      bool
	CumulativeGrantedNonVolatileMemory     bool
	CumulativeGrantedVolatileMemory        bool
	CumulativeRemainingNonVolatileMemory   bool
	CumulativeRemainingVolatileMemory      bool
	ProtocolDataTypeF                      bool
	PrivacySensitiveIndicator              bool
}

// Bytes returns TagList as BER encoded bytes.
func (tl TagList) Bytes() []byte {
	outerBuilder := &bertlv.Builder{}
	innerBuilder := &bertlv.Builder{}

	if tl.AID {
		innerBuilder = innerBuilder.AddRaw(tag.AID)
	}

	if tl.ApplicationLifecycleState {
		innerBuilder = innerBuilder.AddRaw(tag.LifeCycleState)
	}

	if tl.Privileges {
		innerBuilder = innerBuilder.AddRaw(tag.Privileges)
	}

	if tl.ImplicitSelectionParameters {
		innerBuilder = innerBuilder.AddRaw(tag.ImplicitSelectionParameter)
	}

	if tl.ApplicationElfAID {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationELFAID)
	}

	if tl.ElfVersionNumber {
		innerBuilder = innerBuilder.AddRaw(tag.ELFVersion)
	}

	if tl.ListOfEmAIDs {
		innerBuilder = innerBuilder.AddRaw(tag.EMAID)
	}

	if tl.AssociatedSdAID {
		innerBuilder = innerBuilder.AddRaw(tag.AssociatedSDAID)
	}

	if tl.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.DisplayControlTemplate)
	}

	// UniformResourceLocator is a sub-tag of DisplayControlTemplate
	if tl.UniformResourceLocator && !tl.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.UniformResourceLocator)
	}

	// ApplicationImageTemplate is a sub-tag of DisplayControlTemplate
	if tl.ApplicationImageTemplate && !tl.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationImageTemplate)
	}

	// DisplayMessage is a sub-tag of DisplayControlTemplate
	if tl.DisplayMessage && !tl.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.DisplayMessage)
	}

	if tl.ApplicationGroupHeadApplication {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationGroupHeadApplication)
	}

	if tl.ApplicationGroupAuthorizationList {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationGroupAuthorizationList)
	}

	if tl.CRELApplicationAIDList {
		innerBuilder = innerBuilder.AddRaw(tag.CRELApplicationAIDList)
	}

	if tl.PolicyRestrictedApplications {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfPolicyRestrictedApplications)
	}

	if tl.ApplicationGroupMembers {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationGroupMembers)
	}

	if tl.ApplicationDiscretionaryData {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfApplicationDiscretionaryData)
	}

	if tl.ApplicationFamily {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfApplicationFamily)
	}

	if tl.AssignedProtocolsImplicitSelection {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfAssignedProtocolsImplicitSelection)
	}

	if tl.InitialContactlessActivationState {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfInitialContactlessActivationState)
	}

	if tl.ContactlessProtocolTypeState {
		innerBuilder = innerBuilder.AddRaw(tag.ContactlessProtocolTypeState)
	}

	if tl.ContactlessProtocolParametersProfile {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfContactlessProtocolParametersProfile)
	}

	if tl.RecognitionAlgorithm {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfRecognitionAlgorithm)
	}

	if tl.ContinuousProcessing {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfContinuousProcessing)
	}

	if tl.CommunicationInterfaceAccessParameters {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfCommunicationInterfaceAccessParameters)
	}

	if tl.ProtocolDataTypeA {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeA)
	}

	if tl.ProtocolDataTypeB {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeB)
	}

	if tl.CumulativeGrantedNonVolatileMemory {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfCumulativeGrantedNonVolatileMemory)
	}

	if tl.CumulativeGrantedVolatileMemory {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfCumulativeGrantedVolatileMemory)
	}

	if tl.CumulativeRemainingNonVolatileMemory {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfCumulativeRemainingNonVolatileMemory)
	}

	if tl.CumulativeRemainingVolatileMemory {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfCumulativeRemainingVolatileMemory)
	}

	if tl.ProtocolDataTypeF {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeF)
	}

	if tl.PrivacySensitiveIndicator {
		innerBuilder = innerBuilder.AddRaw(tag.PrivacySensitiveIndicator)
	}

	outerBuilder = outerBuilder.AddBytes(tag.TagList, innerBuilder.Bytes())

	return outerBuilder.Bytes()
}

// GetStatusCommandDataField must include at least aid.AID as search criteria. Other search criteria must be added TLV encoded.
// TagList can be used to indicate how response data shall be constructed.
type GetStatusCommandDataField struct {
	AID                 aid.AID
	OtherSearchCriteria []byte // Must be added TLV encoded.
	TagList             *TagList
}

// Bytes returns GetStatusCommandDataField as BER-TLV encoded bytes.
func (gsdf GetStatusCommandDataField) Bytes() []byte {
	builder := &bertlv.Builder{}

	builder = builder.AddBytes(tag.AID, gsdf.AID)

	if gsdf.OtherSearchCriteria != nil {
		builder = builder.AddRaw(gsdf.OtherSearchCriteria)
	}

	if gsdf.TagList != nil {
		builder = builder.AddRaw(gsdf.TagList.Bytes())
	}

	return builder.Bytes()
}

// TagListCRS indicates to the card how to construct the response data for each on-card entity matching the search criteria.
// It is only applicable for CRS applications. Can be used as filter criteria in GetStatusCRSCommandDataField.
type TagListCRS struct {
	AID                                      bool
	ApplicationLifecycleState                bool
	DisplayControlTemplate                   bool
	UniformResourceLocator                   bool
	ApplicationImageTemplate                 bool
	DisplayMessage                           bool
	ApplicationUpdateCounter                 bool
	SelectionPriority                        bool
	GroupHeadApplication                     bool
	GroupMembersApplication                  bool
	CRELApplicationAIDList                   bool
	PolicyRestrictedApplications             bool
	ApplicationDiscretionaryData             bool
	ApplicationFamily                        bool
	DisplayRequiredIndicator                 bool
	ContactlessProtocolTypeState             bool
	ContinuousProcessing                     bool
	RecognitionAlgorithmForImplicitSelection bool
	AssignedProtocolsForImplicitSelection    bool
	ProtocolDataTypeA                        bool
	ProtocolDataTypeB                        bool
	ProtocolDataTypeF                        bool
	ProtocolDataTypeFSystemCode              bool
	CommunicationInterfaceAvailability       bool
	PrivacySensitiveIndicator                bool
}

// Bytes returns TagListCRS as BER-TLV encoded bytes.
func (tlcrs TagListCRS) Bytes() []byte {
	outerBuilder := &bertlv.Builder{}
	innerBuilder := &bertlv.Builder{}

	if tlcrs.AID {
		innerBuilder = innerBuilder.AddRaw(tag.AID)
	}

	if tlcrs.ApplicationLifecycleState {
		innerBuilder = innerBuilder.AddRaw(tag.LifeCycleState)
	}

	if tlcrs.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.DisplayControlTemplate)
	}

	// UniformResourceLocator is a sub-tag of DisplayControlTemplate
	if tlcrs.UniformResourceLocator && !tlcrs.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.UniformResourceLocator)
	}

	// ApplicationImageTemplate is a sub-tag of DisplayControlTemplate
	if tlcrs.ApplicationImageTemplate && !tlcrs.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationImageTemplate)
	}

	// DisplayMessage is a sub-tag of DisplayControlTemplate
	if tlcrs.DisplayMessage && !tlcrs.DisplayControlTemplate {
		innerBuilder = innerBuilder.AddRaw(tag.DisplayMessage)
	}

	if tlcrs.ApplicationUpdateCounter {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationUpdateCounter)
	}

	if tlcrs.SelectionPriority {
		innerBuilder = innerBuilder.AddRaw(tag.SelectionPriority)
	}

	if tlcrs.GroupHeadApplication {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfHeadApplication)
	}

	if tlcrs.GroupMembersApplication {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfGroupMemberApplication)
	}

	if tlcrs.CRELApplicationAIDList {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfCRELApplicationAIDList)
	}

	if tlcrs.PolicyRestrictedApplications {
		innerBuilder = innerBuilder.AddRaw(tag.PolicyRestrictedApplications)
	}

	if tlcrs.ApplicationDiscretionaryData {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationDiscretionaryData)
	}

	if tlcrs.ApplicationFamily {
		innerBuilder = innerBuilder.AddRaw(tag.ApplicationFamily)
	}

	if tlcrs.DisplayRequiredIndicator {
		innerBuilder = innerBuilder.AddRaw(tag.DisplayRequiredIndicator)
	}

	if tlcrs.ContactlessProtocolTypeState {
		innerBuilder = innerBuilder.AddRaw(tag.ContactlessProtocolTypeState)
	}

	if tlcrs.ContinuousProcessing {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfContinuousProcessing)
	}

	if tlcrs.RecognitionAlgorithmForImplicitSelection {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSRecognitionAlgorithmForImplicitSelection)
	}

	if tlcrs.AssignedProtocolsForImplicitSelection {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSAssignedProtocolsForImplicitSelection)
	}

	if tlcrs.ProtocolDataTypeA {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeA)
	}

	if tlcrs.ProtocolDataTypeB {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeB)
	}

	if tlcrs.ProtocolDataTypeF {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusOfProtocolDataTypeF)
	}

	if tlcrs.ProtocolDataTypeFSystemCode {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfProtocolDataTypeFSystemCode)
	}

	if tlcrs.CommunicationInterfaceAvailability {
		innerBuilder = innerBuilder.AddRaw(tag.GetStatusCRSOfCommunicationInterfaceAvailability)
	}

	if tlcrs.PrivacySensitiveIndicator {
		innerBuilder = innerBuilder.AddRaw(tag.PrivacySensitiveIndicator)
	}

	outerBuilder = outerBuilder.AddBytes(tag.TagList, innerBuilder.Bytes())

	return outerBuilder.Bytes()
}

// GetStatusCRSCommandDataField must include at least aid.AID as search criteria. Other search criteria must be added TLV encoded.
// TagListCRS can be used to indicate how response data shall be constructed.
type GetStatusCRSCommandDataField struct {
	AID                 aid.AID
	OtherSearchCriteria []byte // must be added TLV encoded
	TagListCRS          *TagListCRS
}

// Bytes returns GetStatusCommandDataField as BER-TLV encoded bytes.
func (cdf GetStatusCRSCommandDataField) Bytes() []byte {
	builder := &bertlv.Builder{}

	builder = builder.AddBytes(tag.AID, cdf.AID)

	if cdf.OtherSearchCriteria != nil {
		builder = builder.AddRaw(cdf.OtherSearchCriteria)
	}

	if cdf.TagListCRS != nil {
		builder = builder.AddRaw(cdf.TagListCRS.Bytes())
	}

	return builder.Bytes()
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

// Protocols for Implicit Selection
const (
	ImplicitSelectionProtocolTypeA byte = 0x81 // Protocol Type A
	ImplicitSelectionProtocolTypeB byte = 0x82 // Protocol Type B
	ImplicitSelectionProtocolTypeF byte = 0x84 // Protocol Type F
)

// Initial Contactless Activation State
const (
	InitialDeactivated byte = 0x00 // OPEN shall not attempt to activate the application.
	InitialActivated   byte = 0x01 // OPEN shall attempt to activate the application when transitioning to SELECTABLE state for the first time or unlocking.
)

// Communication Interface Access
const (
	ContactBasedCommunication             byte = 0x80 // Contact-based communication (e.g. ISO/IEC 7816) is supported.
	ProximityBasedCommunication           byte = 0x40 // Proximity-based communication (e.g. ISO/IEC 14443) is supported.
	ContactAndProximityBasedCommunication byte = 0xC0 // Contact-based and Proximity-based communication are supported.
)

// CommunicationInterfaceAccessParameters are used to configure interface accessibility.
type CommunicationInterfaceAccessParameters struct {
	CommunicationInterfaceAccessRestriction util.NullByte // Set of communication interfaces that an application may use. Security Domain only.
	CommunicationInterfaceAccessDefault     util.NullByte // Accessibility configuration of an application which is installed under the hierarchy of the SD. Security Domain only.
	CommunicationInterfaceAccessPerInstance util.NullByte // Defines the accessibility configuration of the application.
}

// Bytes returns CommunicationInterfaceAccessParameters as BER-TLV encoded bytes.
func (ciap CommunicationInterfaceAccessParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if ciap.CommunicationInterfaceAccessRestriction.Valid {
		builder = builder.AddByte(tag.CommunicationInterfaceAccessRestriction, ciap.CommunicationInterfaceAccessRestriction.Byte)
	}

	if ciap.CommunicationInterfaceAccessDefault.Valid {
		builder = builder.AddByte(tag.CommunicationInterfaceAccessDefault, ciap.CommunicationInterfaceAccessDefault.Byte)
	}

	if ciap.CommunicationInterfaceAccessPerInstance.Valid {
		builder = builder.AddByte(tag.CommunicationInterfaceAccessPerInstance, ciap.CommunicationInterfaceAccessPerInstance.Byte)
	}

	return builder.Bytes()
}

// ProtocolData is the value part of the Protocol Data TLV for type A, B or F.
type ProtocolData struct {
	ProtocolParameterData          []byte
	ProtocolParameterMandatoryMask []byte
}

// Bytes returns ProtocolData as BER-TLV encoded bytes.
func (pd ProtocolData) Bytes() []byte {
	builder := &bertlv.Builder{}

	if pd.ProtocolParameterData != nil {
		builder = builder.AddBytes(tag.ProtocolParameterData, pd.ProtocolParameterData)
	}

	if pd.ProtocolParameterMandatoryMask != nil {
		builder = builder.AddBytes(tag.ProtocolParameterMandatoryMask, pd.ProtocolParameterMandatoryMask)
	}

	return builder.Bytes()
}

// Contactless Protocol Type State
const (
	ContactlessProtocolTypeA  byte = 0x80 // Contactless Protocol Type A RF activated (Card Emulation Mode) - Type B,F deactivated.
	ContactlessProtocolTypeB  byte = 0x40 // Contactless Protocol Type B RF activated (Card Emulation Mode) - Type A,F deactivated.
	ContactlessProtocolTypeF  byte = 0x20 // Contactless Protocol Type F RF activated (Card Emulation Mode) - Type A,B deactivated.
	ContactlessProtocolTypeAB byte = 0xC0 // Contactless Protocol Type A,B RF activated (Card Emulation Mode) - Type F deactivated.
	ContactlessProtocolTypeAF byte = 0xA0 // Contactless Protocol Type A,F RF activated (Card Emulation Mode) - Type B deactivated.
	ContactlessProtocolTypeBF byte = 0x60 // Contactless Protocol Type B,F RF activated (Card Emulation Mode) - Type A deactivated.
)

// ContactlessProtocolParameters for managing an application on the contactless interface.
type ContactlessProtocolParameters struct {
	AssignedProtocolsImplicitSelection     []byte                                  // Protocols of type A, B or F that are assigned for the application.
	InitialContactlessActivationState      util.NullByte                           // Initial Contactless Activation State when an application is installed and made selectable.
	ContactlessProtocolParametersProfile   []byte                                  // Profiles that are used to facilitate initialization of the Contactless Application.
	RecognitionAlgorithm                   []byte                                  // Provides the capability of the contactless interface to identify and select a legacy Contactless Application not supporting the SELECT by AID command.
	ContinuousProcessing                   []byte                                  // Continuous Processing for applications and the OPEN.
	CommunicationInterfaceAccessParameters *CommunicationInterfaceAccessParameters // Communication Interface Access Configuration
	ProtocolDataTypeA                      *ProtocolData                           // Protocol Data Type A TLV
	ProtocolDataTypeB                      *ProtocolData                           // Protocol Data Type B TLV
	ProtocolDataTypeF                      *ProtocolData                           // Protocol Data Type F TLV
	ContactlessProtocolTypeState           util.NullByte                           // Used to set the new Contactless Protocol Type State of the contactless interface.
}

// Bytes returns ContactlessProtocolParameters as BER-TLV encoded bytes.
func (cpp ContactlessProtocolParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if cpp.AssignedProtocolsImplicitSelection != nil {
		builder = builder.AddRaw(tag.AssignedProtocolsImplicitSelection)

		// add length of protocol tags
		builder = builder.AddRaw([]byte{byte(len(cpp.AssignedProtocolsImplicitSelection))})

		for _, protocol := range cpp.AssignedProtocolsImplicitSelection {
			builder = builder.AddRaw([]byte{protocol})
		}
	}

	if cpp.InitialContactlessActivationState.Valid {
		builder = builder.AddByte(tag.InitialContactlessActivationState, cpp.InitialContactlessActivationState.Byte)
	}

	if cpp.ContactlessProtocolParametersProfile != nil {
		builder = builder.AddBytes(tag.ContactlessProtocolParametersProfile, cpp.ContactlessProtocolParametersProfile)
	}

	if cpp.RecognitionAlgorithm != nil {
		builder = builder.AddBytes(tag.RecognitionAlgorithm, cpp.RecognitionAlgorithm)
	}

	if cpp.ContinuousProcessing != nil {
		builder = builder.AddBytes(tag.ContinuousProcessing, cpp.ContinuousProcessing)
	}

	if cpp.CommunicationInterfaceAccessParameters != nil {
		builder = builder.AddBytes(tag.CommunicationInterfaceAccessParameters, cpp.CommunicationInterfaceAccessParameters.Bytes())
	}

	if cpp.ProtocolDataTypeA != nil {
		builder = builder.AddBytes(tag.ProtocolDataTypeA, cpp.ProtocolDataTypeA.Bytes())
	}

	if cpp.ProtocolDataTypeB != nil {
		builder = builder.AddBytes(tag.ProtocolDataTypeB, cpp.ProtocolDataTypeB.Bytes())
	}

	if cpp.ProtocolDataTypeF != nil {
		builder = builder.AddBytes(tag.ProtocolDataTypeF, cpp.ProtocolDataTypeF.Bytes())
	}

	if cpp.ContactlessProtocolTypeState.Valid {
		builder = builder.AddByte(tag.ContactlessProtocolTypeState, cpp.ContactlessProtocolTypeState.Byte)
	}

	return builder.Bytes()
}

// Display Required Indicator
const (
	DisplayRequired    byte = 0x00 // Application requires a display
	DisplayNotRequired byte = 0x01 // Application does not require a display
)

// UserInteractionParameters provide parameters for user interaction.
type UserInteractionParameters struct {
	DisplayControlTemplate           []byte        // Used to manage an off-card GUI by providing information for a logo, a URL or any related display information.
	HeadApplication                  aid.AID       // Allows an application to request to be member of a group.
	AddToGroupAuthorizationList      []aid.AID     // Establishes the target application as a head application by creating its Group Authorization List.
	RemoveFromGroupAuthorizationList []aid.AID     // Used to remove one or more AIDs from Group Authorization List.
	AddToCRELList                    []aid.AID     // List of AIDs of CREL applications that shall be notified by the OPEN upon any change in the GPRegistryEntry of the target application.
	RemoveFromCRELList               []aid.AID     // List of AIDs of CREL applications that shall be removed from the notification list of an application.
	PolicyRestrictedApplications     []aid.AID     // List of AIDs of applications that should not be activated on the contactless interface at the same time as the application that has this TLV in its registry.
	ApplicationDiscretionaryData     []byte        // Is accessible to the CRS application and CREL applications, if any, for proprietary usage.
	ApplicationFamily                util.NullByte // May be used to group together the applications for a similar process.
	DisplayRequiredIndicator         util.NullByte // Indicates whether the application is able to perform a contactless transaction even when the display is not available.
}

// Bytes returns UserInteractionParameters as BER-TLV encoded bytes.
func (uip UserInteractionParameters) Bytes() []byte {
	builder := &bertlv.Builder{}

	if uip.DisplayControlTemplate != nil {
		builder = builder.AddBytes(tag.DisplayControlTemplate, uip.DisplayControlTemplate)
	}

	if uip.HeadApplication != nil {
		aidBuilder := &bertlv.Builder{}

		aidBuilder = aidBuilder.AddBytes(tag.AID, uip.HeadApplication)

		builder = builder.AddBytes(tag.HeadApplication, aidBuilder.Bytes())
	}

	if uip.AddToGroupAuthorizationList != nil {
		groupAuthorizationListBuilder := &bertlv.Builder{}

		for _, aidToAdd := range uip.AddToGroupAuthorizationList {
			groupAuthorizationListBuilder = groupAuthorizationListBuilder.AddBytes(tag.AID, aidToAdd)
		}

		builder = builder.AddBytes(tag.AddToGroupAuthorizationList, groupAuthorizationListBuilder.Bytes())
	}

	if uip.RemoveFromGroupAuthorizationList != nil {
		groupAuthorizationListBuilder := &bertlv.Builder{}

		for _, aidToRemove := range uip.RemoveFromGroupAuthorizationList {
			groupAuthorizationListBuilder = groupAuthorizationListBuilder.AddBytes(tag.AID, aidToRemove)
		}

		builder = builder.AddBytes(tag.RemoveFromGroupAuthorizationList, groupAuthorizationListBuilder.Bytes())
	}

	if uip.AddToCRELList != nil {
		crelListBuilder := &bertlv.Builder{}

		for _, aidToAdd := range uip.AddToCRELList {
			crelListBuilder = crelListBuilder.AddBytes(tag.AID, aidToAdd)
		}

		builder = builder.AddBytes(tag.AddToCRELList, crelListBuilder.Bytes())
	}

	if uip.RemoveFromCRELList != nil {
		crelListBuilder := &bertlv.Builder{}

		for _, aidToRemove := range uip.RemoveFromCRELList {
			crelListBuilder = crelListBuilder.AddBytes(tag.AID, aidToRemove)
		}

		builder = builder.AddBytes(tag.RemoveFromCRELList, crelListBuilder.Bytes())
	}

	if uip.PolicyRestrictedApplications != nil {
		policyRestrictedBuilder := &bertlv.Builder{}

		for _, aidToAdd := range uip.PolicyRestrictedApplications {
			policyRestrictedBuilder = policyRestrictedBuilder.AddBytes(tag.AID, aidToAdd)
		}

		builder = builder.AddBytes(tag.PolicyRestrictedApplications, policyRestrictedBuilder.Bytes())
	}

	if uip.ApplicationDiscretionaryData != nil {
		builder = builder.AddBytes(tag.ApplicationDiscretionaryData, uip.ApplicationDiscretionaryData)
	}

	if uip.ApplicationFamily.Valid {
		builder = builder.AddByte(tag.ApplicationFamily, uip.ApplicationFamily.Byte)
	}

	if uip.DisplayRequiredIndicator.Valid {
		builder = builder.AddByte(tag.DisplayRequiredIndicator, uip.DisplayRequiredIndicator.Byte)
	}

	return builder.Bytes()
}

// Privacy Sensitive Indicator
const (
	NotPrivacySensitive byte = 0x00 // Application is not Privacy-Sensitive
	PrivacySensitive    byte = 0x01 // Application is Privacy-Sensitive
)

// SystemSpecificParameters provide additional parameters that can be used for an INSTALL command, although their presence might be ignored.
// If both tag 'C6' and 'C8' are present and the implementation does not make any distinction between Non-Volatile Code and Non-Volatile Data Memory
// then the required minimum shall be the sum of both values.
type SystemSpecificParameters struct {
	NonVolatileCodeMinimumRequirement   []byte                         // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	VolatileMemoryMinimumRequirement    []byte                         // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	NonVolatileMemoryMinimumRequirement []byte                         // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	VolatileReservedMemory              []byte                         // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	NonVolatileReservedMemory           []byte                         // 2-byte integer for values up to 32767 and a 4-byte integer above 32767
	GlobalServiceParameters             []byte                         // One or more two-byte service parameters.
	TS102226SpecificParameters          []byte                         // UICC specific parameters.
	LoadFileDataBlockFormatID           util.NullByte                  // Proprietary Load File Data Block format ID.
	LoadFileDataBlockParameters         []byte                         // Proprietary Load File Data Block parameters.
	RestrictParameter                   *open.Restrict                 // Lists functionalities that shall be disabled.
	ImplicitSelectionParameter          util.NullByte                  // Implicit selection parameter.
	PrivacyRequirements                 *PrivacyRequirements           // Privacy Requirements for an application.
	ContactlessProtocolParameters       *ContactlessProtocolParameters // Contains tags for managing an application on the contactless interface.
	UserInteractionParameters           *UserInteractionParameters     // Parameters that are relevant for end-user interaction.
	ETSIParameters                      []byte                         // Assigned to ETSI.
	CumulativeGrantedVolatileMemory     []byte                         // Specifies the exact amount of volatile memory granted to Security Domain, to its applications and its entire sub-hierarchy.
	CumulativeGrantedNonVolatileMemory  []byte                         // Specifies the exact amount of non-volatile memory granted to Security Domain, to its applications and its entire sub-hierarchy.
	PrivacySensitiveIndicator           util.NullByte                  // Indicates whether the application is privacy-sensitive or not.
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

	if ssp.ContactlessProtocolParameters != nil {
		builder = builder.AddBytes(tag.ContactlessProtocolParameters, ssp.ContactlessProtocolParameters.Bytes())
	}

	if ssp.UserInteractionParameters != nil {
		builder = builder.AddBytes(tag.UserInteractionParameters, ssp.UserInteractionParameters.Bytes())
	}

	if ssp.ETSIParameters != nil {
		builder = builder.AddBytes(tag.ETSIAssigned, ssp.ETSIParameters)
	}

	if ssp.CumulativeGrantedVolatileMemory != nil {
		builder = builder.AddBytes(tag.CumulativeGrantedVolatileMemory, ssp.CumulativeGrantedVolatileMemory)
	}

	if ssp.CumulativeGrantedNonVolatileMemory != nil {
		builder = builder.AddBytes(tag.CumulativeGrantedNonVolatileMemory, ssp.CumulativeGrantedNonVolatileMemory)
	}

	if ssp.PrivacySensitiveIndicator.Valid {
		builder = builder.AddByte(tag.PrivacySensitiveIndicator, ssp.PrivacySensitiveIndicator.Byte)
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
