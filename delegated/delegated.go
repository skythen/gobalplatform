package delegated

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/skythen/gobalplatform/aid"
	"github.com/skythen/gobalplatform/command"
	"github.com/skythen/gobalplatform/internal/util"
	"github.com/skythen/gobalplatform/open"
)

// Confirmation is a confirmation for a delegated card content management operation.
type Confirmation struct {
	Receipt []byte // A cryptographic value provided by the card (if so required by the Card Issuer) as proof that a Delegated Management operation has occurred.
	Data    ConfirmationData
}

// ParseConfirmationStructure parses an LV encoded Confirmation Structure and returns Confirmation.
func ParseConfirmationStructure(b []byte) (*Confirmation, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("confirmation must be at least 6 bytes long, got %d", len(b))
	}

	var lenReceipt uint16

	confirmationIndex := uint16(0)
	// check if length of confirmation is encoded in more than one byte
	if b[0] == 0x81 {
		lenReceipt = binary.BigEndian.Uint16(b[:2])
		confirmationIndex += 2
	} else {
		lenReceipt = uint16(b[0])
		confirmationIndex++
	}

	if uint16(len(b)) < (confirmationIndex + lenReceipt) {
		return nil, errors.New("invalid length of receipt")
	}

	confirmation := Confirmation{}

	confirmation.Receipt = b[confirmationIndex : confirmationIndex+lenReceipt]
	confirmationIndex += lenReceipt

	// check if more data is available
	if len(b) > int(confirmationIndex) {
		confirmationData, err := parseConfirmationData(b[confirmationIndex:])
		if err != nil {
			return nil, err
		}

		confirmation.Data = *confirmationData
	}

	return &confirmation, nil
}

type ConfirmationData struct {
	Counter uint16
	// Security Domain unique data is the concatenation without delimiters of the
	// Security Domain Provider Identification Number ('42') and the Security Domain Image Number (SDIN, tag '45') of
	// the Security Domain generating the confirmation (with the Receipt Generation Privilege).
	SDUniqueData    []byte
	TokenIdentifier []byte // Presence depends on whether a Token identifier was included in the original Token.
	TokenDataDigest []byte // Presence depends on the policy of the Security Domain with Receipt Generation privilege.
}

func parseConfirmationData(b []byte) (*ConfirmationData, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("confirmation data must be at least 5 byte long, got %d", len(b))
	}

	data := &ConfirmationData{}

	data.Counter = binary.BigEndian.Uint16(b[1:3])
	index := 3

	lenCardUniqueData := int(b[index])
	index++

	data.SDUniqueData = b[index : index+lenCardUniqueData]
	index += lenCardUniqueData

	if len(b) > index {
		lenTokenIdentifier := int(b[index])
		index++
		data.TokenIdentifier = b[index : index+lenTokenIdentifier]
		index += lenTokenIdentifier
	}

	if len(b) > index {
		lenTokenDataDigest := int(b[index])
		index++
		data.TokenDataDigest = b[index : index+lenTokenDataDigest]
	}

	return data, nil
}

// InputForLoad generates input data for signature for the creation of a LOAD token.
func InputForLoad(p1, p2 byte, lfAID, sdAID aid.AID, lfdbHash []byte, loadParams command.LoadParameters) ([]byte, error) {
	bParams := loadParams.Bytes()

	return inputForLoad(p1, p2, lfAID, sdAID, lfdbHash, bParams)
}

func inputForLoad(p1, p2 byte, elfAID, sdAID aid.AID, lfdbh []byte, params []byte) ([]byte, error) {
	paramsLength, err := util.BuildGPBerLength(uint(len(params)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid parameters length")
	}

	data := make([]byte, 0, 3+len(sdAID)+len(elfAID)+len(lfdbh)+len(paramsLength)+len(params))
	data = append(data, byte(len(elfAID)))
	data = append(data, elfAID...)
	data = append(data, byte(len(sdAID)))
	data = append(data, sdAID...)
	data = append(data, byte(len(lfdbh)))
	data = append(data, lfdbh...)
	data = append(data, paramsLength...)
	data = append(data, params...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

// InputForInstall generates input data for signature for the creation of an INSTALL token.
func InputForInstall(p1, p2 byte, elfAID, emAID, instanceAID aid.AID, privileges open.Privileges, installParams command.InstallParameters) ([]byte, error) {
	bPrivs, err := privileges.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "invalid Privileges")
	}

	bParams := installParams.Bytes()

	return inputForInstall(p1, p2, elfAID, emAID, instanceAID, bPrivs, bParams)
}

func inputForInstall(p1, p2 byte, elfAID, emAID, instanceAID aid.AID, privs, params []byte) ([]byte, error) {
	paramsLength, err := util.BuildGPBerLength(uint(len(params)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid parameters length")
	}

	data := make([]byte, 0, 4+len(elfAID)+len(emAID)+len(instanceAID)+len(privs)+len(paramsLength)+len(params))
	data = append(data, byte(len(elfAID)))
	data = append(data, elfAID...)
	data = append(data, byte(len(emAID)))
	data = append(data, emAID...)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, byte(len(privs)))
	data = append(data, privs...)
	data = append(data, paramsLength...)
	data = append(data, params...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

// InputForMakeSelectable generates input data for signature for the creation of a MAKE SELECTABLE token.
func InputForMakeSelectable(p1, p2 byte, instanceAID aid.AID, privs open.Privileges, makeSelectableParams command.MakeSelectableParameters) ([]byte, error) {
	bPrivs, err := privs.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "invalid Privileges")
	}

	bParams := makeSelectableParams.Bytes()

	paramsLength, err := util.BuildGPBerLength(uint(len(bParams)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid parameters length")
	}

	data := make([]byte, 0, 4+len(instanceAID)+len(bPrivs)+len(paramsLength)+len(bParams))
	data = append(data, 0x00)
	data = append(data, 0x00)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, byte(len(bPrivs)))
	data = append(data, bPrivs...)
	data = append(data, paramsLength...)
	data = append(data, bParams...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

// InputForExtradition generates input data for signature for the creation of an EXTRADITION token.
func InputForExtradition(p1, p2 byte, sdAID, elfOrAppAID aid.AID, extraditionParams command.ExtraditionParameters) ([]byte, error) {
	bParams := extraditionParams.Bytes()

	paramsLength, err := util.BuildGPBerLength(uint(len(bParams)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid parameters length")
	}

	data := make([]byte, 0, 4+len(sdAID)+len(elfOrAppAID)+len(bParams)+len(paramsLength))
	data = append(data, byte(len(sdAID)))
	data = append(data, sdAID...)
	data = append(data, 0x00)
	data = append(data, byte(len(elfOrAppAID)))
	data = append(data, elfOrAppAID...)
	data = append(data, 0x00)
	data = append(data, paramsLength...)
	data = append(data, bParams...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

// InputForRegistryUpdate generates input data for signature for the creation of an REGISTRY UPDATE token.
func InputForRegistryUpdate(p1, p2 byte, sdAID, instanceAID aid.AID, privs open.Privileges, registryUpdateParams command.RegistryUpdateParameters) ([]byte, error) {
	bPrivs, err := privs.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "invalid Privileges")
	}

	bParams := registryUpdateParams.Bytes()

	paramsLength, err := util.BuildGPBerLength(uint(len(bParams)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid parameters length")
	}

	data := make([]byte, 0, 4+len(sdAID)+len(instanceAID)+len(bPrivs)+len(bParams)+len(paramsLength))
	data = append(data, byte(len(sdAID)))
	data = append(data, sdAID...)
	data = append(data, 0x00)
	data = append(data, byte(len(instanceAID)))
	data = append(data, instanceAID...)
	data = append(data, byte(len(bPrivs)))
	data = append(data, bPrivs...)
	data = append(data, paramsLength...)
	data = append(data, bParams...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

// InputForDelete generates input data for signature for the creation of a DELETE token.
func InputForDelete(p1, p2 byte, elfOrAppAID aid.AID, crtDigitalSignature command.CRTDigitalSignature) ([]byte, error) {
	bCrtDigitalSignature := crtDigitalSignature.Bytes()

	data := make([]byte, 0, 2+len(elfOrAppAID)+len(bCrtDigitalSignature))
	data = append(data, 0x4F)
	data = append(data, byte(len(elfOrAppAID)))
	data = append(data, elfOrAppAID...)
	data = append(data, bCrtDigitalSignature...)

	tokenData, err := makeTokenData(p1, p2, data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token data")
	}

	return tokenData, nil
}

type LoadInstallAndMakeSelectableTokenInput struct {
	LoadP1            byte                       // P1 of the Install [for LOAD] command.
	LoadP2            byte                       // P2 of the Install [for LOAD] command.
	LoadELFAID        aid.AID                    // AID of the ELF to be loaded.
	SDAID             aid.AID                    // AID of the Security Domain in the Install [for LOAD] command.
	LFDBHash          []byte                     // Conditional hash of the Load File Data Block.
	LoadParameters    *command.LoadParameters    // Additional parameters for the Install [for LOAD] command.
	InstallP1         byte                       // P1 of the Install [for load,install and make selectable] command.
	InstallP2         byte                       // P2 of the Install [for load,install and make selectable] command.
	InstallELFAID     aid.AID                    // AID of the ELF that contains the application to be installed.
	EMAID             aid.AID                    // AID of the EM that the application shall be instantiated from.
	InstanceAID       aid.AID                    // AID of the application instance.
	Privileges        open.Privileges            // Privileges that shall be assigned to the application instance.
	InstallParameters *command.InstallParameters // Additional parameters for the Install [for load,install and make selectable] command.
}

// InputForLoadInstallAndMakeSelectable generates input data for signature for the creation of a LOAD, INSTALl and MAKE SELECTABLE token.
func InputForLoadInstallAndMakeSelectable(inputData *LoadInstallAndMakeSelectableTokenInput) ([]byte, error) {
	var (
		bLoadParams    []byte
		bInstallParams []byte
	)

	if inputData.LoadParameters != nil {
		bLoadParams = inputData.LoadParameters.Bytes()
	}

	if inputData.InstallParameters != nil {
		bInstallParams = inputData.InstallParameters.Bytes()
	}

	bPrivs, err := inputData.Privileges.Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "invalid Privileges")
	}

	loadTokenData, err := inputForLoad(inputData.LoadP1, inputData.LoadP2, inputData.LoadELFAID, inputData.SDAID, inputData.LFDBHash, bLoadParams)
	if err != nil {
		return nil, errors.Wrap(err, "invalid data for LOAD token")
	}

	installTokenData, err := inputForInstall(inputData.InstallP1, inputData.InstallP2, inputData.InstallELFAID, inputData.EMAID, inputData.InstanceAID, bPrivs, bInstallParams)
	if err != nil {
		return nil, errors.Wrap(err, "invalid data for INSTALL token")
	}

	input := append(loadTokenData, installTokenData...)

	return input, nil
}

func makeTokenData(p1, p2 byte, data []byte) ([]byte, error) {
	length, err := lengthFollowingDataFields(len(data))
	if err != nil {
		return nil, errors.Wrap(err, "invalid length of following data")
	}

	tokenData := make([]byte, 0, len(length)+len(data)+2)
	tokenData = append(tokenData, []byte{p1, p2}...)
	tokenData = append(tokenData, length...)
	tokenData = append(tokenData, data...)

	return tokenData, nil
}

func lengthFollowingDataFields(length int) ([]byte, error) {
	if length > 65535 {
		return nil, errors.Errorf("length must not exceed 65535, got: %d", length)
	}

	if length > 255 {
		return []byte{0x00, (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF)}, nil
	}

	return []byte{byte(length)}, nil
}
