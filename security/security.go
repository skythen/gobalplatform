// Package security provides functions for handling objects related to Secure Communication with a card.
package security

import "github.com/pkg/errors"

// AuthenticationStatus is the current authentication status of a secure channel session.
type AuthenticationStatus int

const (
	// NotAuthenticated indicates that authentication status is neither AUTHENTICATED nor ANY_AUTHENTICATED.
	NotAuthenticated AuthenticationStatus = iota
	// Authenticated indicates authentication status AUTHENTICATED.
	Authenticated
	// AnyAuthenticated indicates authentication status ANY_AUTHENTICATED.
	AnyAuthenticated
)

// Level provides secure messaging protection levels that are applied
// to protected messages, either for the whole session or for a specific command-response pair.
// The rules for handling Security Levels are defined individually for each Secure Channel Protocol.
type Level struct {
	AuthenticationStatus AuthenticationStatus
	CDEC                 bool // Command decryption.
	CMAC                 bool // Command Message Authentication Code.
	RMAC                 bool // Response Message Authentication Code.
	RENC                 bool // Response encryption.
}

// ParseLevel parses the current security level and returns Level.
func ParseLevel(b byte) (*Level, error) {
	level := &Level{}

	if b&0x80 == 0x80 {
		level.AuthenticationStatus = Authenticated
	}

	if b&0x40 == 0x40 {
		if level.AuthenticationStatus == Authenticated {
			return nil, errors.New("security level indicates AUTHENTICATED and ANY_AUTHENTICATED at the same time")
		}

		level.AuthenticationStatus = AnyAuthenticated
	}

	if b&0x20 == 0x20 {
		level.RENC = true
	}

	if b&0x10 == 0x10 {
		level.RMAC = true
	}

	if b&0x02 == 0x02 {
		level.CDEC = true
	}

	if b&0x01 == 0x01 {
		level.CMAC = true
	}

	return level, nil
}

// Byte encodes Level on a byte.
func (level Level) Byte() byte {
	var b byte

	if level.AuthenticationStatus == Authenticated {
		b += 0x80
	} else if level.AuthenticationStatus == AnyAuthenticated {
		b += 0x40
	}

	if level.CDEC {
		b += 0x02
	}

	if level.CMAC {
		b += 0x01
	}

	if level.RMAC {
		b += 0x10
	}

	if level.RENC {
		b += 0x20
	}

	return b
}

// SCPParameter is used for storing data about SCPs that might be unknown to the current implementation.
type SCPParameter struct {
	ID     byte // ID of the SCP.
	Option byte // i-Param of the SCP.
}

// SCP02Parameter contains options encoded on the i-Parameter for SCP02.
type SCP02Parameter struct {
	ThreeSCKeys                bool // true: 3 Secure Channel Keys, false: 1 Secure Channel base key
	CMACOnUnmodifiedAPDU       bool // true: C-MAC on unmodified APDU, false: C-MAC on modified APDU
	ExplicitInitiation         bool // true: Initiation mode explicit, false: Initiation mode implicit
	ICVMacOverAID              bool // true: ICV set to MAC over AID, false: ICV set to zero
	ICVEncryptionForCMAC       bool // true: ICV encryption for C-MAC session, false: No ICV encryption
	RMACSupported              bool // true: R-MAC support, false: No R-MAC support
	KnownPseudoRandomAlgorithm bool // true: Well-known pseudo-random algorithm (card challenge), false: Unspecified card challenge generation method
}

// ParseSCP02Parameter parses the i-Param for SCP02 and returns SCP02Parameter.
func ParseSCP02Parameter(i byte) *SCP02Parameter {
	param := &SCP02Parameter{}

	if i&0x01 == 0x01 {
		param.ThreeSCKeys = true
	}

	if i&0x02 == 0x02 {
		param.CMACOnUnmodifiedAPDU = true
	}

	if i&0x04 == 0x04 {
		param.ExplicitInitiation = true
	}

	if i&0x08 == 0x08 {
		param.ICVMacOverAID = true
	}

	if i&0x10 == 0x10 {
		param.ICVEncryptionForCMAC = true
	}

	if i&0x20 == 0x20 {
		param.RMACSupported = true
	}

	if i&0x40 == 0x40 {
		param.KnownPseudoRandomAlgorithm = true
	}

	return param
}

// Byte encodes SCP02Parameter on a byte.
func (param SCP02Parameter) Byte() byte {
	b := 0x00
	if param.ThreeSCKeys {
		b += 0x01
	}

	if param.CMACOnUnmodifiedAPDU {
		b += 0x02
	}

	if param.ExplicitInitiation {
		b += 0x04
	}

	if param.ICVMacOverAID {
		b += 0x08
	}

	if param.ICVEncryptionForCMAC {
		b += 0x10
	}

	if param.RMACSupported {
		b += 0x20
	}

	if param.KnownPseudoRandomAlgorithm {
		b += 0x40
	}

	return byte(b)
}

// SCP03Parameter contains options encoded on the i-Parameter for SCP03.
type SCP03Parameter struct {
	PseudoRandomCardChallenge bool // true:Pseudo-random card challenge, false: Random card challenge
	RMACSupport               bool // Response MAC.
	RENCSupport               bool // Response encryption.
}

// ParseSCP03Parameter parses the i-Param for SCP03 and returns SCP03Parameter.
func ParseSCP03Parameter(i byte) *SCP03Parameter {
	param := &SCP03Parameter{}

	if i&0x10 == 0x10 {
		param.PseudoRandomCardChallenge = true
	}

	if i&0x60 == 0x20 {
		param.RMACSupport = true
	} else if i&0x60 == 0x60 {
		param.RMACSupport = true
		param.RENCSupport = true
	}

	// b1-4 is rfu... ignore for now
	return param
}

// Byte encodes SCP03Parameter on a byte.
func (param SCP03Parameter) Byte() byte {
	b := 0x00

	if param.PseudoRandomCardChallenge {
		b += 0x10
	}

	if param.RMACSupport {
		b += 0x20
	}

	if param.RENCSupport {
		b += 0x40
	}

	return byte(b)
}

// SCP10Parameter contains options encoded on the i-Parameter for SCP10.
type SCP10Parameter struct {
	KeyAgreement                    bool // true: Key Agreement, false: Key Transport
	SignatureWithoutMessageRecovery bool // true: Signature without message recovery, false: Signature with message recovery
}

// ParseSCP10Parameter parses the i-Param for SCP10 and returns SCP10Parameter.
func ParseSCP10Parameter(i byte) *SCP10Parameter {
	param := &SCP10Parameter{}

	if i&0x01 == 0x01 {
		param.KeyAgreement = true
	}

	if i&0x02 == 0x02 {
		param.SignatureWithoutMessageRecovery = true
	}

	// b1-4 is rfu... ignore for now
	return param
}

// Byte encodes SCP10Parameter on a byte.
func (param SCP10Parameter) Byte() byte {
	b := 0x00

	if param.KeyAgreement {
		b += 0x01
	}

	if param.SignatureWithoutMessageRecovery {
		b += 0x02
	}

	return byte(b)
}

/*
// SCP21 Parameter represents options encoded in the i-Parameter for SCP21.
type SCP21Parameter struct {
	PACE bool
	EACV1 bool
	GAP bool
}

// ParseSCP21Parameter parses the i-Param for SCP21 and returns SCP21Parameter.
func ParseSCP21Parameter(i byte) *SCP21Parameter {
	param := &SCP21Parameter{}

	if i&0x01 == 0x01 {
		param.PACE = true
	}

	if i&0x02 == 0x02 {
		param.EACV1 = true
	}

	if i&0x01 == 0x01 && i&0x04 == 0x04 {
		param.GAP = true
	}

	// b8-4 is rfu... ignore for now
	return param
}

// Byte encodes SCP21Parameter on a byte.
func (scp21Param SCP21Parameter) Byte() byte {
	b := 0x00

	if scp21Param.PACE {
		b += 0x01
	}

	if scp21Param.EACV1 {
		b += 0x02
	}

	if scp21Param.GAP {
		if b & 0x01 != 0x01 {
			b += 0x01
		}

		b += 0x04
	}

	return byte(b)
}

// SCP22Parameter represents options encoded in the i-Parameter for SCP22.
type SCP22Parameter struct {
	OpacityZKM bool
	OpacityBlinded bool
	OpacityFS bool
}

// ParseSCP22Parameter parses the i-Param for SCP22 and returns SCP22Parameter.
func (scp22Param SCP22Parameter) ParseSCP22Parameter(i byte) *SCP22Parameter {
	param := &SCP22Parameter{}

	if i == 0x00 {
		param.OpacityZKM = true

		return  param
	}

	if i == 0x20 {
		param.OpacityBlinded = true

		return param
	}

	if i == 0x40{
		param.OpacityFS = true

		return param
	}

	// b8-4 is rfu... ignore for now
	return param
}
*/
