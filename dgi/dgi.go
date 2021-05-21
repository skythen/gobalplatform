// Package dgi provides functions for parsing Data Group Identifier structures.
package dgi

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	KeyControlReferenceTemplate = [2]byte{0x00, 0xB9}
	PrivateKeyExponent          = [2]byte{0x81, 0x12}
	SecretKey                   = [2]byte{0x81, 0x13}
	PublicKeyExponent           = [2]byte{0x00, 0x11}
	KeyModulus                  = [2]byte{0x00, 0x10}
	RsaCrtIqmp                  = [2]byte{0x81, 0x21}
	RsaCrtDmq1                  = [2]byte{0x81, 0x22}
	RsaCrtDmp1                  = [2]byte{0x81, 0x23}
	RsaCrtQ                     = [2]byte{0x81, 0x24}
	RsaCrtP                     = [2]byte{0x81, 0x25}
	EccP                        = [2]byte{0x00, 0x30}
	EccA                        = [2]byte{0x00, 0x31}
	EccB                        = [2]byte{0x00, 0x32}
	EccG                        = [2]byte{0x00, 0x33}
	EccN                        = [2]byte{0x00, 0x34}
	EccK                        = [2]byte{0x00, 0x35}
	EccQ                        = [2]byte{0x00, 0x36}
	EccD                        = [2]byte{0x81, 0x37}
)

// DGI is a Data Grouping Identifier which is used to personalize data or trigger actions within Security Domains.
type DGI struct {
	DGI   [2]byte // Two byte DGI.
	Value []byte  // Value of the DGI.
}

// Bytes encodes the DGI as a TLV-like structure (not to be confused with BER-TLV).
func (dgi DGI) Bytes() ([]byte, error) {
	length, err := buildDGILength(uint(len(dgi.Value)))
	if err != nil {
		return nil, errors.Wrap(err, "invalid DGI length")
	}

	bytes := make([]byte, 0, 2+len(length)+len(dgi.Value))
	bytes = append(bytes, dgi.DGI[:]...)
	bytes = append(bytes, length...)
	bytes = append(bytes, dgi.Value...)

	return bytes, nil
}

// buildDGILength encodes a length value up to 65535 on up to three bytes.
// The formatting is as defined by ASN.1 BER-TLV (see [ISO 8825-1]) except that the length 128 may also be coded on one byte as '80'.
func buildDGILength(length uint) ([]byte, error) {
	if length > 65534 {
		return nil, fmt.Errorf("length must not exceed 65534, got %d", length)
	}

	if length <= 254 {
		return []byte{byte(length)}, nil
	}

	return []byte{0xFF, (byte)(length>>8) & 0xFF, (byte)(length & 0xFF)}, nil
}
