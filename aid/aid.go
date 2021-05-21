// Package aid provides functions for handling AID as specified in ISO/IEC 7816-5.
package aid

import (
	"fmt"
)

// AID is an identifier for a chip card application.
type AID []byte

// ParseAID parses an application identifier from bytes and returns an AID.
// A valid application identifier has a length of 5-16 bytes.
func ParseAID(b []byte) (*AID, error) {
	if len(b) < 5 || len(b) > 16 {
		return nil, fmt.Errorf("AID must have a length of 5-16 bytes, got: %d", len(b))
	}

	aid := AID(b)

	return &aid, nil
}

// RID returns the Registered Identifier of an AID which consists of its first 5 bytes.
func (a AID) RID() []byte {
	return a[:5]
}

// PIX returns the Proprietary Application Identifier Extension of an AID
// which consists of all byte following its first five bytes.
func (a AID) PIX() []byte {
	return a[5:]
}
