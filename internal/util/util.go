package util

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// NullByte represents a byte that may be null.
type NullByte struct {
	Byte  byte // the actual value
	Valid bool // true if Byte is not NULL
}

// BuildGPBerLength encodes a length value up to 65535 on up to three byte.
// The formatting is as defined by ASN.1 BER-TLV (see [ISO 8825-1]) except that the length 128 may also be coded on one byte as '80'.
func BuildGPBerLength(length uint) ([]byte, error) {
	if length > 65535 {
		return nil, fmt.Errorf("length must not exceed 65535, got %d", length)
	}

	if length <= 128 {
		return []byte{byte(length)}, nil
	}

	if length <= 255 {
		return []byte{0x81, byte(length)}, nil
	}

	return []byte{0x82, (byte)(length>>8) & 0xFF, (byte)(length & 0xFF)}, nil
}

func EvaluateTestWithError(t *testing.T, expErr bool, rcvErr error, exp interface{}, rcv interface{}) {
	if rcvErr != nil && !expErr {
		t.Errorf("Expected: no error, got: error(%v)", rcvErr.Error())

		return
	}

	if rcvErr == nil && expErr {
		t.Errorf("Expected: error, got: no error")

		return
	}

	if !cmp.Equal(exp, rcv) {
		t.Errorf("Expected: '%v', got: '%v'", exp, rcv)
	}
}
