package crypto

import (
	"crypto/cipher"
	"crypto/des"

	"github.com/pkg/errors"
)

// Pad80 takes a []byte and a block size which must be a multiple of 8 and appends '80' and zero bytes until
// the length of the resulting []byte reaches a multiple of the block size and returns the padded []byte.
// If force is false, the padding will only be applied, if the []byte is not a multiple of the blocksize.
// If force is true, the padding will be applied anyways.
func Pad80(b []byte, blockSize int, force bool) ([]byte, error) {
	if blockSize%8 != 0 {
		return nil, errors.New("block size must be a multiple of 8")
	}

	rest := len(b) % blockSize
	if rest != 0 || force {
		padded := make([]byte, len(b)+blockSize-rest)
		copy(padded, b)
		padded[len(b)] = 0x80

		return padded, nil
	}

	return b, nil
}

// DESFinalTDESMac calculates a MAC with Single DES and a final round TripleDES in CBC mode.
// The length of input data must be a multiple of 8.
func DESFinalTDESMac(dst *[8]byte, src []byte, key [16]byte, iv [8]byte) error {
	if len(src)%des.BlockSize != 0 {
		return errors.New("length of src must be a multiple of 8")
	}

	tdesKey := resizeDoubleDESToTDES(key)
	sdesKey := key[:8]

	// get key as single des
	sdes, err := des.NewCipher(sdesKey)
	if err != nil {
		return errors.Wrap(err, "create DES cipher")
	}

	tdes, err := des.NewTripleDESCipher(tdesKey[:])
	if err != nil {
		return errors.Wrap(err, "create TDES cipher")
	}

	tdesCbc := cipher.NewCBCEncrypter(tdes, iv[:])

	if len(src) > 8 {
		// first do simple DES
		sdesCbc := cipher.NewCBCEncrypter(sdes, iv[:])
		tmp1 := make([]byte, len(src)-des.BlockSize)
		sdesCbc.CryptBlocks(tmp1, src[:len(src)-des.BlockSize])
		// use the result as IV for TDES
		tdesCbc = cipher.NewCBCEncrypter(tdes, tmp1[len(tmp1)-des.BlockSize:])
	}

	tdesCbc.CryptBlocks(dst[:], src[len(src)-des.BlockSize:])

	return nil
}

// resizeDoubleDESToTDES resizes a double length DES key to a Triple DES key.
func resizeDoubleDESToTDES(key [16]byte) [24]byte {
	var k [24]byte

	copy(k[:], key[:])
	copy(k[16:], key[:9])

	return k
}
