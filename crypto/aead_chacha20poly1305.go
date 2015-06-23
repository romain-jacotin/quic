package crypto

import "github.com/romain-jacotin/quic/protocol"
import "encoding/binary"
import "errors"
import "fmt"

type AEAD_ChaCha20Poly1305 struct {
	cipher *ChaCha20Cipher
	hasher *Poly1305
}

// NewAEAD_ChaCha20Poly1305 returns a *AEAD_ChaCha20Poly1305 that implements AEAD interface
func NewAEAD_ChaCha20Poly1305(key, nonceprefix []byte) (AEAD, error) {
	var buf [64]byte
	var err error

	if len(key) < 32 {
		return nil, errors.New("NewAEAD_ChaCha20Poly1305 : AEAD_CHACHA20_POLY1305_12 requires 256-bit key")
	}
	if len(nonceprefix) < 4 {
		return nil, errors.New("NewAEAD_ChaCha20Poly1305 : QUIC requires 32-bit nonce prefix")
	}

	aead := new(AEAD_ChaCha20Poly1305)
	if aead.cipher, err = NewChaCha20Cipher(key, nonceprefix, 0); err != nil {
		return nil, errors.New("NewAEAD_ChaCha20Poly1305 : error when calling NewChaCha20Cipher")
	}
	aead.cipher.GetNextKeystream(&buf)
	if aead.hasher, err = NewPoly1305(buf[0:32]); err != nil {
		return nil, errors.New("NewAEAD_ChaCha20Poly1305 : error when calling NewPoly1305")
	}
	return aead, nil
}

// Open
func (this *AEAD_ChaCha20Poly1305) Open(seqnum protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) (bytescount int, err error) {
	// Authenticate: check the MAC
	l := len(ciphertext) - 12
	if l < 0 {
		err = errors.New("AEAD_ChaCha20Poly1305.Open : Message Authentication Code can't be less than 12 bytes")
		return
	}
	low := binary.LittleEndian.Uint64(ciphertext[l:])
	high := binary.LittleEndian.Uint32(ciphertext[l+8:])
	testhigh, testlow := this.hasher.ComputeAeadMAC(aad, ciphertext[:l])
	if (low != testlow) || (high != uint32(testhigh&0xffffffff)) {
		err = fmt.Errorf("AEAD_ChaCha20Poly1305.Open : invalid Message Authentication Code verification %x:%x versus %x:%x", low, high, testlow, testhigh)
		return
	}
	// Then decrypt
	this.cipher.SetPacketSequenceNumber(seqnum)
	bytescount, err = this.cipher.Decrypt(plaintext, ciphertext[:l])
	return
}

// Seal
func (this *AEAD_ChaCha20Poly1305) Seal(seqnum protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) (bytescount int, err error) {
	// Encrypt
	l := len(plaintext)
	if len(ciphertext) < (l + 12) {
		err = errors.New("AEAD_ChaCha20Poly1305.Seal : ciphertext can't be less than plaintext + 12 bytes")
		return
	}
	this.cipher.SetPacketSequenceNumber(seqnum)
	if bytescount, err = this.cipher.Encrypt(ciphertext, plaintext); err != nil {
		return
	}
	if bytescount != l {
		err = errors.New("AEAD_ChaCha20Poly1305.Seal : truncated encryption by Chacha20Cipher.Encrypt") // Impossible normally
	}
	// Then MAC
	high, low := this.hasher.ComputeAeadMAC(aad, ciphertext[:l])
	binary.LittleEndian.PutUint64(ciphertext[l:], low)
	binary.LittleEndian.PutUint32(ciphertext[l+8:], uint32(high))
	bytescount += 12
	return
}
