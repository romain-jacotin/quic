package crypto

import "github.com/romain-jacotin/quic/protocol"
import "errors"

type AEAD_AES128GCM12 struct {
	noncePrefix []byte
	key         []byte
}

// NewAEAD_AES128GCM12 returns a *AEAD_AES128GCM12 that implements crypto.AEAD interface
func NewAEAD_AES128GCM12() AEAD {
	return new(AEAD_AES128GCM12)
}

// SetKey
func (this *AEAD_AES128GCM12) SetKey(key []byte) error {
	if len(key) < 16 {
		return errors.New("AEAD_AES128GCM12.SetKey : AES_128_GCM_12 requires 128-bit key")
	}
	this.key = make([]byte, 16)
	copy(this.key, key)
	return nil
}

// SetNoncePrefix fixes the nonce prefix used for the AEAD_AES_128_GCM_12.
//
// QUIC uses nonce prefix + QUIC packet sequence as nonce, so nonce prefix must be 4 bytes at minimum.
func (this *AEAD_AES128GCM12) SetNoncePrefix(nonceprefix []byte) error {
	l := len(nonceprefix)
	if l < 4 {
		return errors.New("AEAD_AES128GCM12.SetKey : QUIC requires 32-bit nonce prefix")
	}
	this.noncePrefix = make([]byte, 4)
	copy(this.noncePrefix, nonceprefix)
	return nil
}

// Open
func (this *AEAD_AES128GCM12) Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) (bytescount int, err error) {
	return
}

// Seal
func (this *AEAD_AES128GCM12) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) (bytescount int, err error) {
	return
}
