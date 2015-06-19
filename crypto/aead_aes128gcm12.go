package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD_AES128GCM12 struct {
}

// NewAEAD_ChaCha20Poly1305 returns a *AEAD_ChaCha20 that implements AEAD interface
func NewAEAD_AES128GCM12() AEAD {
	return new(AEAD_AES128GCM12)
}

// SetKey
func (this *AEAD_AES128GCM12) SetKey(key []byte) error {
	return nil
}

//SetNoncePrefix
func (this *AEAD_AES128GCM12) SetNoncePrefix(nonce []byte) error {
	return nil
}

// Open
func (this *AEAD_AES128GCM12) Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, associateddata, ciphertext, tag []byte) error {
	return nil
}

// Seal
func (this *AEAD_AES128GCM12) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, tag, associateddata, plaintext []byte) error {
	return nil
}
