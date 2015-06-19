package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD_AES128GCM12 struct {
}

// NewAEAD_ChaCha20Poly1305 returns a *AEAD_ChaCha20 that implements AEAD interface
func NewAEAD_AES128GCM12(key, nonce []byte) AEAD {
	return new(AEAD_AES128GCM12)
}

// Open
func (this *AEAD_AES128GCM12) Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, associateddata, ciphertext, tag []byte) error {
	return nil
}

// Seal
func (this *AEAD_AES128GCM12) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, tag, associateddata, plaintext []byte) error {
	return nil
}
