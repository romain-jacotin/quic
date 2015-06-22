package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD_NullFNV1A128 struct {
}

// NewAEAD_FNV1A128 returns a *AEAD_NullFNV1A128 that implements an AEAD interface with null encryption and FNV1A-128 hash
func NewAEAD_FNV1A128() AEAD {
	return new(AEAD_NullFNV1A128)
}

// Open
func (this *AEAD_NullFNV1A128) Open(sequencenumber protocol.QuicPacketSequenceNumber, cleartext, aad, ciphertext []byte) error {
	return nil
}

// Seal
func (this *AEAD_NullFNV1A128) Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, cleartext []byte) error {
	return nil
}
