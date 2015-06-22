package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD interface {
	// Open
	Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) error
	// Seal
	Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) error
}
