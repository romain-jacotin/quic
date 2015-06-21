package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD interface {
	// Open
	Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, associateddata, ciphertext, tag []byte) error
	// Seal
	Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, tag, associateddata, plaintext []byte) error
}
