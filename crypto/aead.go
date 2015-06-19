package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD_Reader interface {
	// Open
	Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, associateddata, ciphertext, tag []byte) error
}

type AEAD_Writer interface {
	// Seal
	Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, tag, associateddata, plaintext []byte) error
}

type AEAD interface {
	AEAD_Reader
	AEAD_Writer
}
