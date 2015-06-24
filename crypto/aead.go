package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD interface {
	// Open
	Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) (bytescount int, err error)
	// Seal
	Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) (bytescount int, err error)
	// GetMacSize
	GetMacSize() int
}
