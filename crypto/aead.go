package crypto

import "github.com/romain-jacotin/quic/protocol"

type AEAD interface {
	// SetKey
	SetKey(key []byte) error
	//SetNoncePrefix
	SetNoncePrefix(nonce []byte) error
	// Open
	Open(sequencenumber protocol.QuicPacketSequenceNumber, plaintext, associateddata, ciphertext, tag []byte) error
	// Seal
	Seal(sequencenumber protocol.QuicPacketSequenceNumber, ciphertext, tag, associateddata, plaintext []byte) error
}
