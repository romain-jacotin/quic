package crypto

// A KeyExchange is a generic way to exchange a shared key between two hosts that own private/public key pairs.
//
// Supported Key Exchange algorithm in QUIC Crypto protocol are the following:
//
//     Elliptic Curve Diffie-Hellman Curve25519: TagKEXS with value TagC255
//     Elliptic Curve Diffie-Hellman P-256:      TagKEXS with value TagP256
type KeyExchange interface {
	// GetPublicKey generates local private/public keys pair and returns the local public key that should be sent to the remote host.
	GetPublicKey() []byte
	// ComputeSharedKey computes and returns the shared key based on the local private key and the remote public key described in input.
	ComputeSharedKey([]byte) (error, []byte)
}

// NewKeyExchange is a KeyExchange factory that returns the KeyExchange algorithm corresponding to the MessageTag given in input.
//
//     TagC255 = Elliptic Curve Diffie-Hellman Curve25519
//     TagP256 = Elliptic Curve Diffie-Hellman P-256
func NewKeyExchange(kexs MessageTag) (error, KeyExchange) {
	switch kexs {
	case TagC255: // Elliptic Curve Diffie-Hellman Curve25519
		return NewECDH_Curve25519()
	case TagP256: // Elliptic Curve Diffie-Hellman P-256
		return NewECDH_P256()
	}
	return nil, nil
}
