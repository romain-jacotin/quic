package crypto

type curve25519 struct {
	publicKey  []byte
	privateKey []byte
}

// NewECDH_Curve25519 returns an Elliptic Curve Diffie-Hellman Curve25519 KeyExchange algorithm.
func NewECDH_Curve25519() (error, KeyExchange) {
	return nil, &curve25519{}
}

// GetPublicKey generates local private/public keys pair and returns the local public key that should be sent to the remote host.
func (this *curve25519) GetPublicKey() []byte {
	return nil
}

// ComputeSharedKey computes and returns the shared key based on the local private key and the remote public key described in input.
func (this *curve25519) ComputeSharedKey([]byte) (error, []byte) {
	return nil, nil
}
