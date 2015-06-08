package crypto

type p256 struct {
	publicKey  []byte
	privateKey []byte
}

// NewECDH_P256 returns an Elliptic Curve Diffie-Hellman P-256 KeyExchange algorithm.
func NewECDH_P256() (error, KeyExchange) {
	return nil, &p256{}
}

// GetPublicKey generates local private/public keys pair and returns the local public key that should be sent to the remote host.
func (this *p256) GetPublicKey() []byte {
	return nil
}

// ComputeSharedKey computes and returns the shared key based on the local private key and the remote public key described in input.
func (this *p256) ComputeSharedKey([]byte) []byte {
	return nil
}
