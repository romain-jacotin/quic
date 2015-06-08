package crypto

import "crypto/rand"
import "golang.org/x/crypto/curve25519"
import "io"
import "errors"

type c255 struct {
	publicKey  [32]byte
	privateKey [32]byte
}

// NewECDH_Curve25519 returns an Elliptic Curve Diffie-Hellman Curve25519 KeyExchange algorithm.
func NewECDH_Curve25519() (err error, keyexchange KeyExchange) {
	c := new(c255)
	_, err = io.ReadFull(rand.Reader, c.privateKey[:])
	if err != nil {
		return
	}
	curve25519.ScalarBaseMult(&c.publicKey, &c.privateKey)
	curve25519.ScalarBaseMult(&c.publicKey, &c.privateKey)
	return nil, c
}

// GetPublicKey generates local private/public keys pair and returns the local public key that should be sent to the remote host.
func (this *c255) GetPublicKey() []byte {
	return this.publicKey[:]
}

// ComputeSharedKey computes and returns the shared key based on the local private key and the remote public key.
func (this *c255) ComputeSharedKey(remotePublicKey []byte) (error, []byte) {
	var remote [32]byte
	if len(remotePublicKey) != 32 {
		return errors.New("ECDH : invalid Curve25519 KeyExchange"), nil
	}
	sharedKey := new([32]byte)
	copy(remote[:], remotePublicKey)
	curve25519.ScalarMult(sharedKey, &this.privateKey, &remote)
	return nil, sharedKey[:]
}
