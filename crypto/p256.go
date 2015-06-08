package crypto

import "crypto/elliptic"
import "crypto/rand"
import "math/big"
import "errors"

type p256 struct {
	curve      elliptic.Curve
	publicX    *big.Int
	publicY    *big.Int
	privateKey []byte
}

// NewECDH_P256 returns an Elliptic Curve Diffie-Hellman P-256 KeyExchange algorithm.
func NewECDH_P256() (error, KeyExchange) {
	curve := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err, nil
	}
	return nil, &p256{
		curve:      curve,
		publicX:    x,
		publicY:    y,
		privateKey: priv}
}

// GetPublicKey generates local private/public keys pair and returns the local public key that should be sent to the remote host.
func (this *p256) GetPublicKey() []byte {
	return elliptic.Marshal(this.curve, this.publicX, this.publicY)
}

// ComputeSharedKey computes and returns the shared key based on the local private key and the remote public key.
func (this *p256) ComputeSharedKey(remotePublicKey []byte) (error, []byte) {
	remotePublicX, remotePublicY := elliptic.Unmarshal(this.curve, remotePublicKey)
	if !this.curve.IsOnCurve(remotePublicX, remotePublicY) {
		return errors.New("ECDH : invalid P-256 KeyExchange"), nil
	}
	x, _ := this.curve.ScalarMult(remotePublicX, remotePublicY, this.privateKey)
	return nil, x.Bytes()
}
