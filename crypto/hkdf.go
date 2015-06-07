package crypto

import "crypto/hmac"
import "crypto/sha256"

// HKDF contains the resulting AEAD Key and Initialization Vector for QUIC Client and QUIC Server
type HKDF struct {
	clientWriteKey   []byte
	clientWriteNonce []byte
	serverWriteKey   []byte
	serverWriteNonce []byte
}

// NewHKDF is a factory HKDF that computes the output keys materials for AEAD by using HMAC-based Key Derivation Function using SHA-256 as Hash function.
//
// An error is return and a pointer to an HKDF structure that contains the resulting Output Keying Material.
func NewHKDF(salt, ikm, info []byte, keysize, noncesize int) (error, *HKDF) {
	var t []byte
	var okm []byte
	var counter byte
	var i int

	counter = 1
	need := 2*keysize + 2*noncesize
	n := need / 32
	m := need % 32

	if salt == nil {
		salt = make([]byte, 32) // SHA-256 requires 32-bytes Key
	}

	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	// We need 32 + 32 + 32 + 32 bytes of Output Keying Material
	expand := hmac.New(sha256.New, prk)

	// Fill the okm buffer
	for i = 0; i < n; i++ {
		expand.Reset()
		expand.Write(t)
		expand.Write(info)
		expand.Write([]byte{counter})
		t = expand.Sum(nil)
		counter++
		copy(okm[i*32:], t)
	}
	if m > 0 {
		expand.Reset()
		expand.Write(t)
		expand.Write(info)
		expand.Write([]byte{counter})
		t = expand.Sum(nil)
		copy(okm[i*32:], t[0:m])
	}

	return nil, &HKDF{
		clientWriteKey:   okm[0:keysize],
		clientWriteNonce: okm[keysize : keysize+noncesize],
		serverWriteKey:   okm[keysize+noncesize : 2*keysize+noncesize],
		serverWriteNonce: okm[2*keysize+noncesize : 2*keysize+2*noncesize]}
}

// GetClientWriteKey returns the Key used by the QUIC Client for AEAD when sending packet.
func (this *HKDF) GetClientWriteKey() []byte {
	return this.clientWriteKey
}

// GetClientWriteNonce returns the Nonce used by the QUIC Client for AEAD when sending packet.
func (this *HKDF) GetClientWriteNonce() []byte {
	return this.clientWriteNonce
}

// GetServerWriteKey returns the Key used by the QUIC Server for AEAD when sending packet.
func (this *HKDF) GetServerWriteKey() []byte {
	return this.serverWriteKey
}

// GetServerWriteNonce returns the Nonce used by the QUIC Server for AEAD when sending packet.
func (this *HKDF) GetServerWriteNonce() []byte {
	return this.serverWriteNonce
}
