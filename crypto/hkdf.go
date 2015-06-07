package crypto

// HKDF contains the resulting AEAD Key and Initialization Vector for QUIC Client and QUIC Server
type HKDF struct {
	clientWriteKey   []byte
	clientWriteNonce []byte
	serverWriteKey   []byte
	serverWriteNonce []byte
}

// ComputeHKDF computes the output keys materials for AEAD by using HMAC-based Key Derivation Function using SHA-256 as Hash function.
//
// An error is return and a pointer to an HKDF structure that contains the resulting Output Key Material.
func ComputeteHKDF(salt []byte, ikm []byte, info []byte) (error, *HKDF) {
	return nil, &HKDF{
		clientWriteKey:   nil,
		clientWriteNonce: nil,
		serverWriteKey:   nil,
		serverWriteNonce: nil}
}

// GetClientWriteKey returns the Key used by the QUIC Client for AEAD.
func (this *HKDF) GetClientWriteKey() []byte {
	return this.clientWriteKey
}

// GetClientWriteNonce returns the Nonce used by the QUIC Client for AEAD.
func (this *HKDF) GetClientWriteNonce() []byte {
	return this.clientWriteNonce
}

// GetServerWriteKey returns the Key used by the QUIC Server for AEAD.
func (this *HKDF) GetServerWriteKey() []byte {
	return this.serverWriteKey
}

// GetServerWriteNonce returns the Nonce used by the QUIC Server for AEAD.
func (this *HKDF) GetServerWriteNonce() []byte {
	return this.serverWriteNonce
}
