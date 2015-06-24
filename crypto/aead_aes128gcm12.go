package crypto

import "github.com/romain-jacotin/quic/protocol"
import "crypto/aes"
import "crypto/cipher"
import "errors"
import "fmt"

type AEAD_AES128GCM12 struct {
	cipher cipher.Block
	h0     uint64
	h1     uint64
	ghash  [16]byte
	y      [16]byte
	nonce  [16]byte
}

// NewAEAD_AES128GCM12 returns a *AEAD_AES128GCM12 that implements crypto.AEAD interface
func NewAEAD_AES128GCM12(key, nonce []byte) (AEAD, error) {
	var err error
	var i uint

	if len(key) < 16 {
		return nil, errors.New("NewAEAD_AES128GCM12 : key must be 16 bytes at minimum")
	}
	if len(nonce) < 12 {
		return nil, errors.New("NewAEAD_AES128GCM12 : key must be 12 bytes at minimum")
	}
	aead := new(AEAD_AES128GCM12)
	if aead.cipher, err = aes.NewCipher(key[:16]); err != nil {
		return nil, err
	}
	aead.cipher.Encrypt(aead.y[:], aead.nonce[:])
	for i = 0; i < 8; i++ {
		aead.h1 += uint64(aead.y[i]) << (56 - (i << 3))
		aead.h0 += uint64(aead.y[i+8]) << (56 - (i << 3))
	}
	for i = 0; i < 4; i++ {
		aead.nonce[i] = nonce[i]
	}
	return aead, nil
}

// Open
func (this *AEAD_AES128GCM12) Open(seqnum protocol.QuicPacketSequenceNumber, plaintext, aad, ciphertext []byte) (bytescount int, err error) {
	var c, i, j, k, n, modn uint32

	l := len(ciphertext) - 12
	if l < 0 {
		err = errors.New("AEAD_AES128GCM12.Open : Message Authentication Code can't be less than 12 bytes")
		return
	}
	if len(plaintext) < l {
		err = errors.New("AEAD_AES128GCM12.Open : plaintext must same have length as ciphertext less 12 bytes at minimum")
		return
	}

	// Authenticate: check the MAC

	// Compute nonce prefix
	for i = 0; i < 8; i++ {
		this.nonce[4+i] = byte(seqnum >> (i << 3))
	}
	this.nonce[12] = 0
	this.nonce[13] = 0
	this.nonce[14] = 0
	this.nonce[15] = 1
	c = 1
	this.computeGHash(aad, ciphertext[:l])
	// Compute Y0
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y[:], this.nonce[:])
	// Compute and compare GHASH^E(K,Y0)
	k = uint32(l)
	for i = 0; i < 12; i++ {
		this.ghash[i] ^= this.y[i]
		if ciphertext[k] != this.ghash[i] {
			err = fmt.Errorf("AEAD_AEAD_AES128GCM12.Open : invalid Message Authentication Code verification %x versus %x", ciphertext[l:], this.ghash[:12])
			return
		}
		k++
	}

	// Then decrypt
	n = uint32(l)
	modn = n & 0xf
	n >>= 4
	for i = 0; i < n; i++ {
		// Compute Yi = incr(Yi−1)
		c++
		this.nonce[15] = byte(c & 0xff)
		this.nonce[14] = byte((c >> 8) & 0xff)
		this.nonce[13] = byte((c >> 16) & 0xff)
		this.nonce[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y[:], this.nonce[:])
		// Compute Ci = Pi xor E(K,Yi)
		k = i << 4
		for j = 0; j < 16; j++ {
			plaintext[k] = ciphertext[k] ^ this.y[j]
			k++
		}
	}
	if modn > 0 {
		// Compute Yn = incr(Yn−1)
		c++
		this.nonce[15] = byte(c & 0xff)
		this.nonce[14] = byte((c >> 8) & 0xff)
		this.nonce[13] = byte((c >> 16) & 0xff)
		this.nonce[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y[:], this.nonce[:])
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		k = n << 4
		for j = 0; j < modn; j++ {
			plaintext[k] = ciphertext[k] ^ this.y[j]
			k++
		}
	}
	bytescount = l
	return
}

// Seal
func (this *AEAD_AES128GCM12) Seal(seqnum protocol.QuicPacketSequenceNumber, ciphertext, aad, plaintext []byte) (bytescount int, err error) {
	var c, i, j, n, modn uint32

	l := len(plaintext)
	if len(ciphertext) < (l + 12) {
		err = errors.New("AEAD_AES128GCM12.Seal : ciphertext can't be less than plaintext + 12 bytes")
		return
	}

	// Encrypt

	for i = 0; i < 8; i++ {
		this.nonce[4+i] = byte(seqnum >> (i << 3))
	}
	c = 1
	// Encryption of the plain text
	n = uint32(len(plaintext))
	modn = n & 0xf
	n >>= 4
	for i = 0; i < n; i++ {
		// Compute Yi = incr(Yi−1)
		c++
		this.nonce[15] = byte(c & 0xff)
		this.nonce[14] = byte((c >> 8) & 0xff)
		this.nonce[13] = byte((c >> 16) & 0xff)
		this.nonce[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yi)
		this.cipher.Encrypt(this.y[:], this.nonce[:])
		// Compute Ci = Pi xor E(K,Yi)
		for j = 0; j < 16; j++ {
			ciphertext[(i<<4)+j] = plaintext[(i<<4)+j] ^ this.y[j]
		}
	}
	if modn > 0 {
		// Compute Yn = incr(Yn−1)
		c++
		this.nonce[15] = byte(c & 0xff)
		this.nonce[14] = byte((c >> 8) & 0xff)
		this.nonce[13] = byte((c >> 16) & 0xff)
		this.nonce[12] = byte((c >> 24) & 0xff)
		// Compute E(K,Yn)
		this.cipher.Encrypt(this.y[:], this.nonce[:])
		// Compute Cn = Pn xor MSBv( E(K,Yn) )
		for j = 0; j < modn; j++ {
			ciphertext[(n<<4)+j] = plaintext[(n<<4)+j] ^ this.y[j]
		}
	}

	// Then MAC

	this.computeGHash(aad, ciphertext[:l])
	// Compute Y0
	this.nonce[12] = 0
	this.nonce[13] = 0
	this.nonce[14] = 0
	this.nonce[15] = 1
	// Compute E(K,Y0)
	this.cipher.Encrypt(this.y[:], this.nonce[:])
	for i := 0; i < 12; i++ {
		ciphertext[l+i] = this.ghash[i] ^ this.y[i]
	}
	bytescount = l + 12
	return
}

// GetMacSize
func (this *AEAD_AES128GCM12) GetMacSize() int {
	return 12
}
