package crypto

import "testing"
import "bytes"

func TestECDH_Curve25519(test *testing.T) {
	errClient, keyExchangeClient := NewECDH_Curve25519()
	if errClient != nil {
		test.Error("ECDH_Curve25519: can't generate private/public key material at client side")
		return
	}
	errServer, keyExchangeServer := NewECDH_Curve25519()

	if errClient != nil {
		test.Error("ECDH_Curve25519: can't generate private/public key material at client side")
		return
	}

	pubKeyClient := keyExchangeClient.GetPublicKey()
	pubKeyServer := keyExchangeServer.GetPublicKey()

	errClient, sharedKeyClient := keyExchangeClient.ComputeSharedKey(pubKeyServer)
	if errClient != nil {
		test.Error("ECDH_Curve25519: can't compute shared key at client side")
		return
	}

	errServer, sharedKeyServer := keyExchangeServer.ComputeSharedKey(pubKeyClient)
	if errServer != nil {
		test.Error("ECDH_Curve25519: can't compute shared key at server side")
		return
	}

	if !bytes.Equal(sharedKeyClient, sharedKeyServer) {
		test.Error("ECDH_Curve25519: different share keys evaluated by client and server !")
		return
	}
}
