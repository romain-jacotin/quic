package crypto

import "testing"

func Test_FNV1A_64(t *testing.T) {
	/*
	   https://tools.ietf.org/html/draft-eastlake-fnv-09

	   FNV1A Test Vectors :

	    String       FNV32       FNV64
	       ""        0x811c9dc5  0xcbf29ce484222325
	       "a"       0xe40c292c  0xaf63dc4c8601ec8c
	       "foobar"  0xbf9cf968  0x85944171f73967e8
	*/
	if ComputeHashFNV1A_64(nil) != 0xcbf29ce484222325 {
		t.Error("HashFNV1A_64: bad hash")
	}

	if ComputeHashFNV1A_64([]byte("a")) != 0xaf63dc4c8601ec8c {
		t.Error("HashFNV1A_64: bad hash")
	}

	if ComputeHashFNV1A_64([]byte("foobar")) != 0x85944171f73967e8 {
		t.Error("HashFNV1A_64: bad hash")
	}
}

func Test_FNV1A_128(t *testing.T) {
	/*
		http://find.fnvhash.com/

		FNV1A Test Vectors :

		String      FNV128
		   ""       0x6c62272e07bb014262b821756295c58d
		   "a"      0xd228cb696f1a8caf78912b704e4a8964
		   "foobar" 0x343e1662793c64bf6f0d3597ba446f18
	*/
	if h, l := ComputeHashFNV1A_128(nil); (h != 0x6c62272e07bb0142) && (l != 0x62b821756295c58d) {
		t.Errorf("HashFNV1A_128: bad hash %x %x", h, l)
	}

	if h, l := ComputeHashFNV1A_128([]byte("a")); (h != 0xd228cb696f1a8caf) && (l != 0x78912b704e4a8964) {
		t.Error("HashFNV1A_128: bad hash")
	}

	if h, l := ComputeHashFNV1A_128([]byte("foobar")); (h != 0x343e1662793c64bf) && (l != 0x6f0d3597ba446f18) {
		t.Error("HashFNV1A_128: bad hash")
	}
}

func Test_ComputeAeadHashFNV1A_128(t *testing.T) {
	h, l := ComputeHashFNV1A_128([]byte("Carpe Diem"))
	h_aead, l_aead := ComputeAeadHashFNV1A_128([]byte("Carpe "), []byte("Diem"))
	if h != h_aead || l != l_aead {
		t.Error("ComputeAeadHashFNV1A_128: bad hash")
	}
}
