package musigBls

import (
	"github.com/Nik-U/pbc"
	"testing"
)


func testPairing(t *testing.T) *pbc.Pairing {
	// Generated with pbc_param_init_a_gen(p, 10, 32);
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		t.Fatalf("Could not instantiate test pairing")
	}
	return pairing
}

func logElement(e *pbc.Element, name string, t *testing.T) {
	t.Logf("%s = %s\n", name, e)
}

func TestBLS(t *testing.T) {
	pairing := testPairing(t)

	g := pairing.NewG2()
	publicKey := pairing.NewG2()
	h := pairing.NewG1()
	sig := pairing.NewG1()
	temp1 := pairing.NewGT()
	temp2 := pairing.NewGT()
	secretKey := pairing.NewZr()

	// Generate system parameters
	g.Rand()
	logElement(g, "g", t)

	// Generate private key
	secretKey.Rand()
	logElement(secretKey, "secret key", t)

	// Compute corresponding public key
	publicKey.PowZn(g, secretKey)
	logElement(publicKey, "public key", t)

	// Generate element from a hash
	// For toy pairings, should check that pairing(g, h) != 1
	h.SetFromHash([]byte("hashofmessage"))
	logElement(h, "message hash", t)

	// h^secret_key is the signature
	// In real life: only output the first coordinate
	sig.PowZn(h, secretKey)
	logElement(sig, "signature", t)

	{
		sigBefore := sig.NewFieldElement().Set(sig)
		data := sig.CompressedBytes()
		sig.SetCompressedBytes(data)
		logElement(sig, "decompressed signature", t)
		if !sig.Equals(sigBefore) {
			t.Fatal("decompressed signature does not match")
		}
	}

	// Verification part 1
	temp1.Pair(sig, g)
	logElement(temp1, "f(sig,g)", t)

	// Verification part 2
	// Should match above
	temp2.Pair(h, publicKey)
	logElement(temp2, "f(hash,pubkey)", t)

	if !temp1.Equals(temp2) {
		t.Fatal("signature does not verify")
	}

	{
		data := sig.XBytes()
		sig.SetXBytes(data)

		temp1.Pair(sig, g)
		if temp1.Equals(temp2) {
			t.Log("signature verified on first try")
		} else {
			temp1.Invert(temp1)
			if temp1.Equals(temp2) {
				t.Log("signature verified on second try")
			} else {
				t.Fatal("signature does not verify")
			}
		}
	}

	// A random signature shouldn't verify
	sig.Rand()
	temp1.Pair(sig, g)
	if temp1.Equals(temp2) {
		t.Fatal("random signature verifies")
	}
}

