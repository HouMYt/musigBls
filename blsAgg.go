package musigBls

import (
	"errors"
	"github.com/Nik-U/pbc"
)

type PKG struct {
	pairing *pbc.Pairing
	g *pbc.Element
}
type Key struct {
	g *pbc.Element
	publickey *pbc.Element
	privatekey *pbc.Element
}
func GenTestPairing() (*pbc.Pairing, error){
	// Generated with pbc_param_init_a_gen(p, 10, 32);
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		return nil,err
	}
	return pairing,nil
}
func (pkg *PKG) GenKey()*Key{
	publicKey := pkg.pairing.NewG2()
	privateKey := pkg.pairing.NewZr()
	privateKey.Rand()
	publicKey.PowZn(pkg.g, privateKey)
	return &Key{
		g:pkg.g,
		privatekey:privateKey,
		publickey:publicKey,
	}

}
func Getai(pairing *pbc.Pairing,pks []*pbc.Element,pk *pbc.Element) *pbc.Element {
	a := pairing.NewZr()
	var plaintext []byte
	for _,pkt := range pks{
		plaintext = append(plaintext, pkt.Bytes()...)
	}
	plaintext = append(plaintext,pk.Bytes()...)
	return a.SetFromHash(plaintext)
}
func Sign(pairing *pbc.Pairing,pks []*pbc.Element,key *Key,msg []byte)*pbc.Element{
	sig := pairing.NewG1()
	h := pairing.NewG1()
	h.SetFromHash(msg)
	temp := pairing.NewZr()
	sig.PowZn(h,temp.Mul(Getai(pairing,pks,key.publickey),key.privatekey))
	return sig
}
func AggSig(pairing *pbc.Pairing,sigs []*pbc.Element) (*pbc.Element,error) {
	if len(sigs)==0 {
		err := errors.New("signatures must be an array with one or more elements")
		return nil,err
	}
	aggsig := sigs[0]
	for i:=1;i<len(sigs);i++{
		aggsig.Mul(aggsig,sigs[i])
	}
	return aggsig,nil
}
func AggVerify(pairing *pbc.Pairing,aggsig *pbc.Element,pks []*pbc.Element,g *pbc.Element,msg [][]byte)(bool,error) {
	if len(pks)==0 {
		err := errors.New("publicKeys must be an array with one or more elements")
		return false,err
	}
	temp1 := pairing.NewGT()
	temp1.Pair(aggsig,g)
	temp2 := pairing.NewGT()
	h0 := pairing.NewG1()
	h0.SetFromHash(msg[0])
	apk := pairing.NewG2()
	apk.PowZn(pks[0],Getai(pairing,pks,pks[0]))
	temp2.Pair(h0,apk)
	temp := pairing.NewGT()
	for i:=1;i<len(pks);i++  {
		h0.SetFromHash(msg[i])
		apk.PowZn(pks[i],Getai(pairing,pks,pks[i]))
		temp.Pair(h0,apk)
		temp2.Mul(temp2,temp)
	}
	if temp2.Equals(temp1){
		return true,nil
	}
	return false,errors.New("false")
}
