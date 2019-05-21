package musigBls
//
//import "github.com/Nik-U/pbc"
//
//func Sign(par *pbc.Pairing,pks []*PublicKey,sk *PrivateKey, m []byte){
//
//}
//func Verify(par *pbc.Pairing,apk PublicKey,m []byte, sig []byte )  {
//
//}
//func Aggsig()  {
//
//}
//func AggPk(par *pbc.Pairing, pks []*PublicKey) (*pbc.Element,error) {
//	apk:=par.NewG2()
//	for index,pk:=range pks{
//		ai,err :=Getai(par,pk,pks)
//		if err!=nil {
//			return nil,err
//		}
//		temp:=
//	}
//}
//func Getai(par *pbc.Pairing,pk *PublicKey,pks []*PublicKey)(*pbc.Element,error) {
//	l,err := hashpks(pks)
//	if err!=nil {
//		return nil,err
//	}
//	plaintext:= append(pk.SerializeCompressed(),l...)
//	ai := par.NewZr()
//	return ai.SetFromHash(plaintext),nil
//}
//func HashMsg(par *pbc.Pairing, m []byte)*pbc.Element{
//	hm := par.NewG1()
//	return hm.SetFromHash(m)
//}
