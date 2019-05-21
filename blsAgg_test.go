package musigBls

import (
	"github.com/Nik-U/pbc"
	"testing"
)

func TestBlsAgg(t *testing.T)  {
	pairing,err := GenTestPairing()
	if err!=nil{
		t.Fatal(err)
	}
	g := pairing.NewG2()
	g.Rand()
	pkg := PKG{
		g:g,
		pairing:pairing,
	}
	keys := []*Key{pkg.GenKey(),pkg.GenKey(),pkg.GenKey()}
	var pks []*pbc.Element
	for _,key := range keys{
		pks = append(pks, key.publickey)
	}
	msgs :=[][]byte{[]byte("12llgas3"),[]byte("24fasd351"),[]byte("safasfd")}
	var sigs []*pbc.Element
	for i,msg := range msgs{
		sigs = append(sigs,Sign(pairing,pks,keys[i],msg))
	}
	aggSig,err := AggSig(pairing,sigs)
	if err!=nil{
		t.Fatal(err)
	}
	result,err := AggVerify(pairing,aggSig,pks,g,msgs)
	t.Logf("%v",result)
	if err!=nil{
		t.Log(err)
	}

}
func BenchmarkAggVerify(b *testing.B) {
	pairing,_ := GenTestPairing()
	g := pairing.NewG2()
	g.Rand()
	pkg := PKG{
		g:g,
		pairing:pairing,
	}
	keys := []*Key{pkg.GenKey(),pkg.GenKey(),pkg.GenKey(),pkg.GenKey()}
	var pks []*pbc.Element
	for _,key := range keys{
		pks = append(pks, key.publickey)
	}
	msgs :=[][]byte{[]byte("12llgakkkhs3"),[]byte("24faskd351"),[]byte("safasfd"),[]byte("huahhfa")}
	var sigs []*pbc.Element
	for i,msg := range msgs{
		sigs = append(sigs,Sign(pairing,pks,keys[i],msg))
	}
	aggSig,_ := AggSig(pairing,sigs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		 AggVerify(pairing, aggSig, pks, g, msgs)
	}
}