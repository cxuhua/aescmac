package aescmac

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestAesMac(t *testing.T){
	key := make([]byte,16)
	data:= []byte{1}
	mac := CMAC8(key,data)
	log.Println(hex.EncodeToString(mac))
}

//uid=041E19A2FB6180&ctr=00000E&mac=03745F4EDBC3875A
func TestValue413DNA(t *testing.T){
	key := make([]byte,16)
	ret := VaildNTAG413DNA(key,"041E19A2FB6180","00000E","03745F4EDBC3875A","")
	if !ret {
		t.Error("Test imacoff == macoff error")
	}
}
//http://www.xxx.com/?uid=042410A2FB6180&ctr=000002&mac=DCF9F78B197F6E64 imacoff=5
func TestValue413DNAWithInput(t *testing.T) {
	key := make([]byte,16)
	ret := VaildNTAG413DNA(key,"042410A2FB6180","000002","DCF9F78B197F6E64","xxx.com/?uid=042410A2FB6180&ctr=000002&mac=")
	if !ret {
		t.Error("Test imacoff != macoff error")
	}
}