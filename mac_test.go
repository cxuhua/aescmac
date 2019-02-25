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

func TestValue413DNA(t *testing.T){
	key := make([]byte,16)
	ret := VaildNTAG413DNA(key,"041E19A2FB6180","00000E","03745F4EDBC3875A")
	log.Println(ret)
}