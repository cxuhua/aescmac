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