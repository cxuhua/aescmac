package aescmac

import (
	"encoding/hex"
	"log"
	"testing"
)

//CD 04 44 7A
func TestAesMac(t *testing.T){
	key := make([]byte,16)
	data:= []byte{1}
	mac := CMAC(key,data)
	log.Println(hex.EncodeToString(mac))
}