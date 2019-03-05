package aescmac

import (
	"encoding/hex"
	"testing"
)

func TestAesMac(t *testing.T){
	key := make([]byte,16)
	data:= []byte{1}
	mac := CMAC8(key,data)
	if hex.EncodeToString(mac) != "82955c99a3709634" {
		t.Error("CMAC8 error")
	}
}

//uid=041E19A2FB6180&ctr=00000E&mac=03745F4EDBC3875A
func TestValue413DNA(t *testing.T){
	key := make([]byte,16)
	ret := VaildNTAGDNA(key,"041E19A2FB6180","00000E","03745F4EDBC3875A",nil)
	if !ret {
		t.Error("Test imacoff == macoff error")
	}
}
//http://www.xxx.com/?uid=042410A2FB6180&ctr=000002&mac=DCF9F78B197F6E64 imacoff=5
func TestValue413DNAWithInput(t *testing.T) {
	key := make([]byte,16)
	ret := VaildNTAGDNA(key,"042410A2FB6180","000002","DCF9F78B197F6E64",[]byte("xxx.com/?uid=042410A2FB6180&ctr=000002&mac="))
	if !ret {
		t.Error("Test imacoff != macoff error")
	}
}
//http://www.xxx.com/?uid=047D1432AA6180&ctr=000006&tt=OO&mac=023E3F6F08351B31
func TestValue424DNA(t *testing.T){
	key := make([]byte,16)
	ret := VaildNTAGDNA(key,"047D1432AA6180","000006","023E3F6F08351B31",nil)
	if !ret {
		t.Error("Test imacoff == macoff error")
	}
}
//http://www.xxx.com/?uid=047D1432AA6180&ctr=000008&tt=OO&mac=4129C412374AB665
//C闭合状态O打开状态I初始状态
func TestValue424DNAWithInput(t *testing.T){
	key := make([]byte,16)
	ret := VaildNTAGDNA(key,"047D1432AA6180","000008","4129C412374AB665",[]byte("xxx.com/?uid=047D1432AA6180&ctr=000008&tt=OO&mac="))
	if !ret {
		t.Error("Test imacoff == macoff error")
	}
}
//https://trace.rfidtrace.com/h5/047A1732AA6180?ctr=00000C&tts=CC&mac=70F6B12FF1D634A0
//C闭合状态O打开状态I初始状态
func TestValue424DNAWithCCInput(t *testing.T){
	key := []byte("JvQcZnKs2bI3RDO5")
	ret := VaildNTAGDNAWithTT(key,"047A1732AA6180","00000C","70F6B12FF1D634A0","CC")
	if !ret {
		t.Error("Test imacoff == macoff error")
	}
}