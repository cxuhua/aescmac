package aescmac

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"log"
	"strings"
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


//https://xginx.com/sign/
// 55B81FE956A0A36831B56A599B3C1783  encdata
// B3503D9BB275E5D2A5F48C3781DB1D86
// CC 573FD80B825BC20C
func TestPICCEncodeWithEncData(t *testing.T) {

	key := []byte("JvQcZnKs2bI3RDO5")


	picc := DecryptPICCData(key,"B3503D9BB275E5D2A5F48C3781DB1D86")
	log.Printf("UID=%s CTR=%s\n",hex.EncodeToString(picc.GetUID()),hex.EncodeToString(picc.GetCtr()))

	encdata := DecryptEncData(key,"047A1732AA6180","000043","55B81FE956A0A36831B56A599B3C1783")
	log.Println("ENC DATA=",hex.EncodeToString(encdata))

	x :=VaildNTAGDNA(key,"047A1732AA6180","000043","573FD80B825BC20C",[]byte("xginx.com/sign/55B81FE956A0A36831B56A599B3C1783B3503D9BB275E5D2A5F48C3781DB1D86CC"))
	log.Println(x)
	//xginx.com/sign/c7047a1732aa61804000001bd483a73aCC 95133B479DD28FFD
}

//https://xginx.com/sign/D22C3BA653E1D5A451A01D0C0E4DBF4DCC95133B479DD28FFD
func TestPICCEncode(t *testing.T) {

	key := []byte("JvQcZnKs2bI3RDO5")
	data := "D22C3BA653E1D5A451A01D0C0E4DBF4D"
	db,_:= hex.DecodeString(data)
	log.Println(key,db)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockMode := cipher.NewCBCDecrypter(block, []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
	origData := make([]byte, len(db))
	blockMode.CryptBlocks(origData, db)
	log.Println(strings.ToUpper(hex.EncodeToString(origData)))

	x :=VaildNTAGDNA(key,"047a1732aa6180","000040","95133B479DD28FFD",[]byte("xginx.com/sign/D22C3BA653E1D5A451A01D0C0E4DBF4DCC"))
	log.Println(x)
	//xginx.com/sign/c7047a1732aa61804000001bd483a73aCC 95133B479DD28FFD
}

//https://nestle.com/1?&UID=042313A2FB6180&Ctr=000014&Cmac=BF4A11AA532BF841
//http://www.xxx.com/?uid=047D1432AA6180&ctr=000006&tt=OO&mac=023E3F6F08351B31
//"https://nestle.com/1?&UID=042313A2FB6180&Ctr=00001A&Cmac=F15C93DDE97EA224"
func TestValue424DNA(t *testing.T){
	key,err := hex.DecodeString("8cef6454381e6a88841705641b6ee6f8")
	if err != nil {
		panic(err)
	}
	if len(key) != 16 {
		panic("key len error")
	}
	ret := VaildNTAGDNA(key,"042313A2FB6180","00001A","F15C93DDE97EA224",nil)
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