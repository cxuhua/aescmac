package aescmac

import (
	"bytes"
	"encoding/hex"
	"github.com/pkg/errors"
	"unsafe"
)
/*
void cmacgo(const unsigned char *key,const unsigned char *ptr,int size,unsigned char *mac);
*/
import "C"

func CMAC(key []byte,data []byte)[]byte {
	mac := make([]byte,16)
	keyptr := (*C.uchar)(unsafe.Pointer(&key[0]))
	macptr := (*C.uchar)(unsafe.Pointer(&mac[0]))
	if len(data) > 0 {
		datptr := (*C.uchar)(unsafe.Pointer(&data[0]))
		datlen := C.int(len(data))
		C.cmacgo(keyptr, datptr, datlen, macptr)
	}else{
		C.cmacgo(keyptr, nil, 0, macptr)
	}
	return mac
}

func CMAC8(key []byte,data []byte)[]byte {
	mac := CMAC(key,data);
	ret := make([]byte,8)
	for i:=0;i<16;i++ {
		if i % 2  != 0 {
			ret[i/2] = mac[i]
		}
	}
	return ret
}

func VaildNTAG413DNA(key []byte,uid,ctr,mac string,input string) bool {
	if(len(key) != 16){
		panic(errors.New("key len error"))
	}
	if(len(uid) != 14){
		panic(errors.New("uid len error"))
	}
	if(len(ctr) != 6){
		panic(errors.New("ctr len error"))
	}
	if(len(mac) != 16){
		panic(errors.New("mac len error"))
	}
	uidb ,err:= hex.DecodeString(uid)
	if err != nil {
		panic(err)
	}
	ctrb,err := hex.DecodeString(ctr)
	if err != nil {
		panic(err)
	}
	macb,err := hex.DecodeString(mac)
	if err != nil {
		panic(err)
	}
	kssv := []byte{}
	kssv = append(kssv,0x3C,0xC3,0x00,0x01,0x00,0x80)
	kssv = append(kssv,uidb...)
	kssv = append(kssv,ctrb[2],ctrb[1],ctrb[0])
	kss := CMAC(key,kssv)
	var ib []byte = nil
	if len(input) > 0 {
		ib = []byte(input)
	}else{
		ib = nil
	}
	macv := CMAC8(kss,ib)
	return bytes.Equal(macv,macb)
}