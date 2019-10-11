package aescmac

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
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
//TT&mac=
func VaildNTAGDNAWithTT(key []byte,uid,ctr,mac ,tts string) bool {
	return VaildNTAGDNA(key,uid,ctr,mac,[]byte(tts+"&mac="))
}

type PiccHeader []byte

func(h PiccHeader)EnableMirrUID() bool {
	return (h[0] & 0b10000000) != 0
}

func(h PiccHeader)EnableMirrCtr() bool {
	return (h[0] & 0b01000000) != 0
}

func(h PiccHeader)UIDLength() int {
	return int(h[0] &0b111)
}

func(h PiccHeader)GetUID() []byte {
	if h.EnableMirrUID() {
		return h[1:h.UIDLength()+1]
	}
	return nil
}

func(h PiccHeader)GetCtr() []byte {
	if !h.EnableMirrCtr() {
		return nil
	}
	off := 1
	if h.EnableMirrUID() {
		off += 7
	}

	return h[off:off + 3]
}

//支持ntag424dna
func DecryptPICCData(key []byte,input string) PiccHeader {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ib ,err:= hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
	data := make([]byte, len(ib))
	blockMode.CryptBlocks(data, ib)
	return data
}

//支持ntag424dna
func DecryptEncData(key []byte,uid,ctr,input string) []byte {
	if(len(key) != 16){
		panic(errors.New("key len error"))
	}
	if(len(uid) != 14){
		panic(errors.New("uid len error"))
	}
	if(len(ctr) != 6){
		panic(errors.New("ctr len error"))
	}
	if(len(input) % 16 != 0){
		panic(errors.New("input len error"))
	}
	uidb ,err:= hex.DecodeString(uid)
	if err != nil {
		panic(err)
	}
	ctrb,err := hex.DecodeString(ctr)
	if err != nil {
		panic(err)
	}
	inputb,err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	//get read key
	enciv := []byte{}
	enciv = append(enciv,0xC3,0x3C,0x00,0x01,0x00,0x80)
	enciv = append(enciv,uidb...)
	enciv = append(enciv,ctrb[2],ctrb[1],ctrb[0])
	enckey := CMAC(key,enciv)

	block, err := aes.NewCipher(enckey)
	if err != nil {
		panic(err)
	}
	//get iv
	ivb := []byte{ctrb[2],ctrb[1],ctrb[0],0,0,0,0,0,0,0,0,0,0,0,0,0}
	blockMode := cipher.NewCBCEncrypter(block, []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
	iv := make([]byte, len(ivb))
	blockMode.CryptBlocks(iv, ivb)
	//get data
	data := make([]byte, len(inputb))
	blockMode = cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(data, inputb)
	return data
}

//支持ntag413dna ntag424dna
func VaildNTAGDNA(key []byte,uid,ctr,mac string,input []byte) bool {
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
	maciv := []byte{}
	maciv = append(maciv,0x3C,0xC3,0x00,0x01,0x00,0x80)
	maciv = append(maciv,uidb...)
	maciv = append(maciv,ctrb[2],ctrb[1],ctrb[0])
	mackey := CMAC(key,maciv)
	macv := CMAC8(mackey,input)
	return bytes.Equal(macv,macb)
}