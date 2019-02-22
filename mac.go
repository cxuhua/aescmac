package aescmac

import "unsafe"
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