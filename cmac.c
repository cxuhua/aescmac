#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include "cmac.h"

void cmacgo(const unsigned char *key,const unsigned char *ptr,int size,unsigned char *mac)
{
    cmac_ctx ctx;
    cmac_init(&ctx,key,AES_BLOCK_SIZE);
    cmac_encrypt(&ctx, ptr, size, mac);
}

static void cmac_xor (unsigned char *out, const unsigned char *in) {
  
  int i;
  
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    out[i] ^= in[i];
  }
  
}

static void cmac_pad (unsigned char *buf, int len) {

  int i;
  
  for ( i = len; i < AES_BLOCK_SIZE; i++ ) {
    buf[i] = (i == len) ? 0x80 : 0x00;
  }
  
}

static unsigned char cmac_left_shift(unsigned char *out, unsigned char *in, unsigned char *overflow) {
  int i;
  for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    out[i] = (in[i] << 1) | (*overflow);
    (*overflow) = CMAC_MSB(&in[i]);
  }
}

static void cmac_generate_sub_key(unsigned char *out, unsigned char *in) {
  
  int i; unsigned char overflow = 0;

  cmac_left_shift(out, in, &overflow);
  
  if (overflow) {
    out[AES_BLOCK_SIZE-1] ^= 0x87;
  }
  
  return;
}


static void dump(const unsigned char *v,int size)
{
    for(int i=0;i<size;i++){
        printf("%.2X",v[i]);
    }
    printf("\n");
}

void cmac_encrypt (cmac_ctx *ctx, const unsigned char *msg, int msg_len, unsigned char *ct) {
  int n, i, k;
  unsigned char iv[AES_BLOCK_SIZE]={0};
  unsigned char M[AES_BLOCK_SIZE];
  memset(M, 0, AES_BLOCK_SIZE);
  n = (msg_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE ;
  k = (msg_len % AES_BLOCK_SIZE);
  int asiz = n * AES_BLOCK_SIZE;
  unsigned char *buf = NULL;
  if(msg_len == 0){
    buf = ( unsigned char  *)malloc(AES_BLOCK_SIZE);
    memset(buf, 0, AES_BLOCK_SIZE);
    buf[0] = 0x80;
    for (i = 0; i < AES_BLOCK_SIZE; i++){
        buf[i] ^= ctx->K2[i];
    }
    AES_cbc_encrypt(buf, buf, AES_BLOCK_SIZE , &ctx->cmac_key, iv, AES_ENCRYPT);
    memcpy(ct,iv,AES_BLOCK_SIZE);
    free(buf);
    return;
  }
    buf = (unsigned char *)malloc(asiz);
    memset(buf,0,asiz);
    memcpy(buf,msg,msg_len);
  if(k == 0){
    int len = asiz - AES_BLOCK_SIZE;
    for (i = 0; i < AES_BLOCK_SIZE; i++){
        buf[len + i] ^= ctx->K1[i];
    }
  }else{
    buf[msg_len++] = 0x80;
    int len = asiz - AES_BLOCK_SIZE;
    for (i = 0; i < AES_BLOCK_SIZE; i++){
        buf[len + i] ^= ctx->K2[i];
    }
  }
 AES_cbc_encrypt(buf, buf, AES_BLOCK_SIZE *n, &ctx->cmac_key, iv, AES_ENCRYPT);
 memcpy(ct,iv,AES_BLOCK_SIZE);
 free(buf);
}

int cmac_init (cmac_ctx *ctx, const unsigned char *key, int key_len)
{

  unsigned char iv[AES_BLOCK_SIZE]={0};
  unsigned char L[AES_BLOCK_SIZE];
  
  memset((char *)ctx, 0, sizeof(cmac_ctx));
  
  AES_set_encrypt_key(key, 128, &ctx->cmac_key);

  AES_cbc_encrypt(zero_block, L, AES_BLOCK_SIZE, &ctx->cmac_key, iv, AES_ENCRYPT);
  
  cmac_generate_sub_key(ctx->K1, L);
  cmac_generate_sub_key(ctx->K2, ctx->K1);

  return 1;
  
}