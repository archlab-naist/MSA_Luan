/*********************************************************************
* Filename:   sha512.h
* Author:     HoaiLuan
* Reference: Brad Conte (brad AT bradconte.com)
*********************************************************************/

#ifndef SHA512_H
#define SHA512_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
/**************************** DATA TYPES ****************************/
typedef uint64_t  WORD;            

typedef struct {
	WORD data[16];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA512_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const WORD data[], WORD hash[]);

#endif   
