/*********************************************************************
* Filename:   sha224.h
* Author:     HoaiLuan
* Reference: Brad Conte (brad AT bradconte.com)
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/**************************** DATA TYPES ****************************/
typedef unsigned int  WORD;            

typedef struct {
	WORD data[16];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const WORD data[], WORD hash[]);

#endif   
