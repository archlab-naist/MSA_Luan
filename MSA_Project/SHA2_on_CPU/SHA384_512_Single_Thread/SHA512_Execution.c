/*********************************************************************
* Filename:   sha256.c
* Author:     HoaiLuan
* Reference: Brad Conte (brad AT bradconte.com)
*********************************************************************/

///*************************** HEADER FILES ***************************/


#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <time.h>
#include "sha512.h"
#include "sha512.c"

#define N 100000000

int main(void)
{
	WORD buf1[8];
	SHA512_CTX ctx1;
	int i;
	
	WORD Word1[16] = {0x6162638000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000018};

	clock_t start, end;
	double cpu_time_used;

	start = clock();
	for (i = 0; i < N ; i ++){
	WORD Word1[16] = {i, i+1, 0x8000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000040};
	sha512_init(&ctx1);
	sha512_update(&ctx1, Word1, buf1);
	}
	end = clock();

	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("time used: %f second \n",cpu_time_used);
	return 0;
}