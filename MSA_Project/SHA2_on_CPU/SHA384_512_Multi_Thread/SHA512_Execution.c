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
#include <pthread.h>
#define NUM_THREADS 10

#define N 1000000000
struct thread_data
{
  int i;
  int j;
};

int finish[NUM_THREADS];

void *myThreadFun(void *threadid) 
{ 
	WORD buf1[8];
	SHA512_CTX ctx1;
    // Store the value argument passed to this thread 
    struct thread_data *data = threadid;
	int i;
	//printf("%d\n",(data->i)*(N/NUM_THREADS));
	//printf("%d\n",(data->i+1)*(N/NUM_THREADS));
	for(i = (data->i)*(N/NUM_THREADS); i < (data->i+1)*(N/NUM_THREADS); i++){ 
		WORD Word1[16] = {i, i+1, 0x8000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000040};
		sha512_init(&ctx1);
		sha512_update(&ctx1, Word1, buf1);
	}

} 

int main(void)
{
	int i;
	srand(time(NULL)); 
	pthread_t threads[NUM_THREADS];
	for (i = 0; i < NUM_THREADS ; i ++){
		struct thread_data *data = (struct thread_data *) malloc(sizeof(struct thread_data));
		data->i = i;
		pthread_create(&threads[i], NULL, myThreadFun,data);
	}		
	pthread_exit(NULL);
	return 0;
}