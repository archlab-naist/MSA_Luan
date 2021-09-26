// cd /home/hork/cuda-workspace/CudaSHA256/Debug/files
// time ~/Dropbox/FIIT/APS/Projekt/CpuSHA256/a.out -f ../file-list
// time ../CudaSHA256 -f ../file-list


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cuda.h>
#include "sha512.cuh"
#include <dirent.h>
#include <ctype.h>
#include <sys/time.h>


#define N 1
#define BLOCKSIZE 1
#define M 1000000/N

void string2ByteArray(char* input, BYTE* output)
{
    uint32_t loop;
    uint32_t i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

uint32_t LitToBigEndian(uint32_t x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}

__global__ void sha512_cuda(JOB ** jobs, uint32_t n, uint32_t j, OUT * outs) {

   uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t stride = blockDim.x * gridDim.x;
 
  for (uint32_t i = index; i < n; i += stride){
		SHA512_CTX ctx;
		jobs[i]->data1[0] = j*n+i;
		sha512_transform(&ctx, jobs[i]->data1, jobs[i]->digest);
		//printf("%016llx\n",jobs[i]->digest[0]);
	}
}

void pre_sha512() {
	// compy symbols
	checkCudaErrors(cudaMemcpyToSymbol(dev_k, host_k, sizeof(host_k), 0, cudaMemcpyHostToDevice));
}

void runJobs(JOB ** jobs, uint32_t n, uint32_t j, OUT * outs){
	
	uint32_t blockSize = BLOCKSIZE;
	uint32_t numBlocks = (n + blockSize - 1) / blockSize;
	sha512_cuda <<< numBlocks, blockSize >>> (jobs, n, j,outs);
}

JOB * JOB_init(const WORD data1[]) {
	JOB * j;
	checkCudaErrors(cudaMallocManaged(&j, sizeof(JOB)));

	for (uint32_t i = 0; i < 16; i++)
	{
		j->data1[i] = data1[i];
	}

	return j;
}

int main(void)
{
	JOB ** jobs;
	OUT * outs;
	uint32_t i,j;

	
	clock_t start, end;
	double cpu_time_used;
	int GPU_N;
	start = clock();
	checkCudaErrors(cudaGetDeviceCount(&GPU_N));
	checkCudaErrors(cudaSetDevice(GPU_N-1));
	//sha256_transform_0(&ctx1, Word1, buf1);
	
	checkCudaErrors(cudaMallocManaged(&jobs, N * sizeof(JOB *)));

	for (i=0; i < N; ++i){	
			WORD Word1[16] = {i, i+1, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000040};
			jobs[i] 	   = JOB_init(Word1);
	}

	for(j = 0; j <M; ++j){
		pre_sha512();
		runJobs(jobs, N, j, outs);
	}
	cudaDeviceSynchronize();	

	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

	printf("*Execution Time of 2^32 hashes on GPU : %f seconds\n", cpu_time_used);

	cudaDeviceReset();


	return 0;
}	
	
