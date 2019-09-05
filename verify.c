#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

typedef struct Signature{
	unsigned int j;
	BIGNUM* Z;
	BIGNUM* sigma;
} Sig;

typedef struct VerifyKey{
	BIGNUM* N;
	BIGNUM* U;
	unsigned int T;
} VerKey;

int FSIGVerify(char M[], int M_l, Sig sign, VerKey VK);
int mySHA256(unsigned char* input, unsigned long len, BIGNUM* hash);

int main(int argc, char* argv[]){
	char* c_str;
	FILE* fp_vk,*fp_sign;
	VerKey VK;
	Sig sign;
	char Message[512] = "";

	char file_path[512] = "./Public_KEY.io";
	char file_path2[512] = "./Signature.io";
	
	if(argc == 2)
		strcpy(Message,argv[1]);
	
	if(argc == 2)
	fp_vk = fopen(file_path,"r+");

	char chT2[1024] = {0};
	char chT1[10] = {0};

	VK.N = BN_new();
	VK.U = BN_new();

	while(!feof(fp_vk)){
		fscanf(fp_vk,"%s %s\n\n",chT1,chT2);
		switch(chT1[0]){
			case 'N':
				BN_hex2bn(&VK.N,chT2);
				//printf("N: %s\n",chT2);
				break;
			case 'U':
				BN_hex2bn(&VK.U,chT2);
				//printf("U: %s\n",chT2);
				break;
			case 'T':
				VK.T = atoi(chT2);
				//printf("T: %s\n",chT2);
				break;
			default:
				break;
		}
	}
	fclose(fp_vk);

	fp_sign = fopen(file_path2, "r+");
	sign.Z = BN_new();
	sign.sigma = BN_new();

	while(!feof(fp_sign)){
		fscanf(fp_sign,"%s %s\n\n",chT1,chT2);
		switch(chT1[0]){
			case 'Z':
				BN_hex2bn(&sign.Z,chT2);
				//printf("Z: %s\n",chT2);
				break;
			case 'H':
				BN_hex2bn(&sign.sigma,chT2);
				//printf("H: %s\n",chT2);
				break;
			case 'j':
				sign.j = atoi(chT2);
				//printf("j: %s\n",chT2);
				break;
			default:
				break;
		}
	}
	fclose(fp_sign);

	clock_t start, end;
	start = clock();
	if(FSIGVerify(Message, strlen(Message), sign, VK) == 1){
		printf("\nAccept!\n");
	}
	else{
		printf("\nReject!\n");
	}
	end = clock();

	printf("\nVerify Time\n\t%f\n\n",((double)(end - start)/CLOCKS_PER_SEC));

	FILE* fp_time = fopen("./VerTime.txt","a+");
	fprintf(fp_time,"%d %d %f\n",BN_num_bits(VK.N),VK.T,((double)(end - start)/CLOCKS_PER_SEC));
	fclose(fp_time);

	return 0;
}

int FSIGVerify(char M[], int M_l, Sig sign, VerKey VK){
	BN_CTX* ctx = BN_CTX_new();
	int i = 0;

	BIGNUM* Z = BN_new();
	BIGNUM* U = BN_new();
	BIGNUM* Y = BN_new();
	
	BIGNUM* exp = BN_new();
	BIGNUM* tmp = BN_new();

	BIGNUM* new_sigma = BN_new();

	BN_set_word(exp,2);
	BN_set_word(tmp,256*(VK.T + 1 - sign.j));

	Z = BN_dup(sign.Z);
	U = BN_dup(VK.U);
	BN_exp(exp, exp, tmp, ctx);
	/*
	for(i = 0; i < (VK.T + 1 - sign.j); i++){
		BN_mod_exp(Z, Z, exp, VK.N, ctx);
	} */
	BN_mod_exp(Z, sign.Z, exp,VK.N, ctx);
	BN_mod_exp(U, VK.U, sign.sigma,VK.N, ctx);
	BN_mod_mul(Y, Z, U, VK.N,ctx);

	unsigned char* c_str = BN_bn2hex(Y);
	unsigned int j_tmp = sign.j;
	
	for(i = 0; i < BN_num_bits(Y); i++){
		if(i < M_l)
			c_str[i] = c_str[i]^M[i]^(j_tmp%256);
		else
			c_str[i] = c_str[i]^(j_tmp%256);
		j_tmp /= 256;
	}
	c_str[i] = 0;	

	if(!mySHA256(c_str, strlen(c_str), new_sigma))
		printf("SHA Error!\n");

	c_str = BN_bn2hex(new_sigma);
	printf("new_sigma: %s\n",c_str);

	printf("ori_sigma: %s\n",BN_bn2hex(sign.sigma));
	
	if(BN_cmp(new_sigma, sign.sigma) == 0)
		return 1;
	return 0;
}


int mySHA256(unsigned char input[], unsigned long len, BIGNUM* hash){
	unsigned char buffer[257];
	unsigned char hexbuffer[1024] = {0};
	SHA256_CTX ctx;
	if(!SHA256_Init(&ctx))
		return 0;
	if(!SHA256_Update(&ctx, input, len))
		return 0;
	if(!SHA256_Final(buffer,&ctx))
		return 0;
	
	for(int i = 0; i < 256;i++)
		sprintf(hexbuffer + (i*2), "%02x", buffer[i]);
	hexbuffer[64] = 0;

	BN_hex2bn(&hash, hexbuffer);

	return 1;
}
