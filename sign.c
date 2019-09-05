#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

typedef struct SignKey{
	BIGNUM* N;
	unsigned int T;
	unsigned int j;
	BIGNUM* s;
} SignKey;

typedef struct Signature{
	unsigned int j;
	BIGNUM* Z;
	BIGNUM* sigma;
} Sig;

Sig FSIGSign(char M[], int M_l, SignKey SK);
int mySHA256(unsigned char* input, unsigned long len, BIGNUM* hash);

int main(int argc, char* argv[]){
	char* c_str;
	FILE* fp_sk;
	SignKey SK;
	Sig sign;
	char Message[512] = "";

	char file_path[512] = "./Secret_KEY.io";
	if(argc == 2)
		strcpy(Message,argv[1]);
	else if(argc == 3)
		strcpy(file_path+2,argv[2]);
	
	fp_sk = fopen(file_path,"r+");
	char chT2[1024] = {0};
	char chT1[10] = {0};

	SK.N = BN_new();
	SK.s = BN_new();
	
	while(!feof(fp_sk)){
		fscanf(fp_sk,"%s %s\n\n",chT1,chT2);
		switch(chT1[0]){
			case 'N':
				BN_hex2bn(&SK.N,chT2);
				break;
			case 's':
				BN_hex2bn(&SK.s,chT2);
				break;
			case 'T':
				SK.T = atoi(chT2);
				break;
			case 'j':
				SK.j = atoi(chT2);
				break;
			default:
				break;
		}
	}
	fclose(fp_sk);
	clock_t start, end;
	start = clock();
	sign = FSIGSign(Message, strlen(Message), SK);
	end = clock();

	FILE* fp_sign = fopen("./Signature.io","w+");
	c_str = BN_bn2hex(sign.Z);
	//printf("Z : %s\n",c_str);
	fprintf(fp_sign,"Z: %s\n\n",c_str);

	c_str = BN_bn2hex(sign.sigma);
	//printf("H : %s\n",c_str);
	fprintf(fp_sign,"H: %s\n\n",c_str);
	
	//printf("j: %d\n",sign.j);
	fprintf(fp_sign,"j: %d\n\n",sign.j);
	
	fclose(fp_sign);
	printf("\nSign Time\n\t%f\n\n",((double)(end - start)/CLOCKS_PER_SEC));
	
	FILE* fp_time = fopen("./SignTime.txt","a+");
	fprintf(fp_time,"%d %d %f\n",BN_num_bits(SK.N),SK.T,((double)(end - start)/CLOCKS_PER_SEC));
	fclose(fp_time);	
	return 0;
}

Sig FSIGSign(char M[], int M_l, SignKey SK){
	Sig ret;
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* R = BN_new();

	ret.Z = BN_new();
	ret.sigma = BN_new();

	BN_rand(R, BN_num_bits(SK.N), BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
	BN_mod(R, R, SK.N, ctx);

	BIGNUM* Y = BN_new();
	BIGNUM* exp = BN_new();
	BIGNUM* tmp = BN_new();

	BN_set_word(exp,2);
	BN_set_word(tmp,256*(SK.T + 1 - SK.j));

	Y = BN_dup(R);
	BN_exp(exp, exp, tmp, ctx);
	/*
	for(int i = 0; i < (SK.T + 1 - SK.j); i++){
		BN_mod_exp(Y, Y, exp, SK.N, ctx);
	}*/
	BN_mod_exp(Y,Y,exp,SK.N,ctx);

	unsigned char* c_str = BN_bn2hex(Y);
	unsigned int j_tmp = SK.j;
	int i = 0;
	for(i = 0; i < BN_num_bits(Y); i++){
		if(i < M_l)
			c_str[i] = c_str[i]^M[i]^(j_tmp%256);
		else
			c_str[i] = c_str[i]^(j_tmp%256);
		j_tmp /= 256;
	}
	c_str[i] = 0;	

	if(!mySHA256(c_str, strlen(c_str), ret.sigma))
		printf("SHA Error!\n");

	BN_mod_exp(ret.Z, SK.s, ret.sigma, SK.N, ctx);
	BN_mod_mul(ret.Z, ret.Z, R, SK.N, ctx);

	ret.j = SK.j;

	return ret;
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
