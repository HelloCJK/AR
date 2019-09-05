#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

typedef struct SignKey{
	BIGNUM* N;
	unsigned int T;
	unsigned int j;
	BIGNUM* s;
} SignKey;

SignKey FSIGUpdate(SignKey SK);

int main(int argc, char* argv[]){
	char* c_str;
	FILE* fp_sk;
	SignKey SK;

	char file_path[512] = "./Secret_KEY.io";
	if(argc == 2)
		strcpy(file_path+2,argv[1]);
	
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
	SK = FSIGUpdate(SK);
	end = clock();

	fp_sk = fopen(file_path,"w+");
	c_str = BN_bn2hex(SK.N);
	//printf("N : %s\n",c_str);
	fprintf(fp_sk,"N: %s\n\n",c_str);

	c_str = BN_bn2hex(SK.s);
	//printf("s : %s\n",c_str);
	fprintf(fp_sk,"s: %s\n\n",c_str);
	
	//printf("T: %d\n",SK.T);
	//printf("j: %d\n",SK.j);
	fprintf(fp_sk,"T: %d\n\n",SK.T);
	fprintf(fp_sk,"j: %d\n\n",SK.j);
	
	fclose(fp_sk);
	printf("\nKey update Time\n\t%f\n\n",((double)(end - start)/CLOCKS_PER_SEC));
	
	FILE* fp_time = fopen("./UpdateTime.txt","a+");
	fprintf(fp_time,"%d %d %f\n",BN_num_bits(SK.N),SK.T,((double)(end - start)/CLOCKS_PER_SEC));
	fclose(fp_time);
	
	return 0;
}

SignKey FSIGUpdate(SignKey SK){
	SignKey ret;
	BN_CTX* ctx = BN_CTX_new();

	ret.N = BN_new();
	ret.s = BN_new();

	if(SK.j == SK.T){
		printf("i == T!\n");
		return ret;
	}

	BIGNUM* exp = BN_new();
	BIGNUM* l = BN_new();

	BN_set_word(exp,2);
	BN_set_word(l, 256);

	BN_exp(exp, exp, l, ctx);
	BN_mod_exp(ret.s, SK.s, exp, SK.N, ctx);

	ret.N = BN_dup(SK.N);
	ret.T = SK.T;
	ret.j = SK.j + 1;
	
	return ret;
}
