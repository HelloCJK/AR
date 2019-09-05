#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

typedef struct VerifyKey{
	BIGNUM* N;
	BIGNUM* U;
	unsigned int T;
} VerKey;

typedef struct SignKey{
	BIGNUM* N;
	unsigned int T;
	unsigned int j;
	BIGNUM* s;
} SignKey;

typedef struct Key{
	SignKey SK;
	VerKey VK;
} Key;

Key FSIGKeyGen(int bits,unsigned int T);
int getBlumInt(BIGNUM* ret,int bits);

int main(int argc, char* argv[]){
	char* c_str;

	FILE* fp_vk;
	FILE* fp_sk;
	FILE* fp_t;

	int bits = atoi(argv[1]);
	unsigned int T = atoi(argv[2]);

	fp_vk = fopen("./Public_KEY.io","w+");
	fp_sk = fopen("./Secret_KEY.io","w+");
	fp_t = fopen("./KeyGenTime.txt","a+");

	clock_t start, end;
	start = clock();
	Key k = FSIGKeyGen(bits,T);
	end = clock();
	c_str = BN_bn2hex(k.VK.N);
	//printf("N : %s\n",c_str);
	fprintf(fp_vk,"N: %s\n\n",c_str);
	fprintf(fp_sk,"N: %s\n\n",c_str);

	c_str = BN_bn2hex(k.VK.U);
	//printf("U : %s\n",c_str);
	fprintf(fp_vk,"U: %s\n\n",c_str);
	
	c_str = BN_bn2hex(k.SK.s);
	//printf("s : %s\n",c_str);
	fprintf(fp_sk,"s: %s\n\n",c_str);

	//printf("T : %d\n",T);	
	//printf("j : 0\n");	
	fprintf(fp_vk,"T: %d\n\n",T);
	fprintf(fp_sk,"T: %d\n\n",T);
	fprintf(fp_sk,"j: 0\n\n");
	
	fclose(fp_vk);
	fclose(fp_sk);

	printf("\nKey Generation Time\n\t%f\n\n",((double)(end - start)/CLOCKS_PER_SEC));
	int size_of_sk = BN_num_bytes(k.SK.N) + BN_num_bytes(k.SK.s) + sizeof(k.SK.T) + sizeof(k.SK.j);
	int size_of_vk = BN_num_bytes(k.VK.N) + BN_num_bytes(k.VK.U) + sizeof(k.VK.T);
	fprintf(fp_t,"(N: %d) (T: %d)\n(Key Size SK: %d  VK: %d) (TIME: %f)\n",bits,T,size_of_sk,size_of_vk,((double)(end - start)/CLOCKS_PER_SEC));

	fclose(fp_t);
	return 0;
}

Key FSIGKeyGen(int bits,unsigned int T){
	Key ret;
	BN_CTX* ctx = BN_CTX_new();
	char* c_str;
	
	BIGNUM* N = BN_new();
	BIGNUM* S = BN_new();
	BIGNUM* U = BN_new();

	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* phi_N = BN_new();
	
	do{
		getBlumInt(p,bits>>1);
		getBlumInt(q,bits>>1);
		BN_mul(N,p,q,ctx);
	}
	while(BN_num_bits(N) != bits);

	BN_sub_word(p,1);
	BN_sub_word(q,1);

	BN_mul(phi_N,p,q,ctx);

	BN_rand(S, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
	BN_mod(S,S,N,ctx);

	BIGNUM* tmp = BN_new();
	BIGNUM* two = BN_new();
	BIGNUM* exp = BN_new();

	BN_set_word(tmp, 256*(T+1));
	BN_set_word(two, 2);

	BN_mod_exp(exp, two, tmp, phi_N,ctx);
	BN_mod_exp(U, S, exp, N, ctx);
	BN_mod_inverse(U,U,N,ctx);

	ret.SK.N = BN_new();
	ret.SK.s = BN_new();
	ret.VK.N = BN_new();
	ret.VK.U = BN_new();

	ret.SK.N = BN_dup(N);
	ret.SK.T = T;
	ret.SK.j = 0;
	ret.SK.s = BN_dup(S);

	ret.VK.N = BN_dup(N);
	ret.VK.U = BN_dup(U);
	ret.VK.T = T;

	return ret;
}
int getBlumInt(BIGNUM* ret,int bits){
		
	BIGNUM* add = BN_new();
	BIGNUM* rem = BN_new();
	
	BN_set_word(add,4);
	BN_set_word(rem,3);
	
	BN_generate_prime_ex(ret,bits,0,add,rem,NULL);

	return 1;
}
