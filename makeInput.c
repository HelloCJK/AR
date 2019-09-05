#include <stdio.h>

int main(){
	int N = 512;
	int T = 1024;
	char m[] = "HelloCrypto";
	int j = 1;

	FILE* fp = fopen("./input.in","w+");

	fprintf(fp,"300\n");

	for(int i = 0; i < 300; i++){
		fprintf(fp,"%d %d %s %d\n",N,T,m,j);
		T *= 2;
		if(T > 1000000){
			T = 1024;
			N *= 2;
			if(N > 4000)
				N = 512;
		}
	}
	fclose(fp);

	return 0;
}
