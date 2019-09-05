#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]){
	char s_params[512] = {0};
	char per_T[512] = {0};
	char m[512] = {0};

	char com[512] = "./";

	int j = 0;
	int tast_case = 0; //= atoi(argv[1]);

	scanf("%d",&tast_case);

	for(int i = 0; i < tast_case; i++){
		//strcpy(s_params,argv[1]);
		//strcpy(per_T,argv[2]);
		//strcpy(m,argv[3]);
		//j = atoi(argv[4]);
		scanf("%s",s_params);
		scanf("%s",per_T);
		scanf("%s",m);
		scanf("%d",&j);


		// key gen
		strcpy(com,"./keygen_ ");
		strcat(com,s_params);
		strcat(com," ");
		strcat(com,per_T);

		system(com);

		// update
		strcpy(com,"./update_");
		for(int i = 0; i < j; i++){
			system(com);
		}

		// make signature
		strcpy(com,"./sign_ ");
		strcat(com,m);
		system(com);

		// check verify
		strcpy(com,"./verify_ ");
		strcat(com,m);
		system(com);

		printf("\nA new Forward Digital Signature End\n");
	}
	return 0;
}
