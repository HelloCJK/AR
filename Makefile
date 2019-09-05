CC = gcc

all : keygen_ update_ sign_ verify_ FSIG_
	
FSIG_ : main.c
	$(CC) -o FSIG_ main.c

keygen_ : keygen.c
	$(CC) -o keygen_ keygen.c -lcrypto
update_ : update.c
	$(CC) -o update_ update.c -lcrypto
sign_ : sign.c
	$(CC) -o sign_ sign.c -lcrypto
verify_ : verify.c
	$(CC) -o verify_ verify.c -lcrypto

clean :
	rm *_ *.io *.txt
