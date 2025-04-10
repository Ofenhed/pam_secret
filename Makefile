pam_tpm2.o: pam_tpm2.c
	gcc -fPIC -c pam_tpm2.c -o pam_tpm2.o

pam_tpm2.so: pam_tpm2.o
	ld -x --shared -l ssl -o pam_tpm2.so pam_tpm2.o

install: pam_tpm2.so
	install --mode=755 --owner=root --group=root --target-directory=/usr/lib64/security/ pam_tpm2.so

clean:
	rm -f pam_tpm2.o pam_tpm2.so

all: pam_tpm2.so
