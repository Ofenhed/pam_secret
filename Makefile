CFLAGS += -std=c23 -D_GNU_SOURCE -DDEBUG -DSERVICE_GROUP=qubes

all: build/pam_tpm2.so build/main

install-deps:
	dnf install -Cy clangd openssl-devel pam-devel

build:
	mkdir $@

build/%.o: %.c build
	$(CC) $(CFLAGS) -g -fPIC -c $< -o $@

build/main-debug: build/main.o build/utils.o build/creds.o build/extern.o build/install.o build/hash.o build/daemon.o build/ipc.o build/fortify.o
	$(CC) $(CFLAGS) -g -fPIE -pie $^ -lssl -lcrypto -lcap -o $@

build/main.symbols: build/main-debug
	objcopy --only-keep-debug $? $@

build/main: build/main-debug build/main.symbols
	cp $< $@
	strip --strip-debug --strip-unneeded $@
	objcopy --add-gnu-debuglink=build/main.symbols $@

build/pam_tpm2.so: build/pam_tpm2.o build/utils.o build/creds.o build/hash.o
	$(CC) -shared -fPIC -l ssl $< -o $@

install: build/pam_tpm2.so
	install --mode=755 --owner=root --group=root --target-directory=/usr/lib64/security/ pam_tpm2.so

clean:
	rm -rf ./build/

.PHONY: clean install all install-deps
