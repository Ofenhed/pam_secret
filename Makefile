#CFLAGS += -std=c23 -fvisibility=hidden -g -D_GNU_SOURCE -DDEBUG -DSERVICE_GROUP=qubes
CFLAGS += -std=c23 -Wall -g -DDEBUG -D_GNU_SOURCE -DSERVICE_GROUP=qubes

all: build/pam_secret.so build/pam_secret

install-deps:
	dnf install -Cy clangd openssl-devel pam-devel

build:
	mkdir $@

build/%.o: %.c build
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

build/pam_secret.so: build/main.o build/utils.o build/creds.o build/extern.o build/install.o build/hash.o build/daemon.o build/ipc.o build/fortify.o build/pam_secret.o
	# $(CC) $(CFLAGS) -fPIC -fPIE -pie -shared -Wl,-soname,$@ -Wl,-e,lib_entry $^ -lssl -lcrypto -lcap -lpam -o $@
	$(CC) $(CFLAGS) -fPIC -shared $^ -lssl -lcrypto -lcap -lpam -o $@

build/pam_secret-debug: build/libwrapper.o
	$(CC) $(CFLAGS) -g -fPIE -pie -ldl $^ -o $@

build/pam_secret.symbols: build/pam_secret-debug
	objcopy --only-keep-debug $? $@

build/pam_secret: build/pam_secret-debug build/pam_secret.symbols
	cp $< $@
	strip --strip-debug --strip-unneeded $@
	objcopy --add-gnu-debuglink=build/pam_secret.symbols $@

install-pam: build/pam_secret.so
	install --mode=755 --owner=root --group=root --target-directory=/usr/lib64/security/ $<

install-main: build/pam_secret
	install --mode=755 --owner=root --group=root --target-directory=/usr/sbin/ $<
	setcap cap_dac_override+p /usr/sbin/pam_secret

install: install-pam install-main

clean:
	rm -rf ./build/ || rm -f ./build/*

.PHONY: clean install all install-deps install install-pam install-main
