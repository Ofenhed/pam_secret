#CFLAGS += -std=c23 -g -D_GNU_SOURCE -DDEBUG -DSERVICE_GROUP=qubes
pam_secret_group = qubes
CFLAGS += -std=c23 -fvisibility=hidden -Wall -Wextra -Wno-unused-parameter -Wformat=2 -Wformat-security -D__USE_GNU -D_GNU_SOURCE -DSERVICE_GROUP=$(pam_secret_group)
# CFLAGS += -Wconversion
pam_lib_dir = /usr/lib64/security

ifdef log_level
	CFLAGS += -DDEBUG_LEVEL=$(log_level)
else
	CFLAGS += -DDEBUG_LEVEL=4
endif

ifeq ($(CC), clang)
	CFLAGS = -fblocks
endif

ifndef target
	target = release
endif

ifeq ($(target), release)
	CFLAGS += -O2 -fstack-protector-all -Wstrict-overflow -D_FORTIFY_SOURCE=2
	LDFLAGS += -Wl,-z,noexecstack -Wl,-z,noexecheap -Wl,-z,relro -Wl,-z,now
endif
ifeq ($(target), debug)
	CFLAGS += -DDEBUG
endif

all: build/pam_secret.so build/pam_secret

install-deps:
	dnf install -Cy clangd openssl-devel pam-devel

build:
	mkdir $@

build/%.o: %.c build
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

build/pam_secret.so-debug: build/main.o build/utils.o build/creds.o build/extern.o build/install.o build/hash.o build/daemon.o build/ipc.o build/fortify.o build/pam_secret.o build/log.o build/path.o build/session_mask.o
	$(CC) -fPIC -shared $^ -lssl -lcap -lpam -o $@ $(LDFLAGS) -z,now -Wl,-soname=$(pam_lib_dir)/pam_secret.so

build/pam_secret.so.symbols: build/pam_secret.so-debug
	objcopy --only-keep-debug $? $@

build/pam_secret.so: build/pam_secret.so-debug build/pam_secret.so.symbols
	cp $< $@
	strip --strip-debug --strip-unneeded $@
	objcopy --add-gnu-debuglink=build/pam_secret.so.symbols $@

build/pam_secret-debug: build/libwrapper.o build/pam_secret.so
	$(CC) $(LDFLAGS) -g -fPIE -pie $< -o $@ -Lbuild -l:pam_secret.so

build/pam_secret.symbols: build/pam_secret-debug
	objcopy --only-keep-debug $? $@

build/pam_secret: build/pam_secret-debug build/pam_secret.symbols
	cp $< $@
	strip --strip-debug --strip-unneeded $@
	objcopy --add-gnu-debuglink=build/pam_secret.symbols $@

install-pam: build/pam_secret.so
	install --mode=755 --owner=root --group=root --target-directory=$(pam_lib_dir)/ $<

install-main: build/pam_secret
	install --mode=755 --owner=root --group=root --target-directory=/usr/sbin/ $<
	setcap cap_dac_override+p /usr/sbin/pam_secret

install-qubes-rpc:
	cp qubes-rpc/auth.* /etc/qubes-rpc/

install: install-pam install-main install-qubes-rpc

clean:
	rm -rf ./build/ || rm -f ./build/*

.PHONY: clean install all install-deps install install-pam install-main install-qubes-rpc
