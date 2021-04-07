  
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

OE_CRYPTO_LIB := mbedtls
CRYPTO_LDFLAGS := $(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem
	../gen_pubkey_header.sh ../enclave/enclave_pubkey.h $<

build:
	@ echo "LDFLAGS used : $(LDFLAGS)"
	@ echo "CRYPTO_LDFLAGS used : $(CRYPTO_LDFLAGS)"
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../linereg.edl --trusted --trusted-dir ../common \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I../../../include -I. -I.. -DOE_API_VERSION=2 -std=c++11 enc.cpp ../common/regression.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp ../common/gatherer.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/linereg_t.c -o linereg_t.o
	$(CXX) -o lineregenc linereg_t.o enc.o regression.o attestation.o dispatcher.o gatherer.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e lineregenc -c enc.conf -k private.pem

clean:
	rm -f *.o lineregenc *.signed enc.o lineregenc lineregenc.signed private.pem public.pem linereg_t.o linereg_t.h linereg_t.c linereg_args.h linereg.o ../common/linereg_args.h enclave_pubkey.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem