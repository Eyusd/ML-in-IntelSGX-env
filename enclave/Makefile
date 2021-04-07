  
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
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem

build:
	@ echo "LDFLAGS used : $(LDFLAGS)"
	@ echo "CRYPTO_LDFLAGS used : $(CRYPTO_LDFLAGS)"
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../linereg.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I. -I.. -DOE_API_VERSION=2 -std=c++11 enc.cpp linereg.cpp ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 linereg_t.c -o linereg_t.o
	$(CXX) -o lineregenc linereg_t.o enc.o linereg.o attestation.o crypto.o ecalls.o dispatcher.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e lineregenc -c linereg.conf -k private.pem
	cp lineregenc.signed linereg.debug.signed
	oesign sign -e lineregenc -c linereg.conf.release -k private.pem
	cp lineregenc.signed lineregenc.release.signed
	oesign sign -e lineregenc -c linereg.conf.prodid -k private.pem
	cp lineregenc.signed lineregenc.prodid.signed
	oesign sign -e lineregenc -c linereg.conf.securityversion -k private.pem
	cp lineregenc.signed lineregenc.securityversion.signed

clean:
	rm -f *.o *.signed ../common/remoteattestation_t.* ../common/remoteattestation_args.h *.pem enclave_b_pubkey.h enc.o lineregenc lineregenc.signed private.pem public.pem linereg_t.o linereg_t.h linereg_t.c linereg_args.h linereg.o

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem