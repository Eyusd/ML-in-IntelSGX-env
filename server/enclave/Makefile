# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../project.edl --trusted --trusted-dir ../common --search-path $(INCDIR) --search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I. -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp ../common/regression.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/project_t.c
	$(CXX) -o project_enclave attestation.o crypto.o ecalls.o dispatcher.o regression.o project_t.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e project_enclave -c enc.conf -k private.pem
	cp project_enclave.signed project_enclave.debug.signed

clean:
	rm -f *.o project_enclave *.signed ../common/project_t.* ../common/project_args.h *.pem
