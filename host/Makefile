# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../linereg.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) quotefile.cpp host.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) remoteattestation_u.c linereg_u.c
	$(CXX) -o linereghost linereg_u.o host.o genquote_host host.o quotefile.o remoteattestation_u.o $(LDFLAGS)

clean:
	rm -f linereghost host.o linereg_u.o linereg_u.c linereg_u.h linereg_args.h genquote_host *.o remoteattestation_u.*  remoteattestation_args.h