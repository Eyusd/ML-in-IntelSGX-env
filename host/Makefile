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
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) linereg_u.c
	$(CXX) -o linereghost linereg_u.o host.o $(LDFLAGS)

clean:
	rm -f linereghost host.o regression_u.o regression_u.c regression_u.h regression_args.h ../common/linereg_t.c ../common/linereg_t.h