# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../project.edl --untrusted --search-path $(INCDIR) --search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) project_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) host.cpp quotefile.cpp
	$(CXX) -o project_host host.o quotefile.o project_u.o   $(LDFLAGS)

clean:
	rm -f project_host *.o project_u.*  project_args.h



