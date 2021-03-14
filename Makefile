PHONY: all build clean run simulate

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	./host/linereghost ./enclave/linerengenc.signed