CFLAGS ?= -O2 -pipe -fomit-frame-pointer -march=native
ifeq ($(OLD_IPSET),1)
	CFLAGS += -DOLD_IPSET
else
	CFLAGS += -lmnl
endif

.PHONY: clean

ipset-dns:

clean:
	rm -f ipset-dns
