#
# Makefile for Encrypt decrypt
# libgcrypt 1.5.0
# Author : Suresh Koppisetty
# 
# run make clean to clean 
# run make to generate compile

COMPILER=gcc
CFLAGS = 
LDFLAGS = -I. 
LIBS =-lgcrypt
all: assign2
assign2: gatordec gatorcrypt

gatordec:
	$(COMPILER) $(CFLAGS) gatordec.c -o gatordec $(LDFLAGS) $(LIBS)
gatordec_clean:
	rm -rf *.o gatordec
	
gatorcrypt:
	$(COMPILER) $(CFLAGS) gatorcrypt.c -o gatorcrypt $(LDFLAGS) $(LIBS)
gatorcrypt_clean:
	rm -rf *.o gatorcrypt *.uf

clean:
	rm -rf *.o gatordec gatorcrypt *.uf
