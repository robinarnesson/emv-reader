all:
	gcc emv-reader.c -o emv-reader -Wall -std=c99 -I /usr/include/PCSC -lpcsclite

clean:
	rm -f emv-reader
