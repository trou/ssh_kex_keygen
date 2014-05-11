CC = gcc
COPTS =-W -Wall -lssl -O2

keygen: main.c
	$(CC) $(COPTS) -o $@ $<

test:
	bash test.sh
