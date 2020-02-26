CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := hack_server.c hack_client.c 
targets := hack_server hack_client

.PHONY: clean default all

default: all
all: $(targets)


hack_server: hack_server.o
	$(CC) $(LDFLAGS) -o hack_server hack_server.o

hack_server.o: hack_server.c
	$(CC) $(CFLAGS) -c -o hack_server.o  hack_server.c

hack_client: hack_client.o
	$(CC) $(LDFLAGS) -o hack_client hack_client.o

hack_client.o: hack_client.c
	$(CC) $(CFLAGS) -c -o hack_client.o hack_client.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

