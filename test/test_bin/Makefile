CC = gcc
CFLAGS = -Wall -Wextra -g -O3
LDFLAGS = -Wl,-rpath=.

SRC = main.c
OBJ = $(SRC:.c=.o)

LIBSRC = customlib.c
LIBOBJ = $(LIBSRC:.c=.o)
LIBNAME = libcustomlib.so
LIBSRC = customlib.c
LIBOBJ = $(LIBSRC:.c=.o)
CFLAGS += -fPIC


all: main

$(LIBNAME): $(LIBOBJ)
	$(CC) -shared -o $@ $^

main: $(OBJ) $(LIBNAME)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) -L. -lcustomlib
	strip ./main
	rm -rf *.o


clean:
	rm -f $(OBJ) $(LIBOBJ) main $(LIBNAME)
