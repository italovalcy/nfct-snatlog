CC=/usr/bin/gcc
CCFLAGS=-Wall

all: nfct-snatlog

nfct-snatlog: nfct-snatlog.o
	$(CC) $^ -o $@

.c.o:
	$(CC) $(CCFLAGS) $< -c -o $@

clean:
	/bin/rm -f *.o nfct-snatlog
