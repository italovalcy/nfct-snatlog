CC=/usr/bin/gcc
CCFLAGS=-Wall

all: nfct-snatlog

nfct-snatlog: nfct-snatlog.o
	$(CC) $^ -o $@ `pkg-config --cflags --libs libnetfilter_conntrack`

.c.o:
	$(CC) $(CCFLAGS) $< -c -o $@

clean:
	/bin/rm -f *.o nfct-snatlog
