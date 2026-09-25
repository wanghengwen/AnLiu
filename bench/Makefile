CFLAGS ?= -std=gnu99 -O2 -g -Wall -Wextra

anl_bench: bench.c ../anliu.c ../anliu.h ikcp.c ikcp.h
	$(CC) $(CFLAGS) -I. -I.. -c bench.c -o bench.o
	$(CC) $(CFLAGS) -I.. -c ../anliu.c -o anliu.o
	$(CC) -std=gnu99 -O2 -g -w -c ikcp.c -o ikcp.o
	$(CC) bench.o anliu.o ikcp.o -o $@ -lm

clean:
	rm -f *.o anl_bench
