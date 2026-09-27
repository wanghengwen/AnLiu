CFLAGS ?= -std=gnu99 -O2 -g -Wall -Wextra

all: anl_bench realnet

anl_bench: bench.c ../anliu.c ../anliu.h ikcp.c ikcp.h
	$(CC) $(CFLAGS) -I. -I.. -c bench.c -o bench.o
	$(CC) $(CFLAGS) -I.. -c ../anliu.c -o anliu.o
	$(CC) -std=gnu99 -O2 -g -w -c ikcp.c -o ikcp.o
	$(CC) bench.o anliu.o ikcp.o -o $@ -lm

# real-network comparison (see ../README.md 6.3); realnet_trace shows BBR internals (REALNET_TRACE=1)
realnet: realnet.c ../anliu.c ../anliu.h ikcp.c ikcp.h
	$(CC) -std=gnu99 -O2 -I. -I.. realnet.c ../anliu.c ikcp.c -o $@ -lm

realnet_trace: realnet.c ../anliu.c ../anliu.h ikcp.c ikcp.h
	$(CC) -std=gnu99 -O2 -DREALNET_INTERNAL -I. -I.. realnet.c ikcp.c -o $@ -lm

clean:
	rm -f *.o anl_bench realnet realnet_trace
