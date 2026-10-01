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

realnet_trace: realnet.c ../anliu.c ../anliu.h ikcp.c ikcp.h tx_diag.h fec_diag.h
	$(CC) -std=gnu99 -O2 -DREALNET_INTERNAL -I. -I.. realnet.c ikcp.c -o $@ -lm

# CPU per segment against window / BDP / loss (DESIGN 5.1): ./wndcost MBps rtt_ms loss_permille wnd seconds [seed]
wndcost: wndcost.c ../anliu.c ../anliu.h
	$(CC) -std=gnu99 -O2 -I.. wndcost.c ../anliu.c -o $@ -lm

clean:
	rm -f *.o anl_bench realnet realnet_trace wndcost media_loss_asan

# Deterministic auto-FEC media validation; all simulation objects use ASan,
# without the production benchmark's -O2 or separately compiled anliu.c.
media_loss_asan: media_loss.c bench.c ../anliu.c ../anliu.h ikcp.c ikcp.h
	$(CC) -std=gnu99 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I. -I.. media_loss.c ikcp.c -lm -o $@

.PHONY: test_media_loss
test_media_loss: media_loss_asan
	python3 test_media_loss.py ./media_loss_asan
