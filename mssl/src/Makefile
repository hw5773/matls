CC = cc
RM = rm
CFLAGS=-O -DDEBUG -I/usr/local/include -Wall

OBJS = core.o tcp_stream.o config.o api.o mos_api.o eventpoll.o socket.o pipe.o \
			 tcp_util.o eth_in.o ip_in.o tcp.o tcp_in.o eth_out.o ip_out.o tcp.o tcp_out.o logs.o \
			 arp.o timer.o cpu.o util.o addr_pool.o fhash.o memory_mgt.o logs.o \
			 tcp_rb_frag_queue.o tcp_send_buffer.o tcp_sb_queue.o tcp_stream_queue.o \
			 bpf/sf_bpf_filter.o bpf/sfbpf-int.o bpf/sf_gencode.o bpf/sf_grammar.o \
			 bpf/sf_nametoaddr.o bpf/sf_optimize.o bpf/sf_scanner.o \
			 event_callback.o tcp_rb.o icmp.o scalable_event.o key_value_store.o sock_module.o
#			 tcp_rb.o sock_module.o tls_split.o scalable_event.o mos_api.o event_callback.o \
			 tcp_send_buffer.o eventpoll.o tcp_sb_queue.o pipe.o tcp_stream_queue.o addr_pool.o

SRC = core.c tcp_stream.c config.c api.c mos_api.c eventpoll.c socket.c pipe.c \
			tcp_util.c eth_in.c ip_in.c tcp.c tcp_in.c eth_out.c ip_out.c tcp.o tcp_out.c logs.c \
			arp.c timer.c cpu.c util.c addr_pool.c fhash.c memory_mgt.c logs.c \
			tcp_rb_frag_queue.c tcp_send_buffer.c tcp_sb_queue.c tcp_stream_queue.c \
			bpf/sf_bpf_filter.c bpf/sfbpf-int.c bpf/sf_gencode.c bpf/sf_grammar.c \
			bpf/sf_nametoaddr.c bpf/sf_optimize.c bpf/sf_scanner.c \
			event_callback.c tcp_rb.c icmp.c scalable_event.c key_value_store.c sock_module.c
#			tcp_rb.c sock_module.c tls_split.c scalable_event.c mos_api.c event_callback.c \
			tcp_send_buffer.c eventpoll.c tcp_sb_queue.c pipe.c tcp_stream_queue.c addr_pool.c

default: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
