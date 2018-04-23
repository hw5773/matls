/* 
 * TCP free send buffer queue - tcp_sb_queue.c/h
 *
 * EunYoung Jeong
 *
 * Part of this code borrows Click's simple queue implementation
 *
 * ============================== Click License =============================
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <assert.h>
#include "include/tcp_sb_queue.h"

/*----------------------------------------------------------------------------*/
#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif
/*---------------------------------------------------------------------------*/
struct sb_queue
{
	index_type _capacity;
	volatile index_type _head;
	volatile index_type _tail;

	struct tcp_send_buffer * volatile * _q;
};
/*----------------------------------------------------------------------------*/
static inline index_type 
next_index(sb_queue_t sq, index_type i)
{
	return (i != sq->_capacity ? i + 1: 0);
}
/*---------------------------------------------------------------------------*/
static inline index_type 
prev_index(sb_queue_t sq, index_type i)
{
	return (i != 0 ? i - 1: sq->_capacity);
}
/*---------------------------------------------------------------------------*/
static inline void 
sb_memory_barrier(struct tcp_send_buffer * volatile buf, volatile index_type index)
{
	__asm__ volatile("" : : "m" (buf), "m" (index));
}
/*---------------------------------------------------------------------------*/
sb_queue_t 
create_sb_queue(int capacity)
{
	sb_queue_t sq;

	sq = (sb_queue_t)calloc(1, sizeof(struct sb_queue));
	if (!sq)
		return NULL;

	sq->_q = (struct tcp_send_buffer **)
			calloc(capacity + 1, sizeof(struct tcp_send_buffer *));
	if (!sq->_q) {
		free(sq);
		return NULL;
	}

	sq->_capacity = capacity;
	sq->_head = sq->_tail = 0;

	return sq;
}
/*---------------------------------------------------------------------------*/
void 
destroy_sb_queue(sb_queue_t sq)
{
	if (!sq)
		return;

	if (sq->_q) {
		free((void *)sq->_q);
		sq->_q = NULL;
	}

	free(sq);
}
/*---------------------------------------------------------------------------*/
int 
sb_enqueue(sb_queue_t sq, struct tcp_send_buffer *buf)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;
	index_type nt = next_index(sq, t);

	if (nt != h) {
		sq->_q[t] = buf;
		sb_memory_barrier(sq->_q[t], sq->_tail);
		sq->_tail = nt;
		return 0;
	}

	return -1;
}
/*---------------------------------------------------------------------------*/
struct tcp_send_buffer *
sb_dequeue(sb_queue_t sq)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;

	if (h != t) {
		struct tcp_send_buffer *buf = sq->_q[h];
		sb_memory_barrier(sq->_q[h], sq->_head);
		sq->_head = next_index(sq, h);
		assert(buf);

		return buf;
	}

	return NULL;
}
/*---------------------------------------------------------------------------*/
