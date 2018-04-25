#ifndef __TCP_RB_FRAG_QUEUE_
#define __TCP_RB_FRAG_QUEUE_

#include "tcp_ring_buffer.h"

/*---------------------------------------------------------------------------*/
typedef struct rb_frag_queue* rb_frag_queue_t;
/*---------------------------------------------------------------------------*/
rb_frag_queue_t 
create_rb_frag_queue(int capacity);
/*---------------------------------------------------------------------------*/
void 
destroy_rb_frag_queue(rb_frag_queue_t rb_fragq);
/*---------------------------------------------------------------------------*/
int 
rb_frag_enqueue(rb_frag_queue_t rb_fragq, struct fragment_ctx *frag);
/*---------------------------------------------------------------------------*/
struct fragment_ctx *
rb_frag_dequeue(rb_frag_queue_t rb_fragq);
/*---------------------------------------------------------------------------*/

#endif /* __TCP_RB_FRAG_QUEUE_ */
