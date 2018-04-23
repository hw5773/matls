#include <string.h>

#include "include/memory_mgt.h"
#include "include/logs.h"
#include "include/tcp_send_buffer.h"
#include "include/tcp_sb_queue.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

struct sb_manager
{
  size_t chunk_size;
  uint32_t cur_num;
  uint32_t cnum;
  mem_pool_t mp;
  sb_queue_t freeq;
} sb_manager;

uint32_t sb_get_curnum(sb_manager_t sbm)
{
  return sbm->cur_num;
}

sb_manager_t sb_manager_create(size_t chunk_size, uint8_t disable_rings, uint32_t concurrency)
{
  sb_manager_t sbm = (sb_manager_t)calloc(1, sizeof(sb_manager));
  if (!sbm)
  {
    MA_LOG("sb_manager_create() failed");
    return NULL;
  }

  sbm->chunk_size = chunk_size;
  sbm->cnum = concurrency;
  sbm->mp = (mem_pool_t)mp_create(chunk_size, 
      (uint64_t)chunk_size * (!disable_rings * concurrency), 0);

  if (!sbm->mp)
  {
    MA_LOG("failed to create mem pool for sb");
    free(sbm);
    return NULL;
  }

  sbm->freeq = create_sb_queue(concurrency);
  if (!sbm->freeq)
  {
    MA_LOG("failed to create free buffer queue");
    mp_destroy(sbm->mp);
    free(sbm);
    return NULL;
  }

  return sbm;
}

struct tcp_send_buffer *sb_init(sb_manager_t sbm, uint32_t init_seq)
{
  struct tcp_send_buffer *buf;

  buf = sb_dequeue(sbm->freeq);
  if (!buf)
  {
    buf = (struct tcp_send_buffer *)malloc(sizeof(struct tcp_send_buffer));
    if (!buf)
    {
      perror("calloc() failed");
      return NULL;
    }
    buf->data = mp_allocate_chunk(sbm->mp);
    if (!buf->data)
    {
      MA_LOG("Failed to fetch memory chunk for data");
      free(buf);
      return NULL;
    }
    sbm->cur_num++;
  }
  buf->head = buf->data;
  buf->head_off = buf->tail_off = 0;
  buf->len = buf->cum_len = 0;
  buf->size = sbm->chunk_size;
  buf->init_seq = buf->head_seq = init_seq;

  return buf;
}

void sb_free(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
  if (!buf)
    return;

  sb_enqueue(sbm->freeq, buf);
}

size_t sb_put(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
  size_t to_put;

  if (len <= 0)
    return 0;

  to_put = MIN(len, buf->size - buf->len);
  if (to_put <= 0)
    return -2;

  if (buf->tail_off + to_put < buf->size)
  {
    memcpy(buf->data + buf->tail_off, data, to_put);
    buf->tail_off += to_put;
  }
  else
  {
    memmove(buf->data, buf->head, buf->len);
    buf->head = buf->data;
    buf->head_off = 0;
    memcpy(buf->head + buf->len, data, to_put);
    buf->tail_off = buf->len + to_put;
  }
  buf->len += to_put;
  buf->cum_len += to_put;

  return to_put;
}

size_t sb_remove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len)
{
  size_t to_remove;

  if (len <= 0)
    return 0;

  to_remove = MIN(len, buf->len);
  if (to_remove <= 0)
    return -2;

  buf->head_off += to_remove;
  buf->head = buf->data + buf->head_off;
  buf->head_seq += to_remove;
  buf->len -= to_remove;

  if (buf->len == 0 && buf->head_off > 0)
  {
    buf->head = buf->data;
    buf->head_off = buf->tail_off = 0;
  }

  return to_remove;
}
