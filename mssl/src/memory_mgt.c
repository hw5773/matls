#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef HUGETABLE
#include <hugetlbfs.h>
#endif
#include "include/logs.h"
#include "include/memory_mgt.h"

typedef struct tag_mem_chunk
{
  int mc_free_chunks;
  struct tag_mem_chunk *mc_next;
} mem_chunk;

typedef mem_chunk *mem_chunk_t;

#ifdef HUGETABLE
typedef enum { MEM_NORMAL, MEM_HUGEPAGE };
#endif

typedef struct mem_pool
{
  uint8_t *mp_startptr;
  mem_chunk_t mp_freeptr;
  int mp_free_chunks;
  int mp_total_chunks;
  int mp_chunk_size;
  int mp_type;
} mem_pool;

mem_pool *mp_create(int chunk_size, size_t total_size, int is_hugepage)
{
  mem_pool_t mp;

  if (chunk_size < sizeof(mem_chunk))
  {
    MA_LOG("The chunk size should be larger");
    return NULL;
  }

  if (chunk_size % 4 != 0)
  {
    MA_LOG("The chunk size should be multiply of 4");
    return NULL;
  }

  if (!(mp = calloc(1, sizeof(mem_pool))))
  {
    perror("calloc failed");
    exit(0);
  }
  mp->mp_type = is_hugepage;
  mp->mp_chunk_size = chunk_size;
  mp->mp_free_chunks = ((total_size + (chunk_size - 1))/chunk_size);
  mp->mp_total_chunks = mp->mp_free_chunks;
  total_size = chunk_size * ((size_t)mp->mp_free_chunks);

#ifndef SYS_MALLOC

#ifdef HUGETABLE
  if (is_hugepage == MEM_HUGEPAGE)
  {
    mp->mp_startptr = get_huge_pages(total_size, NULL);
    if (!mp->mp_startptr)
    {
      MA_LOG("posix mem align failed");
      assert(0);
      free(mp);
      return NULL;
    }
  }
  else
  {
#endif
    int res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
    if (res != 0)
    {
      MA_LOG("posix memalign failed");
      assert(0);
      free(mp);
      return NULL;
    }
#ifdef HUGETABLE
  }
#endif

  if (geteuid() == 0)
  {
    if (mlock(mp->mp_startptr, total_size) < 0)
      MA_LOG("m_lock failed");
  }

  mp->mp_freeptr = (mem_chunk_t)mp->mp_startptr;
  mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
  mp->mp_freeptr->mc_next = NULL;
#endif 

  return mp;
}

void *mp_allocate_chunk(mem_pool_t mp)
{
#ifdef SYS_MALLOC
  return malloc(mp->mp_chunk_size);
#else
  mem_chunk_t p = mp->mp_freeptr;

  if (mp->mp_free_chunks == 0)
  {
    MA_LOG("mp_free_chunks");
    return NULL;
  }
  assert(p->mc_free_chunks > 0 && p->mc_free_chunks <= p->mc_free_chunks);

  p->mc_free_chunks--;
  mp->mp_free_chunks--;

  if (p->mc_free_chunks)
  {
    mp->mp_freeptr = (mem_chunk_t)((uint8_t *)p + mp->mp_chunk_size);
    mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
    mp->mp_freeptr->mc_next = p->mc_next;
  }
  else
  {
    mp->mp_freeptr = p->mc_next;
  }

  return p;
#endif
}

void mp_free_chunk(mem_pool_t mp, void *p)
{
#ifdef SYS_MALLOC
  return free(p);
#else
  mem_chunk_t mcp = (mem_chunk_t)p;

  assert(((uint8_t *)p - mp->mp_startptr) % mp->mp_chunk_size == 0);
  mcp->mc_free_chunks = 1;
  mcp->mc_next = mp->mp_freeptr;
  mp->mp_freeptr = mcp;
  mp->mp_free_chunks++;
#endif
}

