#ifndef __MEMORY_MGT_H_
#define __MEMORY_MGT_H_

struct mem_pool;
typedef struct mem_pool* mem_pool_t;

/* create a memory pool with a chunk size and total size
   an return the pointer to the memory pool */
mem_pool_t mp_create(int chunk_size, size_t total_size, int is_hugepage);

/* allocate one chunk */
void *mp_allocate_chunk(mem_pool_t mp);

/* free one chunk */
void mp_free_chunk(mem_pool_t mp, void *p);

/* destroy the memory pool */
void mp_destroy(mem_pool_t mp);

/* return the number of free chunks */
int mp_get_free_chunks(mem_pool_t mp);

#endif /* __MEMORY_MGT_H_ */
