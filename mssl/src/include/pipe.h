#ifndef __MTCP_PIPE_H_
#define __MTCP_PIPE_H_

#include "mssl_api.h"

int 
pipe_read(mctx_t mctx, int pipeid, char *buf, int len);

int 
pipe_write(mctx_t mctx, int pipeid, const char *buf, int len);

int 
raise_pending_pipe_events(mctx_t mctx, int epid, int pipeid);

int 
pipe_close(mctx_t mctx, int pipeid);

#endif /* __MTCP_PIPE_H_ */
