#include <assert.h>

#include "include/mos_api.h"
#include "include/tcp_util.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/tcp_ring_buffer.h"
//#include "include/eventpoll.h"
#include "include/logs.h"
//#include "include/timer.h"
#include "include/ip_in.h"
#include "include/tcp_rb.h"
#include "include/config.h"
#include "include/scalable_event.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define RECOVERY_AFTER_LOSS TRUE
#define SELECTIVE_WRITE_EVENT_NOTIFY TRUE


