#ifndef __TCP_IN_H__
#define __TCP_IN_H__

#define HZ                  1000
#define TIME_TICK           (1000000 / HZ)
#define TIMEVAL_TO_TS(t)    (uint32_t)((t)->tv_sec * HZ + ((t)->tv_usec / TIME_TICK))

#define TS_TO_USEC(t)       ((t) * TIME_TICK)
#define TS_TO_MSEC(t)       (TS_TO_USEC(t) / 1000)

#define USEC_TO_TS(t)       ((t) / TIME_TICK)
#define MSEC_TO_TS(t)       (USEC_TO_TS((t) * 1000))

#define SEC_TO_USEC(t)      ((t) * 1000000)
#define SEC_TO_MSEC(t)      ((t) * 1000)
#define MSEC_TO_USEC(t)     ((t) * 1000)
#define USEC_TO_SEC(t)      ((t) / 1000000)

#define TCP_TIMEWAIT        0
#define TCP_INITIAL_RTO     (MSEC_TO_USEC(500) / TIME_TICK)
#define TCP_FIN_RTO         (MSEC_TO_USEC(500) / TIME_TICK)
#define TCP_TIMEOUT         (MSEC_TO_USEC(30) / TIME_TICK)

#define TCP_MAX_RTX         16
#define TCP_MAX_SYN_RETRY   7
#define TCP_MAX_BACKOFF     7

#endif /* __TCP_IN_H__ */
