#ifndef TIMER_H_
#define TIMER_H_

#include "syshead.h"
#include "utils.h"
#include "list.h"

#define timer_dbg(msg, t)                                               \
    do {                                                                \
        print_debug("Timer at %d: "msg": expires %d", tick, t->expires); \
    } while (0)

struct timer {
    struct list_head list;
    int refcnt;
    uint32_t expires;
    int cancelled;
    void *(*handler)(void *);
    void *arg;
    pthread_mutex_t lock;
};

struct timer *timer_add(uint32_t expire, void *(*handler)(void *), void *arg);
void timer_oneshot(uint32_t expire, void *(*handler)(void *), void *arg);
void timer_release(struct timer *t);
void timer_cancel(struct timer *t);
void *timers_start();
int timer_get_tick();
                   
#endif
