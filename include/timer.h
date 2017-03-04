#ifndef TIMER_H_
#define TIMER_H_

#include "syshead.h"
#include "utils.h"
#include "list.h"

#define timer_dbg(msg, t)                                               \
    do {                                                                \
        print_debug("Timer at %d: "msg": expires %d\n", tick, t->expires); \
    } while (0)

struct timer {
    struct list_head list;
    int refcnt;
    uint32_t expires;
    int cancelled;
    void (*handler)(uint32_t, void *);
    void *arg;
};

struct timer *timer_add(uint32_t expire, void (*handler)(uint32_t, void *), void *arg);
void timer_release(struct timer *t);
void timer_cancel(struct timer *t);
void *timers_start();
int timer_get_tick();
                   
#endif
