#ifndef TIMER_H_
#define TIMER_H_

#include "syshead.h"
#include "list.h"

struct timer {
    struct list_head list;
    uint32_t expires;
    void (*handler)(uint32_t, void *);
    void *arg;
};

void timer_add(uint32_t expire, void (*handler)(uint32_t, void *), void *arg);
void *timers_start();
                   
#endif
