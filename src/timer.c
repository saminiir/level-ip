#include "syshead.h"
#include "timer.h"
#include "socket.h"

static LIST_HEAD(timers);
static int tick = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void timer_free(struct timer *t)
{
    if (pthread_mutex_trylock(&lock) != 0) {
        perror("Timer free mutex lock");
        return;
    }

    list_del(&t->list);
    free(t);

    pthread_mutex_unlock(&lock);
}

static struct timer *timer_alloc()
{
    struct timer *t = calloc(sizeof(struct timer), 1);

    return t;
}

static void timers_tick()
{
    struct list_head *item, *tmp = NULL;
    struct timer *t = NULL;

    list_for_each_safe(item, tmp, &timers) {
        t = list_entry(item, struct timer, list);

        if (!t->cancelled && t->expires < tick) {
            t->cancelled = 1;
            t->handler(tick, t->arg);
        }

        if (t->cancelled && t->refcnt == 0) {
            timer_free(t);
        }
    }
}

struct timer *timer_add(uint32_t expire, void (*handler)(uint32_t, void *), void *arg)
{
    struct timer *t = timer_alloc();

    t->refcnt = 1;
    t->expires = tick + expire;
    t->cancelled = 0;

    if (t->expires < tick) {
        print_err("ERR: Timer expiry integer wrap around\n");
    }
     
    t->handler = handler;
    t->arg = arg;

    pthread_mutex_lock(&lock);
    list_add_tail(&t->list, &timers);
    pthread_mutex_unlock(&lock);
    
    return t;
}

void timer_release(struct timer *t)
{
    if (pthread_mutex_lock(&lock) != 0) {
        perror("Timer release lock");
        return;
    };

    if (t) {
        t->refcnt--;
    }
    
    pthread_mutex_unlock(&lock);
}

void timer_cancel(struct timer *t)
{
    if (pthread_mutex_lock(&lock) != 0) {
        perror("Timer cancel lock");
        return;
    };

    if (t) {
        t->refcnt--;
        t->cancelled = 1;
    }
    
    pthread_mutex_unlock(&lock);
}

void *timers_start()
{
    while (1) {
        if (usleep(1000) != 0) {
            perror("Timer usleep");
        }

        tick++;
        timers_tick();

        if (tick % 5000 == 0) {
            socket_debug();
        } 
    }
}

int timer_get_tick()
{
    return tick;
}
