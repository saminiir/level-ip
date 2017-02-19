#include "syshead.h"
#include "timer.h"

static LIST_HEAD(timers);
static int tick = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void timer_free(struct timer *t)
{
    pthread_mutex_lock(&lock);
    list_del(&t->list);
    pthread_mutex_unlock(&lock);
    free(t);
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

        if (t->expires < tick) {
            t->handler(tick, t->arg);

            if (t) {
                timer_free(t);
            }
        }
    }
}

struct timer *timer_add(uint32_t expire, void (*handler)(uint32_t, void *), void *arg)
{
    struct timer *t = timer_alloc();

    t->expires = tick + expire;
    t->handler = handler;
    t->arg = arg;

    pthread_mutex_lock(&lock);
    list_add_tail(&t->list, &timers);
    pthread_mutex_unlock(&lock);
    
    timer_dbg("add", t);

    return t;
}

void *timers_start()
{
    while (1) {
        if (usleep(1000) !=0) {
            perror("Timer usleep");
        }

        tick++;
        timers_tick();
    }
}
