#include "syshead.h"
#include "timer.h"
#include "socket.h"

static LIST_HEAD(timers);
static int tick = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

#ifdef DEBUG_TIMER
static void timer_debug()
{
    struct list_head *item;
    int cnt = 0;

    pthread_mutex_lock(&lock);

    list_for_each(item, &timers) {
        cnt++;
    }

    pthread_mutex_unlock(&lock);

    print_debug("TIMERS: Total amount currently %d", cnt);
}
#else
static void timer_debug()
{
    return;
}
#endif

static void timer_free(struct timer *t)
{
    pthread_mutex_destroy(&t->lock);
    free(t);
}

static struct timer *timer_alloc()
{
    struct timer *t = calloc(sizeof(struct timer), 1);
    pthread_mutex_init(&t->lock, NULL);

    return t;
}

static void timers_tick()
{
    struct list_head *item, *tmp = NULL;
    struct timer *t = NULL;
    int rc = 0;

    if ((rc = pthread_mutex_lock(&lock)) != 0) {
        print_err("Timer tick lock not acquired: %s\n", strerror(rc));
        return;
    };
    
    list_for_each_safe(item, tmp, &timers) {
        if (!item) continue;
        
        t = list_entry(item, struct timer, list);

        if ((rc = pthread_mutex_trylock(&t->lock)) != 0) {
            if (rc != EBUSY) {
                print_err("Timer free mutex lock: %s\n", strerror(rc));
            }
            
            continue;
        }

        if (!t->cancelled && t->expires < tick) {
            t->cancelled = 1;
            pthread_t th;
            pthread_create(&th, NULL, t->handler, t->arg);
        }

        if (t->cancelled && t->refcnt == 0) {
            list_del(&t->list);
            pthread_mutex_unlock(&t->lock);

            timer_free(t);
        } else {
            pthread_mutex_unlock(&t->lock);
        }
    }

    pthread_mutex_unlock(&lock);
}

void timer_oneshot(uint32_t expire, void *(*handler)(void *), void *arg)
{
    struct timer *t = timer_alloc();

    int tick = timer_get_tick();

    t->refcnt = 0;
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
}

struct timer *timer_add(uint32_t expire, void *(*handler)(void *), void *arg)
{
    struct timer *t = timer_alloc();

    int tick = timer_get_tick();

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
    int rc = 0;

    if (!t) return;
    
    if ((rc = pthread_mutex_lock(&t->lock)) != 0) {
        print_err("Timer release lock: %s\n", strerror(rc));
        return;
    };

    t->refcnt--;
    
    pthread_mutex_unlock(&t->lock);
}

void timer_cancel(struct timer *t)
{
    int rc = 0;
    
    if (!t) return;

    if ((rc = pthread_mutex_lock(&t->lock)) != 0) {
        print_err("Timer cancel lock: %s\n", strerror(rc));
        return;
    };

    t->refcnt--;
    t->cancelled = 1;
        
    pthread_mutex_unlock(&t->lock);
}

void *timers_start()
{
    while (1) {
        if (usleep(10000) != 0) {
            perror("Timer usleep");
        }

        pthread_rwlock_wrlock(&rwlock);
        tick += 10;
        pthread_rwlock_unlock(&rwlock);
        timers_tick();

        if (tick % 5000 == 0) {
            socket_debug();
            timer_debug();
        } 
    }
}

int timer_get_tick()
{
    int copy = 0;
    pthread_rwlock_rdlock(&rwlock);
    copy = tick;
    pthread_rwlock_unlock(&rwlock);
    return copy;
}
