#ifndef _WAIT_H
#define _WAIT_H

#include "syshead.h"

struct wait_lock {
    pthread_cond_t ready;
    pthread_mutex_t lock;
};

static inline int wait_init(struct wait_lock *w) {
    pthread_cond_init(&w->ready, NULL);
    pthread_mutex_init(&w->lock, NULL);

    return 0;
};

static inline int wait_wakeup(struct wait_lock *w) {
    pthread_mutex_lock(&w->lock);

    pthread_cond_signal(&w->ready);

    pthread_mutex_unlock(&w->lock);
    return 0;
};

static inline int wait_sleep(struct wait_lock *w) {
    pthread_mutex_lock(&w->lock);

    pthread_cond_wait(&w->ready, &w->lock);

    pthread_mutex_unlock(&w->lock);
    
    return 0;
};

static inline void wait_free(struct wait_lock *w) {
    wait_wakeup(w);
    
    pthread_mutex_destroy(&w->lock);
    pthread_cond_destroy(&w->ready);
};

#endif
