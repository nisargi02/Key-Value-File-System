/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * logfs.c
 */

#include <pthread.h>
#include "device.h"
#include "logfs.h"

/**
 * Needs:
 *   pthread_create()
 *   pthread_join()
 *   pthread_mutex_init()
 *   pthread_mutex_destroy()
 *   pthread_mutex_lock()
 *   pthread_mutex_unlock()
 *   pthread_cond_init()
 *   pthread_cond_destroy()
 *   pthread_cond_wait()
 *   pthread_cond_signal()
 */

/* research the above Needed API and design accordingly */

#define W_BLOCKS 32
#define R_BLOCKS 256

struct logfs {
    struct device *device;
    int block_size;
    
    char *buffer; /* block aligned */
    char *buffer_; /* for malloc and free */
    int head;
    int tail;
    int buffer_size;
    int buffer_filled;
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t data_avail;
    pthread_cond_t space_avail;
    int done;
    int device_offset;
    struct RBlock *read_buffer[R_BLOCKS];
};

struct RBlock {
    int valid;
    int block_id;
    char *block;
    char *block_;
};

void *worker(void *args) {
    struct logfs *logfs = (struct logfs *) args;
    int block_id, r_index;

    pthread_mutex_lock(&logfs->lock);

    while(!logfs->done) {
        while(logfs->buffer_filled < logfs->block_size) {
            if(logfs->done) {
                pthread_mutex_unlock(&logfs->lock);
                pthread_exit(NULL);
            }
            pthread_cond_wait(&logfs->data_avail, &logfs->lock);
        }

        block_id = logfs->device_offset / logfs->block_size;
        r_index = block_id % R_BLOCKS;

        if(logfs->read_buffer[r_index]->block_id == block_id) {
            logfs->read_buffer[r_index]->valid = 0;
        }

        if(-1 == device_write(logfs->device, logfs->buffer + logfs->tail, logfs->device_offset, logfs->block_size)) {
            TRACE("Error in device write");
            EXIT(0);
        }

        logfs->tail = (logfs->tail + logfs->block_size) % logfs->buffer_size;
        logfs->buffer_filled -= logfs->block_size;
        logfs->device_offset += logfs->block_size;

        if(logfs->head == logfs->tail || (logfs->tail == 0 && logfs->head == logfs->buffer_size)) {
            pthread_cond_signal(&logfs->space_avail);
        }
    }
    pthread_exit(NULL);
}

void write_to_disk(struct logfs *logfs) {
    int len;
    pthread_mutex_lock(&logfs->lock);

    len = logfs->block_size - (logfs->head % logfs->block_size);
    logfs->head += len;
    logfs->buffer_filled += len;

    pthread_cond_signal(&logfs->data_avail);
    pthread_cond_wait(&logfs->space_avail, &logfs->lock);

    logfs->head -= len;
    logfs->tail = logfs->tail == 0 
                    ? logfs->head - (logfs->head % logfs->block_size)
                    : logfs->tail - logfs->block_size;
    logfs->buffer_filled = logfs->head % logfs->block_size;
    logfs->device_offset -= logfs->block_size;
    pthread_mutex_unlock(&logfs->lock);
}

struct logfs *logfs_open(const char *pathname) {
    struct logfs *logfs =(struct logfs *) malloc(sizeof(struct logfs));
    int i;

    if(logfs == NULL) {
        printf("Error with logfs malloc\n");
        EXIT(0);
    }

    if ((logfs->device = device_open(pathname)) == NULL)  {
        printf("Error with device open\n");
        return NULL;
    }

    logfs->block_size = device_block(logfs->device);
    logfs->buffer_size = logfs->block_size * W_BLOCKS;
    logfs->buffer_ = (char *) malloc(logfs->buffer_size + logfs->block_size); 
    logfs->buffer = (char *) memory_align(logfs->buffer_, logfs->block_size);
    memset(logfs->buffer, 0, logfs->buffer_size);
    logfs->done = 0;
    logfs->head = logfs->tail = 0;
    logfs->buffer_filled = 0;
    logfs->device_offset = 0;

    for(i = 0; i < R_BLOCKS; i++) {
        logfs->read_buffer[i] = (struct RBlock *) malloc(sizeof(struct RBlock));
        logfs->read_buffer[i]->block_ = (char *) malloc(2 * logfs->block_size);
        logfs->read_buffer[i]->block = (char *) memory_align(logfs->read_buffer[i]->block_, logfs->block_size);
        logfs->read_buffer[i]->block_id = -1;
        logfs->read_buffer[i]->valid = 0;
    }

    pthread_create(&logfs->worker, NULL, &worker, logfs);
    pthread_mutex_init(&logfs->lock, NULL);
    pthread_cond_init(&logfs->data_avail, NULL);
    pthread_cond_init(&logfs->space_avail, NULL);

    return logfs;
}


int logfs_read(struct logfs *logfs, void *buf, uint64_t off, size_t len) {
    int block_id, r_index, r_start, r_len;
    size_t r_status = 0;

    write_to_disk(logfs);

    block_id = off / logfs->block_size;
    r_index = block_id % R_BLOCKS;
    r_start = off % logfs->block_size;
    r_len = MIN(len, (size_t)logfs->block_size - r_start);

    while(r_status < len) {
        if(logfs->read_buffer[r_index] != NULL &&
           logfs->read_buffer[r_index]->valid &&
           logfs->read_buffer[r_index]->block_id == block_id) {
            memcpy((char *) buf + r_status, logfs->read_buffer[r_index]->block + r_start, r_len);
        }
        else {
            if (-1 == device_read(logfs->device, logfs->read_buffer[r_index]->block, block_id * logfs->block_size, logfs->block_size)) {
                TRACE("Read Error");
                EXIT(0);
                return -1;
            }
            logfs->read_buffer[r_index]->valid = 1;
            logfs->read_buffer[r_index]->block_id = block_id;
            memcpy((char *) buf + r_status, logfs->read_buffer[r_index]->block + r_start, r_len);
        }

        r_status += r_len;
        block_id++;
        r_index = block_id % R_BLOCKS;
        r_start = 0;
        r_len = MIN((size_t)logfs->block_size, len - r_status);
    }
    return 0;
}

int logfs_append(struct logfs *logfs, const void *buf, uint64_t len) {
    uint64_t write_len = len;
    pthread_mutex_lock(&logfs->lock);

    while(write_len > 0) {
        logfs->buffer_filled++;
        memcpy(logfs->buffer + logfs->head, (char *) buf + (len - write_len), 1);
        write_len--;
        logfs->head = (logfs->head + 1) % (logfs->buffer_size);
        pthread_cond_signal(&logfs->data_avail);
    }
    pthread_mutex_unlock(&logfs->lock);
    return 0;
}

void logfs_close(struct logfs *logfs) {
    int i;
    write_to_disk(logfs);
    pthread_mutex_lock(&logfs->lock);
    logfs->done = 1;
    pthread_mutex_unlock(&logfs->lock);
    pthread_cond_signal(&logfs->data_avail);

    pthread_join(logfs->worker, NULL);
    pthread_mutex_destroy(&logfs->lock);
    pthread_cond_destroy(&logfs->data_avail);
    pthread_cond_destroy(&logfs->space_avail);

    for(i = 0; i < R_BLOCKS; i++) {
        FREE(logfs->read_buffer[i]->block_);
        FREE(logfs->read_buffer[i]);
    }

    FREE(logfs->buffer_);
    device_close(logfs->device);
    FREE(logfs);
}