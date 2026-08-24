#pragma once

#include <pthread.h>
#include <time.h>

#define DB_INITIALIZED_MAGIC 0x1356
#define DB_VMA_SIZE ((size_t)4096 * 4294967296ULL)

/* Per-row capability key. A row is reused later by presenting its key;
 * the key is minted by the server with a CSPRNG on creation. 256 bits. */
#define DB_KEY_SIZE 32

/* RPC commands (the `command` field; 0 means idle/done). */
enum {
    DB_CMD_NONE   = 0,
    DB_CMD_CREATE = 1,   /* allocate a fresh row and mint a key       */
    DB_CMD_REUSE  = 2,   /* look up the live row matching a given key  */
};

/* RPC result status. */
enum {
    DB_STATUS_OK    = 0,
    DB_STATUS_NOKEY = 1, /* reuse: no live row matches that key        */
};

typedef struct {
    time_t created_at;
    unsigned char key[DB_KEY_SIZE];  /* capability key for this row    */
    char data[128];
} Row;   /* 168 bytes: packed so ~24 rows share a page, keeping the row table
          * compact and cache/TLB-friendly for the server's lookup loop. */

typedef struct {
    pthread_mutex_t request_lock;
    pthread_mutex_t allocation_lock;
    pthread_cond_t allocation_condition;
    pthread_cond_t return_condition;
    unsigned command;                 /* DB_CMD_* (0 == done/idle)     */
    int status;                       /* DB_STATUS_* result            */
    unsigned char key[DB_KEY_SIZE];   /* in: reuse key; out: minted key*/
    void *ret;                        /* out: offset of the row's data */
} RPC;

typedef struct {
    unsigned initialized;
    RPC rpc;
    unsigned total_rows;
    Row rows[];
} Database;
