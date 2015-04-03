#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool is_vaddr_valid(void *vaddr);
bool is_vaddr_range_valid(void *vaddr, size_t size);

#endif /* userprog/process.h */
