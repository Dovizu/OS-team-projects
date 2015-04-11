#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);
void exit_handler(struct intr_frame *f, int exit_code) ;
#endif /* userprog/syscall.h */
