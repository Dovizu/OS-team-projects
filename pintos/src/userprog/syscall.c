#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t* args = ((uint32_t*) f->esp);
  switch(args[0]) {
    case SYS_HALT: {
      shutdown_power_off();
    }
    case SYS_EXIT: {
      f->eax = args[1];
      printf("%s: exit\(%d\)\n", thread_current()->name, args[1]);
      thread_exit();
      break;
    }
    case SYS_EXEC: {
      f->eax=process_execute((const char*)args[1]);
      break;
    }
    case SYS_WAIT: {
      break;
    }
    case SYS_CREATE: {
      break;
    }
    case SYS_REMOVE: {
      break;
    }
    case SYS_OPEN: {
      break;
    }
    case SYS_FILESIZE: {
      break;
    }
    case SYS_READ: {
      break;
    }
    case SYS_WRITE: {
      putbuf((char*)args[2], (int) args[3]);
      break;
    }
    case SYS_SEEK: {
      break;
    }
    case SYS_TELL: {
      break;
    }
    case SYS_CLOSE: {
      break;
    }
    case SYS_NULL: {
      f->eax = args[1] + 1;
      break;
    }

  }
}

// typedef struct fun_desc {
  // cmd_fun_t *fun;
  // char *cmd;
  // char *doc;
// } fun_desc_t;

// fun_desc_t cmd_table[] = {
  // {cmd_help, "?", "show this help menu"},
  // {cmd_quit, "quit", "quit the command shell"},
  // {cmd_cd, "cd", "go into directory specified"},
  // {cmd_bg, "bg", "continue last process in the background"},
  // {cmd_wait, "wait", "wait until all process are done"},
  // {cmd_fg, "fg", "contine last process in the foreground"},
// };
