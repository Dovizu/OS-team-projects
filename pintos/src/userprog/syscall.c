#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
uint32_t get_arg (struct intr_frame *f, uint32_t* args, int index);
void exit_handler(struct intr_frame *f, uint32_t exit_code);
struct file * get_file_struct(int fd);
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* Used to clean up the code in syscall_handler */
void
exit_if_invalid (void *ptr, struct intr_frame *f) 
{
  int pointer_is_valid = ptr && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) && is_vaddr_valid(ptr);
  if (!pointer_is_valid) {
    exit_handler(f, -1);
  }
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t* args = ((uint32_t*) f->esp);
  exit_if_invalid(args, f);
  
  switch(args[0]) {
    case SYS_HALT: {
      shutdown_power_off();
    }
    case SYS_EXIT: {
      uint32_t exitcode = get_arg(f, args, 1);
      exit_handler(f, exitcode);
      break;
    }
    case SYS_EXEC: {
      char * file_name = (const char*)get_arg(f, args, 1);
      if(is_vaddr_valid(file_name)){
        f->eax=process_execute(file_name);
      }
      break;
    }
    case SYS_WAIT: {    
      tid_t tid = (tid_t) get_arg(f, args, 1);
      f->eax = process_wait(tid);
      break;
    }
    case SYS_CREATE: {
      char * file = (const char *) get_arg(f, args, 1);
      if (file == NULL) {
        f->eax = -1;
      } else {
        off_t initial_size = (off_t) get_arg(f, args, 2);
        f->eax = filesys_create(file,initial_size);
      }
      break;
    }
    case SYS_REMOVE: {
      char * file = (const char *) get_arg(f, args, 1);
      f->eax = filesys_remove(file);
      break;
    }
    case SYS_OPEN: {
      const char * file = (const char *) get_arg(f, args, 1);
      struct thread *cur_thread = thread_current();
      struct file_description *newFD = malloc(sizeof(struct file_description));
      lock_acquire(&(cur_thread->fd_num_lock));
      newFD->fd = cur_thread->next_fd_num;
      cur_thread->next_fd_num = cur_thread->next_fd_num +1;
      lock_release(&cur_thread->fd_num_lock);
      struct file * newFile = filesys_open(file);
      if(newFile==NULL){
        f->eax = -1;
      } else {
        newFD->f = newFile;
        list_push_front(&(cur_thread->file_descriptions), &(newFD->fd_list_elem));
        f->eax = newFD->fd;
      }
      break;
    }
    case SYS_FILESIZE: {
      int fd = (int) get_arg(f, args, 1);
      struct file *file = get_file_struct(fd);
      f->eax = file_length(file);
      
      break;
    }
    case SYS_READ: {
      int fd = (int) get_arg(f, args, 1);
      void * buffer = (void *) get_arg(f, args, 2);
      unsigned size = (unsigned) get_arg(f, args, 3);
      if (fd == 0) {
        f->eax = input_getc((char*) buffer, (int) size);
      } else {
        struct file *file = get_file_struct(fd);
        f->eax = file_read(file, buffer, size); 
      }
      break;
    }
    case SYS_WRITE: {
      int fd = (int) get_arg(f, args, 1);
      void * buffer = (void *) get_arg(f, args, 2);
      unsigned size = (unsigned) get_arg(f, args, 3);
      if (fd == 1) {
        putbuf((char*) buffer, (int) size);
        f->eax = size;
      } else {
        struct file *file = get_file_struct(fd);
        f->eax = file_write (file, buffer, size) ;
      }
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
      int num = (int) get_arg(f, args, 1);
      f->eax = num + 1;
      break;
    }

  }
}

uint32_t
get_arg (struct intr_frame *f, uint32_t* args, int index) 
{

  int pointer_is_valid = &args[index] && is_user_vaddr(&args[index]) && pagedir_get_page(thread_current()->pagedir, &args[index]);
  if (!pointer_is_valid) {
    exit_handler(f, -1);
    return -1;
  }
  return args[index];
}

struct file *
get_file_struct(int fd) {
  struct thread *cur_thread = thread_current();
  struct list_elem *elem;
  for(elem = list_begin(&cur_thread->file_descriptions); elem != list_end(&cur_thread->file_descriptions); elem = list_next(elem)){
    struct file_description * file_des = list_entry(elem, struct file_description, fd_list_elem);
    if (file_des->fd == fd) {
      return file_des->f;
    }
	}
  return NULL;
}

void
exit_handler(struct intr_frame *f, uint32_t exit_code) {
  f->eax = exit_code;
  thread_current ()->wait_status->exit_status = exit_code;
  printf ("%s: exit(%d)\n", thread_current ()->name, exit_code);
  thread_exit ();
}

