#include "userprog/syscall.h"
#include <stdlib.h>
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
struct file * get_file_struct(int fd);
struct file_description * find_fd_struct(int fd);

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
  exit_if_invalid((void*)args, f);
  
  switch(args[0]) {
    case SYS_HALT: {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: {
      uint32_t exitcode = get_arg(f, args, 1);
      exit_handler(f, exitcode);
      break;
    }
    case SYS_EXEC: {
      char * file_name = (char*)get_arg(f, args, 1);
      exit_if_invalid ((void*)file_name, f);
      char * fn_copy = palloc_get_page (0);
      strlcpy (fn_copy, file_name, PGSIZE);
      f->eax=process_execute(fn_copy);
      palloc_free_page(fn_copy);
      break;
    }
    case SYS_WAIT: {    
      tid_t tid = (tid_t) get_arg(f, args, 1);
      f->eax = process_wait(tid);
      break;
    }
    case SYS_CREATE: {
      char * file = (char *) get_arg(f, args, 1);
      off_t initial_size = (off_t) get_arg(f, args, 2);
      exit_if_invalid ((void*)file, f);
      lock_acquire(&filesys_lock);
      f->eax = filesys_create(file,initial_size);
      lock_release(&filesys_lock);        
      break;
    }
    case SYS_REMOVE: {
      char * file = (char *) get_arg(f, args, 1);
      exit_if_invalid ((void*)file, f);
      lock_acquire(&filesys_lock);          
      f->eax = filesys_remove(file);
      lock_release(&filesys_lock);        
      break;
    }
    case SYS_OPEN: {
      const char * file = (char *) get_arg(f, args, 1);
      exit_if_invalid ((void*)file, f);
      
      lock_acquire(&filesys_lock);      
      struct file * newFile = filesys_open(file);     
      if(newFile==NULL){
        f->eax = -1;
      } else {
        struct thread *cur_thread = thread_current();
        struct file_description *newFD;
        newFD = (struct file_description*)malloc(sizeof(struct file_description));
        lock_acquire(&(cur_thread->fd_num_lock));
        newFD->fd = cur_thread->next_fd_num;
        cur_thread->next_fd_num = cur_thread->next_fd_num +1;
        lock_release(&cur_thread->fd_num_lock);
        newFD->f = newFile;
        list_push_front(&(cur_thread->file_descriptions), &(newFD->fd_list_elem));
        f->eax = newFD->fd;
      }
      lock_release(&filesys_lock); 
      break;
    }
    case SYS_FILESIZE: {
      int fd = (int) get_arg(f, args, 1);
      lock_acquire(&filesys_lock);      
      struct file *file = get_file_struct(fd);
      if (file) {  
        f->eax = file_length(file);  
        lock_release(&filesys_lock);         
      } else {
        lock_release(&filesys_lock); 
        exit_handler(f,-1);
      }
      break;
    }
    case SYS_READ: {
      int fd = (int) get_arg(f, args, 1);
      void * buffer = (void*) get_arg(f, args, 2);
      unsigned size = (unsigned) get_arg(f, args, 3);
      exit_if_invalid (buffer, f);
      exit_if_invalid ((void*)((char*)buffer + size), f);
      if (fd == 0) {
        int read = 0;
        while (read <= size) {
          ((char*) buffer)[read] = input_getc((char*) buffer, (int) size);
          read += 1;
        }
        f->eax = size;
      } else {
        lock_acquire(&filesys_lock); 
        struct file *file = get_file_struct(fd);
        if (file) {          
          f->eax = file_read(file, buffer, size); 
          lock_release(&filesys_lock);           
        } else {
          lock_release(&filesys_lock);   
          exit_handler(f,-1);
        }
      }
      break;
    }
    case SYS_WRITE: {
      int fd = (int) get_arg(f, args, 1);
      void * buffer = (void *) get_arg(f, args, 2);
      unsigned size = (unsigned) get_arg(f, args, 3);
      exit_if_invalid (buffer, f);
      exit_if_invalid ((void*)((char*)buffer + size), f);
      if (fd == 1) {
        putbuf((char*) buffer, (int) size);
        f->eax = size;
      } else {
        lock_acquire(&filesys_lock);
        struct file *file = get_file_struct(fd);
        if (file) {          
          f->eax = file_write (file, buffer, size) ;
          lock_release(&filesys_lock);          
        } else {
          lock_release(&filesys_lock);     
          exit_handler(f,-1);
        }
      }
      break;
    }
    case SYS_SEEK: {
      int fd = (int) get_arg(f, args, 1);
      off_t position = (off_t) get_arg(f, args, 2);
      struct file *file = get_file_struct(fd);
      file_seek(file, position);
      /*
      unsigned position = (unsigned) get_arg(f, args, 2);
      lock_acquire(&filesys_lock); 
      struct file *file = get_file_struct(fd);
      if (file){
        file_seek (file, position);
        lock_release(&filesys_lock);  
      } else {
        lock_release(&filesys_lock);  
        exit_handler(f, -1);
      }
      fd_elem->position = position;
      */
      break;
    }
    case SYS_TELL: {
      int fd = (int) get_arg(f, args, 1);
      lock_acquire(&filesys_lock); 
      struct file *file = get_file_struct(fd);
      //f->eax = file_tell(file);
      /*
      int fd = (int) get_arg(f, args, 1);
      struct file_description *fd_elem = find_fd_struct(fd);
      if(!fd_elem){
        exit_handler(f, -1);
        f->eax = -1;
      }       
      f->eax = fd_elem->position;
      */
      if (file){
        f->eax = file_tell (file);
        lock_release(&filesys_lock);  
      } else {
        lock_release(&filesys_lock); 
        exit_handler(f, -1);
      }
      break;
    }
    case SYS_CLOSE: {
      int fd = (int) get_arg(f, args, 1);
      lock_acquire(&filesys_lock);
      struct file_description *fd_elem = find_fd_struct(fd);
      if(!fd_elem){
        lock_release(&filesys_lock);
        exit_handler(f, -1);
      } else {       
        file_close(fd_elem->f);
        list_remove(&fd_elem->fd_list_elem);
        free(fd_elem);
        lock_release(&filesys_lock);
      }
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
  exit_if_invalid ((void*)(&args[index]), f); 
  return args[index];
}

struct file *
get_file_struct(int fd) {
  struct file_description * file_des = find_fd_struct(fd);
  if (file_des) {
    return file_des->f;
  }
  return NULL;
}

void
closefd() {
  struct list_elem *elem;
  struct thread *t = thread_current();
  for(elem = list_begin(&t->file_descriptions); elem != list_end(&t->file_descriptions); elem = list_next(elem)){
    struct file_description *fd_elem = list_entry(elem, struct file_description, fd_list_elem);
    lock_acquire(&filesys_lock);
    file_close(fd_elem->f);
    list_remove(&fd_elem->fd_list_elem);
    free(fd_elem);
    lock_release(&filesys_lock);
    
  }
}

void
exit_handler(struct intr_frame *f, int exit_code) {
  f->eax = exit_code;
  thread_current ()->wait_status->exit_status = exit_code;
  printf ("%s: exit(%d)\n", thread_current ()->name, exit_code);
  thread_exit ();
}


struct file_description *
find_fd_struct(int fd){
  struct list_elem *elem;
  struct thread *t = thread_current();
  for(elem = list_begin(&t->file_descriptions); elem != list_end(&t->file_descriptions); elem = list_next(elem)){
    struct file_description *fd_elem = list_entry(elem, struct file_description, fd_list_elem);
    if(fd_elem->fd == fd){
      return fd_elem;
    }
  }
  return NULL;
}
