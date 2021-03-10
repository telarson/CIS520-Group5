#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

/*Lock to ensure filesystem can only be accessed by one process at a time */
struct lock lock_filesys;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* Writes SIZE bytes from BUFFER to the open file FD. Returns the number of bytes that were written*/
int write (int fd, const void *buffer, unsigned size)
{

  lock_acquire(&lock_filesys);

  if(fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&lock_filesys);
    return size;
  }

  lock_release(&lock_filesys);

  return 0;
}
