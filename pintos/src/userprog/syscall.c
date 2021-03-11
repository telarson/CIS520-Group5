#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static int read_usr_stack (void *init_addr, void *result, size_t num_of_bytes);
static int get_user (const uint8_t *uaddr);


/*Lock to ensure filesystem can only be accessed by one process at a time */
struct lock lock_filesys;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*reads system call number from the top of the user stack and
  dispatches to the appropriate handler based on constants defined
  in syscall-nr.h*/
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *stack_pointer = f->esp;
  int syscall_num;

  read_usr_stack (stack_pointer, &syscall_num, 4);
  printf ("system call!\n");

  switch (syscall_num)
  {
    case SYS_HALT:
    {
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      int exit_code;
      read_usr_stack (stack_pointer + 4, &exit_code, 4);
      exit (exit_code);
      NOT_REACHED ();
      break;
    }
    case SYS_EXEC:
    {
      exec ();
      break;
    }
    case SYS_WAIT:
    {
      wait ();
      break;
    }
    case SYS_CREATE:
    {
      create ();
      break;
    }
    case SYS_REMOVE:
    {
      remove ();
      break;
    }
    case SYS_OPEN:
    {
      open ();
      break;
    }
    case SYS_FILESIZE:
    {
      filesize ();
      break;
    }
    case SYS_READ:
    {
      read ();
      break;
    }
    case SYS_WRITE:
    {
      write ();
      break;
    }
    case SYS_SEEK:
    {
      seek ();
      break;
    }
    case SYS_TELL:
    {
      tell ();
      break;
    }
    case SYS_CLOSE:
    {
      close ();
      break;
    }
  }
}

static int
read_usr_stack (void *init_addr, void *result, size_t num_of_bytes)
{
  int32_t value;
  for (size_t i = 0; i < num_of_bytes; i++)
  {
    value = get_user (init_addr + i);
    *(char*)(result + i) = value & 0xff;
  }
  return (int)num_of_bytes;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr){
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
   : "=&a" (result) : "m" (*uaddr));
  return result;
}

void halt (void)
{
  thread_exit ();
}

void exit (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

void exec (void)
{
  thread_exit ();
}

void wait (void)
{
  thread_exit ();
}

void create (void)
{
  thread_exit ();
}

void remove (void)
{
  thread_exit ();
}

void open (void)
{
  thread_exit ();
}

void filesize (void)
{
  thread_exit ();
}

void read (void)
{
  thread_exit ();
}


void seek (void)
{
  thread_exit ();
}

void tell (void)
{
  thread_exit ();
}

void close (void)
{
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
