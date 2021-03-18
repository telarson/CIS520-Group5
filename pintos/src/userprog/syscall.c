#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h" /* Imports shutdown_power_off() for use in halt(). */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/palloc.h"


static void syscall_handler (struct intr_frame *);
static int read_usr_stack (void *init_addr, void *result, size_t num_of_bytes);
static int get_user (const uint8_t *uaddr);
struct file* get_file(int fd);


/*Lock to ensure filesystem can only be accessed by one process at a time */
struct lock lock_filesys;

/* mapping of files for use of fd and list elem*/
struct file_entry {
  struct file *file;
  int fd;
  struct list_elem fe;
};

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
      read_usr_stack (stack_pointer + 4, &exit_code, sizeof(exit_code));
      exit (exit_code);
      NOT_REACHED ();
      break;
    }
    case SYS_EXEC:
    {
      void* cmd_line;
      read_usr_stack (stack_pointer + 4, &cmd_line, sizeof(cmd_line));
      int id = exec ((const char*) cmd_line);
      f->eax = (uint32_t) id;
      break;
    }
    case SYS_WAIT:
    {
      int wait_pid;
      read_usr_stack(stack_pointer +4, wait_pid, sizeof(wait_pid));

      f->eax = wait((pid_t) wait_pid);
      break;
    }
    case SYS_CREATE:
    {
      const char *file;
      unsigned initial_size;
      bool result;
      read_usr_stack(stack_pointer + 4, &file, sizeof(file));
      read_usr_stack(stack_pointer + 8, &initial_size, sizeof(initial_size));
      result = create (file, initial_size);
      f->eax = result;
      break;
    }
    case SYS_REMOVE:
    {
      const char *file;
      bool result;
      read_usr_stack (stack_pointer + 4, &file, sizeof(file));
      result = remove (file);
      f->eax = result;
      break;
    }
    case SYS_OPEN:
    {
      const char *file;
      int result;
      read_usr_stack (stack_pointer + 4, &file, sizeof(file));
      result = open (file);
      f->eax = result;
      break;
    }
    case SYS_FILESIZE:
    {
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      f->eax = filesize(fd);
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
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
    	int position;
    	read_usr_stack(stack_pointer + 8, &position, sizeof(position));
      seek (fd, position);
      break;
    }
    case SYS_TELL:
    {
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      f->eax = tell (fd);
      break;
    }
    case SYS_CLOSE:
    {
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      close (fd);
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
  shutdown_power_off(); //from devices/shutdown.h
}

void exit (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  lock_acquire (&lock_filesys);
  pid_t id = process_execute (cmd_line);
  lock_release (&lock_filesys);
  return id;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
{
  bool result;
  lock_acquire (&lock_filesys);
  result = filesys_create (file, initial_size);
  lock_release (&lock_filesys);
  return result;
}

bool
remove (const char *file)
{
  bool result;
  lock_acquire (&lock_filesys);
  result = filesys_remove (file);
  lock_release (&lock_filesys);
  return result;
}

int
open (const char *file)
{
  int result;
  struct file *file_to_open;
  struct file_entry *entry;
  entry->fd = palloc_get_page (0);
  if (!entry->fd)
  {
    return -1;
  }

  lock_acquire (&lock_filesys);
  file_to_open = filesys_open (file);
  if (!file_to_open)
  {
    palloc_free_page (entry->fd);
    lock_release (&lock_filesys);
    return -1;
  }

  file_entry->file = file_to_open;
  struct list *fd_list = &thread_current ()->fd_list;
  if (list_empty(fd_list))
  {
    file_entry->fd = 3;
  } else
  {
    file_entry->fd = (list_entry(list_back(fd_list), struct file_entry, fe)->fd) + 1;
  }
  list_push_back (fd_list, &(file_entry->fe));
  lock_release (&lock_filesys);
  return file_entry->fd;
}

/* get file and return its size (must lock while a file is being used) */
int filesize (int fd)
{
  lock_acquire(&lock_filesys);
  struct file *file = get_file(fd);

  if(file == NULL) {
  	lock_release(&lock_filesys);
  	return -1;
  }

  int size  = file_length(file); //file_length used from filesys/file.h
  lock_release(&lock_filesys);
  return size;
}

/*Read "size" bytes from fd,
  return number of bytes read/ -1 if reading does not occur/ 0 if at end of file*/
int read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&lock_filesys);

  if(fd == 0)
  {
    lock_release(&lock_filesys);
    return (int) input_getc();
  }

  if(fd == 1 || list_empty(&thread_current()->fd))
  {
    lock_release(&lock_filesys);
    return 0;
  }
  
  struct list_elem *temp;

  for (temp = list_front(&thread_current()->fd); temp != NULL; temp = temp->next)
    {
        struct file_entry *t = list_entry (temp, struct file_entry, fe);
        if (t->fd == fd)
        {
          lock_release(&lock_filesys);
          int bytes = (int) file_read(t->file, buffer, size);
          return bytes;
        }
    }


  lock_release(&lock_filesys);
  return -1;
}

/* Changes the next byte to be read or written in open filefdtoposition,
   expressed inbytes from the beginning of the file. Locks/gets file then calls
   file_seek to do the work. */
void seek (int fd, unsigned position)
{
  lock_acquire(&lock_filesys);
  struct file *f = get_file(fd);

  if(f == NULL){
  	lock_release(&lock_filesys);
  	return;
  }
  file_seek(f, position); // from filesys/file.h
  lock_release(&lock_filesys);
}

/* Returns the position of the next byte to be read or written in open filefd,
   expressed in bytes from the beginning of the file. */
unsigned tell (int fd)
{
	lock_acquire(&lock_filesys);
	struct file *f = get_file(fd);

	if(f == NULL) {
		lock_release(&lock_filesys);
		return -1;
	}
	unsigned position = (unsigned) file_tell(f); // from filesys/file.h
	lock_release(&lock_filesys);
	return position;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its openfile descriptors,
    as if by calling this function for each one. */
void close (int fd)
{
  lock_acquire(&lock_filesys);

  if(list_empty(&thread_current()->fd_list)){
  	return;
  }

  struct file *f = get_file(fd);
  struct file_entry *file_entry = list_entry(list_front(&thread_current()->fd_list), struct file_entry, fe);
  
  file_close(f); // from filesys/file.h
  list_remove(&file_entry->fe);
}

/* Writes SIZE bytes from BUFFER to the open file FD. Returns the number of bytes that were written*/
int write (int fd, const void *buffer, unsigned size)
{

  lock_acquire(&lock_filesys);

  //fd == 0, no files present or STDIN
  if (fd == 0 || list_empty(&thread_current()->fd))
  {
    lock_release(&lock_filesys);
    return 0;
  }
  
  //fd == 1, write to STDOUT
  if(fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&lock_filesys);
    return size;
  }
  
  struct list_elem *temp;

  //Check if fd is owened by current process
  for (temp = list_front(&thread_current()->fd); temp != NULL; temp = temp->next)
  {
      struct file_entry *t = list_entry (temp, struct file_entry, fe);

      if (t->fd == fd)
      {
        int bytes_written = (int) file_write(t->file, buffer, size);
        lock_release(&lock_filesys);
        return bytes_written;
      }
  }

  lock_release(&lock_filesys);

  return 0;
}

/* Gets file from the list of files based on descriptor */
struct file* get_file(int fd) {
	struct list_elem *e;

	for(e = list_front(&thread_current()->fd_list); e != NULL; e = e->next) {
		struct file_entry *file_entry = list_entry(e, struct file_entry, fe);
		if(fd == file_entry->fd) {
			return file_entry->file;
		}
	}
	return NULL;
}
