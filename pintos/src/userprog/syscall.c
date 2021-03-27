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
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*reads system call number from the top of the user stack and
  dispatches to the appropriate handler based on constants defined
  in syscall-nr.h*/
static void
syscall_handler (struct intr_frame *f)
{
  void *stack_pointer = f->esp;
  int syscall_num;

  printf ("system call!\n");
  read_usr_stack (stack_pointer, &syscall_num, 4);
  printf ("Entering switch!\n");
  
  switch (syscall_num)
  {
    case SYS_HALT:
    {
      printf ("halt!\n");
      halt ();
      break;
    }
    case SYS_EXIT:
    {
      printf ("exit!\n");
      int exit_code;
      read_usr_stack (stack_pointer + 4, &exit_code, sizeof(exit_code));
      exit (exit_code);
      NOT_REACHED ();
      break;
    }
    case SYS_EXEC:
    {
      printf ("exec!\n");
      void* cmd_line;
      read_usr_stack (stack_pointer + 4, &cmd_line, sizeof(cmd_line));
      int id = exec ((const char*) cmd_line);
      f->eax = (uint32_t) id;
      break;
    }
    case SYS_WAIT:
    {
      printf ("wait!\n");
      pid_t wait_pid;
      read_usr_stack(stack_pointer + 4, &wait_pid, sizeof(wait_pid));

      int result = wait(wait_pid);
      f->eax = (uint32_t) result;
      break;
    }
    case SYS_CREATE:
    {
      printf ("create!\n");
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
      printf ("remove!\n");
      const char *file;
      bool result;
      read_usr_stack (stack_pointer + 4, &file, sizeof(file));
      result = remove (file);
      f->eax = result;
      break;
    }
    case SYS_OPEN:
    {
      printf ("open!\n");
      const char *file;
      int result;
      read_usr_stack (stack_pointer + 4, &file, sizeof(file));
      result = open (file);
      f->eax = result;
      break;
    }
    case SYS_FILESIZE:
    {
      printf ("filesize!\n");
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      f->eax = filesize(fd);
      break;
    }
    case SYS_READ:
    {
      printf ("read!\n");
      int fd;
      void * buff;
      unsigned int size;

      read_usr_stack(stack_pointer +4, &fd, sizeof(fd));
      read_usr_stack(stack_pointer +8, &buff, sizeof(buff));
      read_usr_stack(stack_pointer + 12, &size, sizeof(size));

      f->eax = read(fd, buff, size);
      break;
    }
    case SYS_WRITE:
    {
      printf ("write!\n");
      int fd;
      const void * buff;
      unsigned size;

      printf ("reading user stack...\n");
      read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      read_usr_stack(stack_pointer + 8, &buff, sizeof(buff));
      read_usr_stack(stack_pointer + 12, &size, sizeof(size));

      printf ("calling write function!\n");
      f->eax = write(fd, buff, size);
      printf("success!\n");
      break;
    }
    case SYS_SEEK:
    {
      printf ("seek!\n");
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
    	int position;
    	read_usr_stack(stack_pointer + 8, &position, sizeof(position));
      seek (fd, position);
      break;
    }
    case SYS_TELL:
    {
      printf ("tell!\n");
      int fd;
    	read_usr_stack(stack_pointer + 4, &fd, sizeof(fd));
      f->eax = tell (fd);
      break;
    }
    case SYS_CLOSE:
    {
      printf ("close!\n");
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
  size_t i;
  for (i = 0; i < num_of_bytes; i++)
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
  printf("%s: exit(%d)\n", thread_current()->name, status);
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
  struct file *open_file;
  struct file_entry *entry = palloc_get_page (0);
  if (!entry)
  {
    return -1;
  }

  lock_acquire (&lock_filesys);
  open_file = filesys_open (file);
  if (!open_file)
  {
    palloc_free_page (entry);
    lock_release (&lock_filesys);
    return -1;
  }

  entry->file = open_file;
  struct list *fd_list = &thread_current ()->fd_list;
  if (list_empty(fd_list))
  {
    entry->fd = 3;
  } else
  {
    entry->fd = (list_entry(list_back(fd_list), struct file_entry, fe)->fd) + 1;
  }
  list_push_back (fd_list, &(entry->fe));
  lock_release (&lock_filesys);
  return entry->fd;
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

  if(fd == 1 || list_empty((struct list *)&thread_current()->fd_list))
  {
    lock_release(&lock_filesys);
    return 0;
  }
  
  struct list_elem *temp;

  for (temp = list_front((struct list *)&thread_current()->fd_list); temp != NULL; temp = temp->next)
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
  printf("Acquiring lock!\n");
  lock_acquire(&lock_filesys);

  //fd == 0, no files present or STDIN
  printf("evaluating if\n");
  if (fd == 0 || list_empty((struct list *)&thread_current()->fd_list))
  {
    printf("inside if!\n");
    lock_release(&lock_filesys);
    return 0;
  }
  
    printf("evaluating another if!\n");

  //fd == 1, write to STDOUT
  if(fd == 1)
  {
    printf("inside another if!\n");
    putbuf(buffer, size);
    printf("releasing lock!\n");
    lock_release(&lock_filesys);

    printf("returning!\n");
    return size;
  }
  
  struct list_elem *temp;


  printf("entering for!\n");
  //Check if fd is owened by current process
  for (temp = list_front(&thread_current()->fd_list); temp != NULL; temp = temp->next)
  {
      struct file_entry *t = list_entry (temp, struct file_entry, fe);

      if (t->fd == fd)
      {
        int bytes_written = (int) file_write(t->file, buffer, size);
        lock_release(&lock_filesys);
        return bytes_written;
      }
  }

  printf("releasing lock\n");
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
