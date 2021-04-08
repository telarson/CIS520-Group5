#include <stdio.h>
#include "lib/kernel/hash.h"

#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

static struct hash frame_hash;
static unsigned frame_hash_func (const struct hash_elem *elem, void *aux);
static bool frame_less_func (const struct hash_elem *, const struct hash_elem *, void *aux);

struct frame_entry
{
	void *user_page;						/* pointer to page address in user memory*/
	void *kernel_page;					/* pointer to page address in physical memory*/
	struct hash_elem hash_elem; /* frame_entry in frame_to_page */
};
void
init_frame ()
{
	hash_init (&frame_hash, frame_hash_func, frame_less_func, NULL);
}
/**
 * Allocates a new frame
 * and returns the address of the page allocated.
 */
void*
allocate_frame (void *user_page)
{
	void *page = palloc_get_page (PAL_USER);
	if (page == NULL) {
    PANIC ("Failed to find available frame for allocation in user memeory");
	}

	struct frame_entry *frame = malloc (sizeof (struct frame_entry));
	if (frame == NULL){
		PANIC ("Failed to alloc memory for frame entry sturct");
	}

	frame->user_page = user_page;
	frame->kernel_page = page;
	hash_insert (&frame_hash, &frame->hash_elem);
	return page;
}

void
free_frame (void *kernel_page)
{
	struct frame_entry temp;
	temp.kernal_page = kernal_page;
	struct hash_elem *elem = hash_find (&frame_hash, &(temp.hash_elem));
	if (elem == NULL) {
		PANIC ("Could not find element you are trying to free from table");
	}

	struct frame_entry *entry;
	entry = hash_entry (elem, struct frame_entry, hash_elem);
	hash_delete (&frame_hash, &entry->hash_elem);
	palloc_free_page(kernal_page);
	free(entry);
}

static unsigned
frame_hash_func (const struct hash_elem *elem, void *aux)
{
	struct frame_entry *entry = hash_entry (elem, struct frame_entry, hash_elem);
  return hash_bytes (&entry->kernel_page, sizeof entry->kernal_page);
}

static bool
frame_less_func (const struct hash_elem *elem1, const struct hash_elem *elem2, void *aux UNUSED)
{
  struct frame_entry *entry1 = hash_entry (elem1, struct frame_entry, hash_elem);
  struct frame_entry *entry2 = hash_entry (elem2, struct frame_entry, hash_elem);
  return entry1->kernel_page < entry2->kernel_page;
}