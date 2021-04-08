#ifndef VM_FRAME_H
#define VM_FRAME_H

void init_frame (void);
void* allocate_frame (void *user_page);
void free_frame (void*);
