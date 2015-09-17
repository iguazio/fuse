#include "fuse_list.h"

void init_list_head( struct list_head *list )
{
    list->next = list;
    list->prev = list;
}

int list_empty( const struct list_head *head )
{
    return head->next == head;
}

void list_add( struct list_head *new, struct list_head *prev, struct list_head *next )
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

void list_add_head( struct list_head *new, struct list_head *head )
{
    list_add(new, head, head->next);
}

void list_add_tail( struct list_head *new, struct list_head *head )
{
    list_add(new, head->prev, head);
}

void list_del( struct list_head *entry )
{
    struct list_head *prev = entry->prev;
    struct list_head *next = entry->next;

    next->prev = prev;
    prev->next = next;
}
