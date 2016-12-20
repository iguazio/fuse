/*
 * File: dlist.h
 * Summary: double linked list (+ upcasting routines)
 *
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 * Modified by: Alexander Nezhinsky (nezhinsky@gmail.com)
 *
 * Licensed under BSD-MIT :
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once

#define fuse_ptr_dec(ptr, val) ((typeof(ptr) *)(((uint8_t *)(ptr)) - (val)))
#define fuse_ptr_inc(ptr, val) ((typeof(ptr) *)(((uint8_t *)(ptr)) + (val)))

#define fuse_type_safe_expr_check(expr, type) ((typeof(expr) *)0 != (type *)0)
#define fuse_type_safe_offsetof(containing_type, member, member_type)                                                       \
    (offsetof(containing_type, member) + fuse_type_safe_expr_check(((containing_type *)0)->member, member_type))


__BEGIN_DECLS

/**
 * struct fuse_dlist_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *  struct child {
 *      const char *name;
 *      struct fuse_dlist_node list; // Linked list of all us children
 *  };
 */
struct fuse_dlist_node {
    struct fuse_dlist_node *next, *prev;
};

/**
 * struct fuse_dlist_head - the head of a doubly-linked list
 * @n: the head's fuse_dlist_node (its next and prev pointers)
 *
 * This is used as the head of a linked list.
 * Example:
 *  struct parent {
 *      const char *name;
 *      struct fuse_dlist_head children; // Head of the children linked list
 *      unsigned int num_children;
 *  };
 */
struct fuse_dlist_head {
    struct fuse_dlist_node n;
};

/**
 * struct fuse_dlist_offset_head - the head of a doubly-linked list with pre-saved list node offset
 * @h: the fuse_dlist_head (containing next and prev pointers)
 * @node_offset: saved list node offset
 *
 * fuse_dlist_offset_head is used as the head of a linked list when saving list node offset is desired.
 * This usually happens when list is manipulated from a context where the list entry structure
 * layout is not available and thus the list node's field offset can't be statically calculated
 * by compiler using offsetof() primitive. Otherwise it behaves much like fuse_dlist_head.
 *
 * Example:
 *  struct parent_offset {
 *      const char *name;
 *      struct fuse_dlist_offset_head children; // children linked list with saved list node offset
 *      unsigned int num_children;
 *  };
 */
struct fuse_dlist_offset_head {
    struct fuse_dlist_head h;
    size_t node_offset;
};

/* Initialization of list head:
 * - FUSE_DLIST_HEAD_INIT
 * - FUSE_DLIST_HEAD
 * - fuse_dlist_head_init
 * - fuse_dlist_offset_head_init
 */

/**
 * FUSE_DLIST_HEAD_INIT - explicit initializer for an empty fuse_dlist_head
 * @name: the name of the list.
 *
 * Example:
 *  static struct fuse_dlist_head my_list = FUSE_DLIST_HEAD_INIT(my_list);
 */
#define FUSE_DLIST_HEAD_INIT(name)                                                                                          \
    {                                                                                                                  \
        {                                                                                                              \
            &name.n, &name.n                                                                                           \
        }                                                                                                              \
    }

/**
 * FUSE_DLIST_HEAD - define and initialize an empty fuse_dlist_head
 * @name: the name of the list.
 *
 * The FUSE_DLIST_HEAD macro defines a fuse_dlist_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static fuse_dlist_head.
 *
 * Example:
 *  static FUSE_DLIST_HEAD(my_global_list);
 */
#define FUSE_DLIST_HEAD(name) struct fuse_dlist_head name = FUSE_DLIST_HEAD_INIT(name)

/**
 * fuse_dlist_head_init - dynamically initialize a fuse_dlist_head
 * @h: fuse_dlist_head to initialize as empty list
 *
 * Example:
 *  struct parent *parent = malloc(sizeof(*parent));
 *  parent->name = "parent_list";
 *  fuse_dlist_head_init(&parent->children); // initialize the list head
 *  parent->num_children = 0;
 */
static inline void fuse_dlist_head_init(struct fuse_dlist_head *h)
{
    h->n.next = h->n.prev = &h->n;
}

/**
 * fuse_dlist_offset_head_init - dynamically initialize a fuse_dlist_head
 * @ho: the fuse_dlist_offset_head to set empty
 * @node_offset: node member offset
 *
 * Example:
 *  struct parent_offset *parent = malloc(sizeof(*parent));
 *  parent->name = "parent_offset_list";
 *  fuse_dlist_offset_head_init(&parent->children, offsetof(struct child, node));
 *  parent->num_children = 0;
 */
static inline void fuse_dlist_offset_head_init(struct fuse_dlist_offset_head *ho, size_t node_offset)
{
    fuse_dlist_head_init(&ho->h);
    ho->node_offset = node_offset;
}

/* Private service macros and function:
 * - fuse_dlist_prv_type_node_offsetof : get offset of a field and check it's fuse_dlist_node
 * - fuse_dlist_prv_var_node_offsetof : get offset of a field, by typed pointer var, check it's fuse_dlist_node
 * - fuse_dlist_prv_node2var : get pointer to containing structure using node pointer and node field's offset
 * - fuse_dlist_prv_var2node : get pointer to list node, using containing structure pointer and node field's offset
 */

/**
 * fuse_dlist_prv_type_node_offsetof - get offset of containing type's member, but make sure it's a fuse_dlist_node
 *
 * Example:
 *  struct info {
 *      int some_other_field;
 *      struct fuse_dlist_node my_node;
 *  };
 *  size_t my_node_offset = fuse_dlist_prv_type_node_offsetof(struct info, my_node);
 */
#define fuse_dlist_prv_type_node_offsetof(containing_type, member)                                                          \
    fuse_type_safe_offsetof(containing_type, member, struct fuse_dlist_node)

/**
 * fuse_dlist_prv_var_node_offsetof - get offset of a field in enclosing structure, but make sure it's a fuse_dlist_node
 * @container_var: a pointer to a container structure
 * @member: the name of a member within the structure.
 */
#define fuse_dlist_prv_var_node_offsetof(containing_var, member)                                                            \
    fuse_type_safe_offsetof_by_ptr(containing_var, member, struct fuse_dlist_node)

/**
 * fuse_dlist_prv_node2var - get pointer to containing structure using node pointer and node field's offset
 * @node: pointer to fuse_dlist_node
 * @off: list node offset
 */
static inline void *fuse_dlist_prv_node2var(struct fuse_dlist_node *node, size_t off)
{
    return (void *)fuse_ptr_dec(node, off);
}

/**
 * fuse_dlist_prv_var2node - get pointer to list node, using containing structure pointer and node field's offset
 * @containing_var: pointer to struct
 * @off: list node offset
 */
static inline struct fuse_dlist_node *fuse_dlist_prv_var2node(void *containing_var, size_t off)
{
    return (struct fuse_dlist_node *)fuse_ptr_inc(containing_var, off);
}

/* Debug functions:
 * - fuse_dlist_check_head: check consistency of a list head
 * - fuse_dlist_check_node: check consistency of a list node
 */

/**
 * fuse_dlist_check_head - check head of a list for consistency
 * @h: the fuse_dlist_head
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Because dlist_nodes have redundant information, consistency checking between
 * the back and forward links can be done.  This is useful as a debugging check.
 * If @abortstr is non-NULL, that will be printed in a diagnostic if the list
 * is inconsistent, and the function will abort.
 *
 * Returns the list head if the list is consistent, NULL if not (it
 * can never return NULL if @abortstr is set).
 *
 * See also: fuse_dlist_check_node()
 *
 * Example:
 *  static void dump_parent(struct parent *p)
 *  {
 *      struct child *c;
 *      printf("%s (%u children):\n", p->name, p->num_children);
 *      fuse_dlist_check_head(&p->children, "bad child list");
 *      fuse_dlist_for_each(&p->children, c, list)
 *          printf(" -> %s\n", c->name);
 *  }
 */
struct fuse_dlist_head *fuse_dlist_check_head(const struct fuse_dlist_head *h, const char *abortstr);

/**
 * fuse_dlist_check_node - check node of a list for consistency
 * @n: the fuse_dlist_node
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Check consistency of the list node is in (it must be in one).
 *
 * See also: fuse_dlist_check_head()
 *
 * Example:
 *  static void dump_child(const struct child *c)
 *  {
 *      fuse_dlist_check_node(&c->list, "bad child list");
 *      printf("%s\n", c->name);
 *  }
 */
struct fuse_dlist_node *fuse_dlist_check_node(const struct fuse_dlist_node *n, const char *abortstr);

#ifdef _DLIST_DEBUG_
#define fuse_dlist_debug(h) fuse_dlist_check_head((h), __func__)
#define fuse_dlist_debug_node(n) fuse_dlist_check_node((n), __func__)
#else
#define fuse_dlist_debug(h) (h)
#define fuse_dlist_debug_node(n) (n)
#endif

/* List manipulation methods:
 * - fuse_dlist_add, fuse_dlist_offset_add : add a new entry at the list's head (LIFO if pop is used)
 * - fuse_dlist_add_tail, fuse_dlist_offset_add_tail : add a new entry at the list's tail (FIFO if pop is used)
 * - fuse_dlist_insert, fuse_dlist_offset_insert : insert a new entry after an existing list entry
 * - fuse_dlist_empty, fuse_dlist_offset_empty : return true if the list is currently empty
 * - fuse_dlist_del : delete an entry, no list head checks
 * - fuse_dlist_del_from, fuse_dlist_offset_del_from : delete an entry from a list (dlist_offset needs head to get offset
 * value)
 * - fuse_dlist_top, fuse_dlist_offset_top : return the head entry of the list, or NULL if empty
 * - fuse_dlist_pop, fuse_dlist_offset_pop : remove and return the head entry of the list, or return NULL if empty
 * - fuse_dlist_tail, fuse_dlist_offset_tail : return the tail entry of the list, or NULL if empty
 * - fuse_dlist_pop_tail, fuse_dlist_offset_pop_tail : remove and return the tail entry of the list, or return NULL if empty
 * - dlist_append, dlist_offset_append : empty one list onto the end of another
 * - dlist_prepend, dlist_offset_prepend : empty one list in the start of another
 */

/**
 * fuse_dlist_add - add an entry at the start of a linked list.
 * @h: the fuse_dlist_head to add the node to
 * @n: the fuse_dlist_node to add to the list.
 *
 * The fuse_dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *  struct child *child = malloc(sizeof(*child));
 *
 *  child->name = "marvin";
 *  fuse_dlist_add(&parent->children, &child->list);
 *  parent->num_children++;
 */
static inline void fuse_dlist_add(struct fuse_dlist_head *h, struct fuse_dlist_node *n)
{
    n->next = h->n.next;
    n->prev = &h->n;
    h->n.next->prev = n;
    h->n.next = n;
    (void)fuse_dlist_debug(h);
}

/**
 * fuse_dlist_prv_add_by_off - add an entry at the start of a linked list, identify node member by offset.
 * @h: the fuse_dlist_head to add the node to
 * @containing_var: containing struct
 * @off: fuse_dlist_node member offset.
 */
#define fuse_dlist_prv_add_by_off(h, containing_var, off) fuse_dlist_add(h, fuse_dlist_prv_var2node(containing_var, off))

/**
 * fuse_dlist_offset_add - add an entry at the start of a linked list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 * @containing_var: containing struct
 */
static inline void fuse_dlist_offset_add(struct fuse_dlist_offset_head *ho, void *containing_var)
{
    fuse_dlist_prv_add_by_off(&ho->h, containing_var, ho->node_offset);
}

/**
 * fuse_dlist_add_tail - add an entry at the end of a linked list.
 * @h: the fuse_dlist_head to add the node to
 * @n: the fuse_dlist_node to add to the list.
 *
 * The fuse_dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *  fuse_dlist_add_tail(&parent->children, &child->list);
 *  parent->num_children++;
 */
static inline void fuse_dlist_add_tail(struct fuse_dlist_head *h, struct fuse_dlist_node *n)
{
    n->next = &h->n;
    n->prev = h->n.prev;
    h->n.prev->next = n;
    h->n.prev = n;
    (void)fuse_dlist_debug(h);
}

/**
 * fuse_dlist_prv_add_tail_by_off - add an entry at the end of a linked list, identify node member by offset.
 * @h: the fuse_dlist_head to add the node to
 * @containing_var: containing struct
 * @off: fuse_dlist_node member offset.
 */
#define fuse_dlist_prv_add_tail_by_off(h, containing_var, off) fuse_dlist_add_tail(h, fuse_dlist_prv_var2node(containing_var, off))

/**
 * fuse_dlist_offset_add - add an entry at the start of a linked list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 * @containing_var: containing struct
 */
static inline void fuse_dlist_offset_add_tail(struct fuse_dlist_offset_head *ho, void *containing_var)
{
    fuse_dlist_prv_add_tail_by_off(&ho->h, containing_var, ho->node_offset);
}

/**
 * fuse_dlist_insert - insert an entry after another linked list node.
 * @h: the fuse_dlist_head to add the node to
 * @n: the fuse_dlist_node to add to the list.
 * @after: the fuse_dlist_node after which to add the new entry
 *
 * The fuse_dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *  fuse_dlist_insert(&parent->children, &child->list, &after_child->list);
 *  parent->num_children++;
 */
static inline void fuse_dlist_insert(struct fuse_dlist_head *h, struct fuse_dlist_node *n, struct fuse_dlist_node *after)
{
    n->next = after->next;
    n->prev = after;
    after->next->prev = n;
    after->next = n;
    (void)fuse_dlist_debug(h);
}

/**
 * fuse_dlist_prv_insert_by_off - insert an entry after another linked list node, identify node members by offset.
 * @h: the fuse_dlist_head to add the node to
 * @containing_var: containing struct to be inserted
 * @after_containing_var: containing struct after which to insert
 * @off: fuse_dlist_node member offset.
 */
#define fuse_dlist_prv_insert_by_off(h, containing_var, after_containing_var, off)                                          \
    fuse_dlist_insert(h, fuse_dlist_prv_var2node(containing_var, off), fuse_dlist_prv_var2node(after_containing_var, off))

/**
 * fuse_dlist_offset_insert - add an entry at the start of a linked list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 * @containing_var: containing struct
 * @after_containing_var: containing struct after which to insert
 */
static inline void fuse_dlist_offset_insert(struct fuse_dlist_offset_head *ho, void *containing_var, void *after_containing_var)
{
    fuse_dlist_prv_insert_by_off(&ho->h, containing_var, after_containing_var, ho->node_offset);
}

/**
 * fuse_dlist_empty - is a list empty?
 * @h: the fuse_dlist_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *  ASSERT(fuse_dlist_empty(&parent->children) == (parent->num_children == 0));
 */
static inline int fuse_dlist_empty(const struct fuse_dlist_head *h)
{
    (void)fuse_dlist_debug(h);
    return h->n.next == &h->n;
}

/**
 * fuse_dlist_empty - is a list empty?
 * @ho: the dlist_head_offset
 *
 * If the list is empty, returns true.
 *
 * Example:
 *  ASSERT(fuse_dlist_offset_empty(&parent->children) == (parent->num_children == 0));
 */
static inline int fuse_dlist_offset_empty(const struct fuse_dlist_offset_head *ho)
{
    return fuse_dlist_empty(&ho->h);
}

/**
 * fuse_dlist_del - delete an entry from an (unknown) linked list.
 * @n: the fuse_dlist_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *  fuse_dlist_del_from()
 *
 * Example:
 *  fuse_dlist_del(&child->list);
 *  parent->num_children--;
 */
static inline void fuse_dlist_del(struct fuse_dlist_node *n)
{
    (void)fuse_dlist_debug_node(n);
    n->next->prev = n->prev;
    n->prev->next = n->next;
#ifdef _DLIST_DEBUG_
    /* Catch use-after-del. */
    n->next = n->prev = NULL;
#endif
}

/**
 * fuse_dlist_prv_del_by_off - delete an entry from an (unknown) linked list, identify node member by offset.
 * @containing_var: containing struct
 * @off: fuse_dlist_node member offset.
 */
#define fuse_dlist_prv_del_by_off(containing_var, off) fuse_dlist_del(fuse_dlist_prv_var2node(containing_var, off))

/**
 * fuse_dlist_del_from - delete an entry from a known linked list.
 * @h: the fuse_dlist_head the node is in.
 * @n: the fuse_dlist_node to delete from the list.
 *
 * This explicitly indicates which list a node is expected to be in,
 * which is better documentation and can catch more bugs.
 *
 * See also: fuse_dlist_del()
 *
 * Example:
 *  fuse_dlist_del_from(&parent->children, &child->list);
 *  parent->num_children--;
 */
static inline void fuse_dlist_del_from(struct fuse_dlist_head *h __attribute__((unused)), struct fuse_dlist_node *n)
{
#ifdef _DLIST_DEBUG_
    {
        /* Thorough check: make sure it was in list! */
        struct fuse_dlist_node *i;
        for (i = h->n.next; i != n; i = i->next)
            bug_on(i == &h->n);
    }

    /* Quick test that catches a surprising number of bugs. */
    bug_on(fuse_dlist_empty(h));
#endif /* _DLIST_DEBUG_ */

    fuse_dlist_del(n);
}

/**
 * fuse_dlist_prv_del_by_off - delete an entry from an known linked list, identify node member by offset.
 * @h: the fuse_dlist_head to add the node to
 * @containing_var: containing struct
 * @off: fuse_dlist_node member offset.
 */
#define fuse_dlist_prv_del_from_by_off(h, containing_var, off) fuse_dlist_del_from(h, fuse_dlist_prv_var2node(containing_var, off))

/**
 * fuse_dlist_offset_del_from - delete an entry from an (unknown) linked list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 * @containing_var: containing struct
 */
static inline void fuse_dlist_offset_del_from(struct fuse_dlist_offset_head *ho, void *containing_var)
{
    fuse_dlist_prv_del_from_by_off(&ho->h, containing_var, ho->node_offset);
}

/**
 * fuse_dlist_prv_top_by_off - get the first entry in a list by node member offset
 * @h: the fuse_dlist_head
 * @off: node member offset
 */
static inline void *fuse_dlist_prv_top_by_off(const struct fuse_dlist_head *h, size_t off)
{
    return ((!fuse_dlist_empty(h)) ? fuse_dlist_prv_node2var((h)->n.next, off) : NULL);
}

/**
 * fuse_dlist_top - get the first entry in a list
 * @h: the fuse_dlist_head
 * @type: the type of the entry
 * @member: the fuse_dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *  struct child *first;
 *  first = fuse_dlist_top(&parent->children, struct child, list);
 *  if (!first)
 *      printf("Empty list!\n");
 */
#define fuse_dlist_top(h, containing_type, member)                                                                          \
    ((containing_type *)fuse_dlist_prv_top_by_off(h, fuse_dlist_prv_type_node_offsetof(containing_type, member)))

/**
 * fuse_dlist_offset_top -  get the first entry in a list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 */
static inline void *fuse_dlist_offset_top(struct fuse_dlist_offset_head *ho)
{
    return fuse_dlist_prv_top_by_off(&ho->h, ho->node_offset);
}

/**
 * fuse_dlist_prv_pop_by_off - pop the first entry from a list by node member offset
 * @h: the fuse_dlist_head
 * @off: node member offset
 */
static inline void *fuse_dlist_prv_pop_by_off(const struct fuse_dlist_head *h, size_t off)
{
    if (!fuse_dlist_empty(h)) {
        struct fuse_dlist_node *n = h->n.next;
        fuse_dlist_del(n);
        return fuse_dlist_prv_node2var(n, off);
    } else {
        return NULL;
    }
}

/**
 * fuse_dlist_pop - remove the first entry in a list
 * @h: the fuse_dlist_head
 * @type: the type of the entry
 * @member: the fuse_dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *  struct child *one;
 *  one = fuse_dlist_pop(&parent->children, struct child, list);
 *  if (!one)
 *      printf("Empty list!\n");
 */
#define fuse_dlist_pop(h, containing_type, member)                                                                          \
    ((containing_type *)fuse_dlist_prv_pop_by_off((h), fuse_dlist_prv_type_node_offsetof(containing_type, member)))

/**
 * fuse_dlist_offset_pop - remove the first entry in a list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 */
static inline void *fuse_dlist_offset_pop(struct fuse_dlist_offset_head *ho)
{
    return fuse_dlist_prv_pop_by_off(&ho->h, ho->node_offset);
}

/**
 * fuse_dlist_prv_tail_by_off - get the last entry in a list by node member offset
 * @h: the fuse_dlist_head
 * @off: node member offset
 */
static inline void *fuse_dlist_prv_tail_by_off(const struct fuse_dlist_head *h, size_t off)
{
    return (!fuse_dlist_empty(h)) ? fuse_dlist_prv_node2var(h->n.prev, off) : NULL;
}

/**
 * fuse_dlist_tail - get the last entry in a list
 * @h: the fuse_dlist_head
 * @type: the type of the entry
 * @member: the fuse_dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *  struct child *last;
 *  last = fuse_dlist_tail(&parent->children, struct child, list);
 *  if (!last)
 *      printf("Empty list!\n");
 */
#define fuse_dlist_tail(h, containing_type, member)                                                                         \
    ((containing_type *)fuse_dlist_prv_tail_by_off((h), fuse_dlist_prv_type_node_offsetof(containing_type, member)))

/**
 * fuse_dlist_offset_tail - get the last entry in a list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 */
static inline void *fuse_dlist_offset_tail(struct fuse_dlist_offset_head *ho)
{
    return fuse_dlist_prv_tail_by_off(&ho->h, ho->node_offset);
}

/**
 * fuse_dlist_prv_pop_tail_by_off - pop the last entry from a list by node member offset
 * @h: the fuse_dlist_head
 * @off: node member offset
 */
static inline void *fuse_dlist_prv_pop_tail_by_off(const struct fuse_dlist_head *h, size_t off)
{
    struct fuse_dlist_node *n;

    if (fuse_dlist_empty(h))
        return NULL;
    n = h->n.prev;
    fuse_dlist_del(n);
    return fuse_dlist_prv_node2var(n, off);
}

/**
 * fuse_dlist_pop_tail - remove the last entry in a list
 * @h: the fuse_dlist_head
 * @type: the type of the entry
 * @member: the fuse_dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *  struct child *last;
 *  last = fuse_dlist_pop_tail(&parent->children, struct child, list);
 *  if (!last)
 *      printf("Empty list!\n");
 */
#define fuse_dlist_pop_tail(h, containing_type, member)                                                                     \
    ((containing_type *)fuse_dlist_prv_pop_tail_by_off((h), fuse_dlist_prv_type_node_offsetof(containing_type, member)))

/**
 * fuse_dlist_offset_pop_tail - remove the last entry in a list, using the pre-saved list node offset
 * @ho: the fuse_dlist_offset_head to add the node to
 */
static inline void *fuse_dlist_offset_pop_tail(struct fuse_dlist_offset_head *ho)
{
    return fuse_dlist_prv_pop_tail_by_off(&ho->h, ho->node_offset);
}

/**
 * fuse_dlist_append_list - empty one list onto the end of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the end of
 * @to.  After this @from will be empty.
 *
 * Example:
 *  struct fuse_dlist_head adopter;
 *  fuse_dlist_append_list(&adopter, &parent->children);
 *  ASSERT(fuse_dlist_empty(&parent->children));
 *  parent->num_children = 0;
 */
static inline void fuse_dlist_append_list(struct fuse_dlist_head *to, struct fuse_dlist_head *from)
{
    struct fuse_dlist_node *from_tail = fuse_dlist_debug(from)->n.prev;
    struct fuse_dlist_node *to_tail = fuse_dlist_debug(to)->n.prev;

    /* Sew in head and entire list. */
    to->n.prev = from_tail;
    from_tail->next = &to->n;
    to_tail->next = &from->n;
    from->n.prev = to_tail;

    /* Now remove head. */
    fuse_dlist_del(&from->n);
    fuse_dlist_head_init(from);
}

/**
 * fuse_dlist_offset_append_list - empty one list with pre-saved offset onto the end of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * Saved offsets of both lists must be equal
 */
static inline void fuse_dlist_offset_append_list(struct fuse_dlist_offset_head *to, struct fuse_dlist_offset_head *from)
{
#ifdef _DLIST_DEBUG_
    bug_on(to->node_offset != from->node_offset);
#endif
    fuse_dlist_append_list(&to->h, &from->h);
}

/**
 * fuse_dlist_prepend_list - empty one list into the start of another.
 * @to: the list to prepend into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the start
 * of @to.  After this @from will be empty.
 *
 * Example:
 *  fuse_dlist_prepend_list(&adopter, &parent->children);
 *  ASSERT(fuse_dlist_empty(&parent->children));
 *  parent->num_children = 0;
 */
static inline void fuse_dlist_prepend_list(struct fuse_dlist_head *to, struct fuse_dlist_head *from)
{
    struct fuse_dlist_node *from_tail = fuse_dlist_debug(from)->n.prev;
    struct fuse_dlist_node *to_head = fuse_dlist_debug(to)->n.next;

    /* Sew in head and entire list. */
    to->n.next = &from->n;
    from->n.prev = &to->n;
    to_head->prev = from_tail;
    from_tail->next = to_head;

    /* Now remove head. */
    fuse_dlist_del(&from->n);
    fuse_dlist_head_init(from);
}

/**
 * fuse_dlist_offset_prepend_list - empty one list with pre-saved offset into the start of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * Saved offsets of both lists must be equal
 */
static inline void fuse_dlist_offset_prepend_list(struct fuse_dlist_offset_head *to, struct fuse_dlist_offset_head *from)
{
#ifdef _DLIST_DEBUG_
    bug_on(to->node_offset != from->node_offset);
#endif
    fuse_dlist_prepend_list(&to->h, &from->h);
}

/**
 * fuse_dlist_for_each - iterate through a list.
 * @h: the fuse_dlist_head
 * @i: the structure containing the fuse_dlist_node
 * @member: the fuse_dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *  fuse_dlist_for_each(&parent->children, child, list)
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_for_each(h, i, member) fuse_dlist_prv_for_each_by_off(h, i, fuse_dlist_prv_var_node_offsetof(i, member))

/**
 * fuse_dlist_for_each_rev - iterate through a list backwards.
 * @h: the fuse_dlist_head
 * @i: the structure containing the fuse_dlist_node
 * @member: the fuse_dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *  fuse_dlist_for_each_rev(&parent->children, child, list)
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_for_each_rev(h, i, member) fuse_dlist_prv_for_each_rev_by_off(h, i, fuse_dlist_prv_var_node_offsetof(i, member))

/**
 * fuse_dlist_for_each_safe - iterate through a list, maybe during deletion
 * @h: the fuse_dlist_head
 * @i: the structure containing the fuse_dlist_node
 * @member: the fuse_dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 *
 * Example:
 *  struct child *next;
 *  fuse_dlist_for_each_safe(&parent->children, child, list) {
 *      fuse_dlist_del(&child->list);
 *      parent->num_children--;
 *  }
 */
#define fuse_dlist_for_each_safe(h, i, member) fuse_dlist_prv_for_each_safe_by_off(h, i, fuse_dlist_prv_var_node_offsetof(i, member))

/**
 * fuse_dlist_prv_for_each_by_off - iterate through a list
 * @h: the fuse_dlist_head
 * @i: the pointer to a memory region which contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * This is a low-level wrapper to iterate @i over the entire list, used to
 * implement all other, more high-level, for-each constructs.
 * It's a for loop, so you can break and continue as normal.
 *
 * WARNING! Being the low-level macro that it is, this wrapper doesn't know
 * nor care about the type of @i. The only assumption made is that @i points
 * to a chunk of memory that at some @offset, relative to @i, contains a
 * properly filled `struct fuse_dlist_node' which in turn contains pointers to
 * memory chunks and it's turtles all the way down. With all that in mind
 * remember that given a wrong pointer/offset couple this macro will
 * happily churn all you memory until SEGFAULT stops it, in other words
 * caveat emptor.
 *
 * It is worth mentioning that one of legitimate use-cases for that wrapper
 * is operation on opaque types with known offset for `struct fuse_dlist_node'
 * member(preferably 0), because it allows you not to disclose the type of @i.
 *
 * Example:
 *  fuse_dlist_prv_for_each_by_off(&parent->children, child, offsetof(struct child, node))
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_prv_for_each_by_off(h, i, off)                                                                           \
    for (struct fuse_dlist_node *_hnode = &(fuse_dlist_debug(h)->n), *_curnode = _hnode->next;                                   \
         !!(i = (_curnode != _hnode) ? (typeof(i))fuse_dlist_prv_node2var(_curnode, (off)) : NULL);                         \
         _curnode = fuse_dlist_debug_node(_curnode)->next)

/**
 * fuse_dlist_prv_for_each_rev_by_off - iterate through a list, backwards.
 * @h: the fuse_dlist_head
 * @i: the pointer to a memory region which contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * Example:
 *  fuse_dlist_prv_for_each_rev_by_off(&parent->children, child, offsetof(struct child, list))
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_prv_for_each_rev_by_off(h, i, off)                                                                       \
    for (struct fuse_dlist_node *_hnode = &(fuse_dlist_debug(h)->n), *_curnode = _hnode->prev;                                   \
         !!(i = (_curnode != _hnode) ? (typeof(i))fuse_dlist_prv_node2var(_curnode, (off)) : NULL);                         \
         _curnode = fuse_dlist_debug_node(_curnode)->prev)

/**
 * fuse_dlist_prv_for_each_safe_by_off - iterate through a list, deletion allowed
 * @h: the fuse_dlist_head
 * @i: the pointer to a memory region wich contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * Example:
 *  fuse_dlist_prv_for_each_safe_by_off(&parent->children, child, offsetof(struct child, list))
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_prv_for_each_safe_by_off(h, i, off)                                                                      \
    for (struct fuse_dlist_node *_hnode = &(fuse_dlist_debug(h)->n), *_curnode = _hnode->next, *_nxtnode = _curnode->next;       \
         !!(i = (_curnode != _hnode) ? (typeof(i))fuse_dlist_prv_node2var(_curnode, (off)) : NULL);                         \
         _curnode = _nxtnode, _nxtnode = _curnode->next)

/**
 * fuse_dlist_offset_for_each - iterate through a list with pre-saved list node offset
 * @ho: the dlist_head_offset
 * @i: the structure containing the fuse_dlist_node
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *  struct child *child;
 *  fuse_dlist_offset_for_each(&parent->children, child)
 *      printf("Name: %s\n", child->name);
 */
#define fuse_dlist_offset_for_each(ho, i) fuse_dlist_prv_for_each_by_off(&(ho)->h, i, (ho)->node_offset)

/**
 * fuse_dlist_offset_for_each_rev - iterate through a list with pre-saved list node offset, backwards.
 * @ho: the dlist_head_offset
 * @i: the structure containing the fuse_dlist_node
 */
#define fuse_dlist_offset_for_each_rev(ho, i) fuse_dlist_prv_for_each_rev_by_off(&(ho)->h, i, (ho)->node_offset)

/**
 * fuse_dlist_offset_for_each_safe - iterate through a list with pre-saved list node offset, deletions allowed
 * @ho: the dlist_head_offset
 * @i: the structure containing the fuse_dlist_node
 *
 * An extra variable is used to hold the next element internally, so you can delete @i from the list.
 *
 * Example:
 *  fuse_dlist_offset_for_each_safe(&parent->children, child) {
 *      fuse_dlist_offset_del_from(&parent->children, child);
 *      parent->num_children--;
 *  }
 */
#define fuse_dlist_offset_for_each_safe(ho, i) fuse_dlist_prv_for_each_safe_by_off(&(ho)->h, i, (ho)->node_offset)

__END_DECLS
