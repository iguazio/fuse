/*
 * File: dptr_list.h
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
 *
 */
#ifndef _DPTR_LIST_H_
#define _DPTR_LIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <assert.h>

// #define _DLIST_DEBUG_
#define ASSERT(a)
/**
 * struct dlist_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct dlist_node list;
 *	};
 */
struct dlist_node {
	struct dlist_node *next, *prev;
};

/**
 * struct dlist_head - the head of a doubly-linked list
 * @h: the dlist_head (containing next and prev pointers)
 *
 * This is used as the head of a linked list.
 * Example:
 *	struct parent {
 *		const char *name;
 *		struct dlist_head children;
 *		unsigned int num_children;
 *	};
 */
struct dlist_head {
	struct dlist_node n;
};

/**
 * DLIST_HEAD_INIT - initializer for an empty dlist_head
 * @name: the name of the list.
 *
 * Explicit initializer for an empty list.
 *
 * See also:
 *	DLIST_HEAD, dlist_head_init()
 *
 * Example:
 *	static struct dlist_head my_list = DLIST_HEAD_INIT(my_list);
 */
#define DLIST_HEAD_INIT(name)                                                            \
	{                                                                                \
		{                                                                        \
			&name.n, &name.n                                                 \
		}                                                                        \
	}

/**
 * DLIST_HEAD - define and initialize an empty dlist_head
 * @name: the name of the list.
 *
 * The DLIST_HEAD macro defines a dlist_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static dlist_head.
 *
 * See also:
 *	DLIST_HEAD_INIT, dlist_head_init()
 *
 * Example:
 *	static DLIST_HEAD(my_global_list);
 */
#define DLIST_HEAD(name) struct dlist_head name = DLIST_HEAD_INIT(name)

/**
 * dlist_head_init - initialize a dlist_head
 * @h: the dlist_head to set to the empty list
 *
 * Example:
 *	...
 *	struct parent *parent = malloc(sizeof(*parent));
 *
 *	dlist_head_init(&parent->children);
 *	parent->num_children = 0;
 */
static inline void dlist_head_init(struct dlist_head *h)
{
	h->n.next = h->n.prev = &h->n;
}

/**
 * check_type - issue a warning or build failure if type is not correct.
 * @expr: the expression whose type we should check (not evaluated).
 * @type: the exact type we expect the expression to be.
 *
 * This macro is usually used within other macros to try to ensure that a macro
 * argument is of the expected type.  No type promotion of the expression is
 * done: an unsigned int is not the same as an int!
 *
 * check_type() always evaluates to 0.
 *
 * Example:
 *	// They should always pass a 64-bit value to _set_some_value!
 *	#define set_some_value(expr)			\
 *		_set_some_value((check_type((expr), uint64_t), (expr)))
 */
#define check_type(expr, type) ((typeof(expr) *)0 != (type *)0)
/**
 * check_types_match - issue a warning or build failure if types are not same.
 * @expr1: the first expression (not evaluated).
 * @expr2: the second expression (not evaluated).
 *
 * This macro is usually used within other macros to try to ensure that
 * arguments are of identical types.  No type promotion of the expressions is
 * done: an unsigned int is not the same as an int!
 *
 * check_types_match() always evaluates to 0.
 *
 * Example:
 *	// Do subtraction to get to enclosing type, but make sure that
 *	// pointer is of correct type for that member.
 *	#define _container_of(mbr_ptr, encl_type, mbr)			\
 *		(check_types_match((mbr_ptr), &((encl_type *)0)->mbr),	\
 *		 ((encl_type *)						\
 *		  ((char *)(mbr_ptr) - offsetof(enclosing_type, mbr))))
 */
#define check_types_match(expr1, expr2) ((typeof(expr1) *)0 != (typeof(expr2) *)0)
/**
 * _container_of - get pointer to enclosing structure
 * @member_ptr: pointer to the structure member
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 *
 * Example:
 *	struct foo {
 *		int fielda, fieldb;
 *		// ...
 *	};
 *	struct info {
 *		int some_other_field;
 *		struct foo my_foo;
 *	};
 *
 *	static struct info *foo_to_info(struct foo *foo)
 *	{
 *		return _container_of(foo, struct info, my_foo);
 *	}
 */
#define _container_of(member_ptr, containing_type, member)                               \
	((containing_type *)((char *)(member_ptr)-dlist_container_off(                   \
		 containing_type, member)) +                                             \
		check_types_match(*(member_ptr), ((containing_type *)0)->member))
/**
 * dlist_container_off - get offset to enclosing structure
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does
 * typechecking and figures out the offset to the enclosing type.
 *
 * Example:
 *	struct foo {
 *		int fielda, fieldb;
 *		// ...
 *	};
 *	struct info {
 *		int some_other_field;
 *		struct foo my_foo;
 *	};
 *
 *	static struct info *foo_to_info(struct foo *foo)
 *	{
 *		size_t off = dlist_container_off(struct info, my_foo);
 *		return (void *)((char *)foo - off);
 *	}
 */
#define dlist_container_off(containing_type, member) offsetof(containing_type, member)
/**
 * container_of_var - get pointer to enclosing structure using a variable
 * @member_ptr: pointer to the structure member
 * @container_var: a pointer of same type as this member's container
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 *
 * Example:
 *	static struct info *foo_to_i(struct foo *foo)
 *	{
 *		struct info *i = container_of_var(foo, i, my_foo);
 *		return i;
 *	}
 */
#define container_of_var(member_ptr, container_var, member)                              \
	_container_of(member_ptr, typeof(*container_var), member)
/**
 * dlist_container_off_var - get offset of a field in enclosing structure
 * @container_var: a pointer to a container structure
 * @member: the name of a member within the structure.
 *
 * Given (any) pointer to a structure and a its member name, this
 * macro does pointer subtraction to return offset of member in a
 * structure memory layout.
 *
 */
#define dlist_container_off_var(var, member) dlist_container_off(typeof(*var), member)

/**
 * dlist_check - check head of a list for consistency
 * @h: the dlist_head
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
 * See also: dlist_check_node()
 *
 * Example:
 *	static void dump_parent(struct parent *p)
 *	{
 *		struct child *c;
 *
 *		printf("%s (%u children):\n", p->name, p->num_children);
 *		dlist_check(&p->children, "bad child list");
 *		dlist_for_each(&p->children, c, list)
 *			printf(" -> %s\n", c->name);
 *	}
 */
struct dlist_head *dlist_check(const struct dlist_head *h, const char *abortstr);

/**
 * dlist_check_node - check node of a list for consistency
 * @n: the dlist_node
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Check consistency of the list node is in (it must be in one).
 *
 * See also: dlist_check()
 *
 * Example:
 *	static void dump_child(const struct child *c)
 *	{
 *		dlist_check_node(&c->list, "bad child list");
 *		printf("%s\n", c->name);
 *	}
 */
struct dlist_node *dlist_check_node(const struct dlist_node *n, const char *abortstr);

#ifdef _DLIST_DEBUG_
#define dlist_debug(h) dlist_check((h), __func__)
#define dlist_debug_node(n) dlist_check_node((n), __func__)
#else
#define dlist_debug(h) (h)
#define dlist_debug_node(n) (n)
#endif

/**
 * dlist_add - add an entry at the start of a linked list.
 * @h: the dlist_head to add the node to
 * @n: the dlist_node to add to the list.
 *
 * The dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "marvin";
 *	dlist_add(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void dlist_add(struct dlist_head *h, struct dlist_node *n)
{
	n->next = h->n.next;
	n->prev = &h->n;
	h->n.next->prev = n;
	h->n.next = n;
	(void)dlist_debug(h);
}

/**
 * dlist_add_tail - add an entry at the end of a linked list.
 * @h: the dlist_head to add the node to
 * @n: the dlist_node to add to the list.
 *
 * The dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	dlist_add_tail(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void dlist_add_tail(struct dlist_head *h, struct dlist_node *n)
{
	n->next = &h->n;
	n->prev = h->n.prev;
	h->n.prev->next = n;
	h->n.prev = n;
	(void)dlist_debug(h);
}

/**
 * dlist_insert - insert an entry after another linked list node.
 * @h: the dlist_head to add the node to
 * @n: the dlist_node to add to the list.
 * @after: the dlist_node after which to add the new entry
 *
 * The dlist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	dlist_insert(&parent->children, &child->list, &after_child->list);
 *	parent->num_children++;
 */
static inline void dlist_insert(struct dlist_head *h,
	struct dlist_node *n,
	struct dlist_node *after)
{
	n->next = after->next;
	n->prev = after;
	after->next = n;
	(void)dlist_debug(h);
}

/**
 * dlist_empty - is a list empty?
 * @h: the dlist_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *	ASSERT(dlist_empty(&parent->children) == (parent->num_children == 0));
 */
static inline bool dlist_empty(const struct dlist_head *h)
{
	(void)dlist_debug(h);
	return h->n.next == &h->n;
}

/**
 * dlist_del - delete an entry from an (unknown) linked list.
 * @n: the dlist_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *	dlist_del_from()
 *
 * Example:
 *	dlist_del(&child->list);
 *	parent->num_children--;
 */
static inline void dlist_del(struct dlist_node *n)
{
	(void)dlist_debug_node(n);
	n->next->prev = n->prev;
	n->prev->next = n->next;
#ifdef _DLIST_DEBUG_
	/* Catch use-after-del. */
	n->next = n->prev = NULL;
#endif
}

/**
 * dlist_del_from - delete an entry from a known linked list.
 * @h: the dlist_head the node is in.
 * @n: the dlist_node to delete from the list.
 *
 * This explicitly indicates which list a node is expected to be in,
 * which is better documentation and can catch more bugs.
 *
 * See also: dlist_del()
 *
 * Example:
 *	dlist_del_from(&parent->children, &child->list);
 *	parent->num_children--;
 */
static inline void dlist_del_from(struct dlist_head *h, struct dlist_node *n)
{
#ifdef _DLIST_DEBUG_
	{
		/* Thorough check: make sure it was in list! */
		struct dlist_node *i;
		for (i = h->n.next; i != n; i = i->next)
			ASSERT(i != &h->n);
	}
#endif /* _DLIST_DEBUG_ */

	/* Quick test that catches a surprising number of bugs. */
	ASSERT(!dlist_empty(h));
	dlist_del(n);
}

/**
 * dlist_entry - convert a dlist_node back into the structure containing it.
 * @n: the dlist_node
 * @type: the type of the entry
 * @member: the dlist_node member of the type
 *
 * Example:
 *	// First list entry is children.next; convert back to child.
 *	child = dlist_entry(parent->children.n.next, struct child, list);
 *
 * See Also:
 *	dlist_top(), dlist_for_each()
 */
#define dlist_entry(n, type, member) _container_of(n, type, member)

/**
 * dlist_top - get the first entry in a list
 * @h: the dlist_head
 * @type: the type of the entry
 * @member: the dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *first;
 *	first = dlist_top(&parent->children, struct child, list);
 *	if (!first)
 *		printf("Empty list!\n");
 */
#define dlist_top(h, type, member) ((type *)dlist_top_((h), dlist_off_(type, member)))

static inline const void *dlist_top_(const struct dlist_head *h, size_t off)
{
	if (dlist_empty(h))
		return NULL;
	return (const char *)h->n.next - off;
}

/**
 * dlist_pop - remove the first entry in a list
 * @h: the dlist_head
 * @type: the type of the entry
 * @member: the dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *one;
 *	one = dlist_pop(&parent->children, struct child, list);
 *	if (!one)
 *		printf("Empty list!\n");
 */
#define dlist_pop(h, type, member) ((type *)dlist_pop_((h), dlist_off_(type, member)))

static inline const void *dlist_pop_(const struct dlist_head *h, size_t off)
{
	struct dlist_node *n;

	if (dlist_empty(h))
		return NULL;
	n = h->n.next;
	dlist_del(n);
	return (const char *)n - off;
}

/**
 * dlist_tail - get the last entry in a list
 * @h: the dlist_head
 * @type: the type of the entry
 * @member: the dlist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *last;
 *	last = dlist_tail(&parent->children, struct child, list);
 *	if (!last)
 *		printf("Empty list!\n");
 */
#define dlist_tail(h, type, member) ((type *)dlist_tail_((h), dlist_off_(type, member)))

static inline const void *dlist_tail_(const struct dlist_head *h, size_t off)
{
	if (dlist_empty(h))
		return NULL;
	return (const char *)h->n.prev - off;
}

/**
 * dlist_for_each - iterate through a list.
 * @h: the dlist_head (warning: evaluated multiple times!)
 * @i: the structure containing the dlist_node
 * @member: the dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	dlist_for_each(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define dlist_for_each(h, i, member) dlist_for_each_off(h, i, dlist_off_var_(i, member))

/**
 * dlist_for_each_rev - iterate through a list backwards.
 * @h: the dlist_head
 * @i: the structure containing the dlist_node
 * @member: the dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	dlist_for_each_rev(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define dlist_for_each_rev(h, i, member)                                                 \
	for (i = container_of_var(dlist_debug(h)->n.prev, i, member);                    \
		&i->member != &(h)->n;                                                   \
		i = container_of_var(i->member.prev, i, member))

/**
 * dlist_for_each_safe - iterate through a list, maybe during deletion
 * @h: the dlist_head
 * @i: the structure containing the dlist_node
 * @nxt: the structure containing the dlist_node
 * @member: the dlist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 *
 * Example:
 *	struct child *next;
 *	dlist_for_each_safe(&parent->children, child, next, list) {
 *		dlist_del(&child->list);
 *		parent->num_children--;
 *	}
 */
#define dlist_for_each_safe(h, i, nxt, member)                                           \
	dlist_for_each_safe_off(h, i, nxt, dlist_off_var_(i, member))

/**
 * dlist_append_list - empty one list onto the end of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the end of
 * @to.  After this @from will be empty.
 *
 * Example:
 *	struct dlist_head adopter;
 *
 *	dlist_append_list(&adopter, &parent->children);
 *	ASSERT(dlist_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void dlist_append_list(struct dlist_head *to, struct dlist_head *from)
{
	struct dlist_node *from_tail = dlist_debug(from)->n.prev;
	struct dlist_node *to_tail = dlist_debug(to)->n.prev;

	/* Sew in head and entire list. */
	to->n.prev = from_tail;
	from_tail->next = &to->n;
	to_tail->next = &from->n;
	from->n.prev = to_tail;

	/* Now remove head. */
	dlist_del(&from->n);
	dlist_head_init(from);
}

/**
 * dlist_prepend_list - empty one list into the start of another.
 * @to: the list to prepend into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the start
 * of @to.  After this @from will be empty.
 *
 * Example:
 *	dlist_prepend_list(&adopter, &parent->children);
 *	ASSERT(dlist_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void dlist_prepend_list(struct dlist_head *to, struct dlist_head *from)
{
	struct dlist_node *from_tail = dlist_debug(from)->n.prev;
	struct dlist_node *to_head = dlist_debug(to)->n.next;

	/* Sew in head and entire list. */
	to->n.next = &from->n;
	from->n.prev = &to->n;
	to_head->prev = from_tail;
	from_tail->next = to_head;

	/* Now remove head. */
	dlist_del(&from->n);
	dlist_head_init(from);
}

/**
 * dlist_for_each_off - iterate through a list of memory regions.
 * @h: the dlist_head
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
 * properly filled `struct node_list' which in turn contains pointers to
 * memory chunks and it's turtles all the way down. With all that in mind
 * remember that given a wrong pointer/offset couple this macro will
 * happily churn all you memory until SEGFAULT stops it, in other words
 * caveat emptor.
 *
 * It is worth mentioning that one of legitimate use-cases for that wrapper
 * is operation on opaque types with known offset for `struct dlist_node'
 * member(preferably 0), because it allows you not to disclose the type of
 * @i.
 *
 * Example:
 *	dlist_for_each_off(&parent->children, child,
 *				offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define dlist_for_each_off(h, i, off)                                                    \
	for (i = dlist_node_to_off_(dlist_debug(h)->n.next, (off));                      \
		dlist_node_from_off_((void *)i, (off)) != &(h)->n;                       \
		i = dlist_node_to_off_(                                                  \
			dlist_node_from_off_((void *)i, (off))->next, (off)))

/**
 * dlist_for_each_safe_off - iterate through a list of memory regions, maybe
 * during deletion
 * @h: the dlist_head
 * @i: the pointer to a memory region wich contains list node data.
 * @nxt: the structure containing the dlist_node
 * @off: offset(relative to @i) at which list node data resides.
 *
 * For details see `dlist_for_each_off' and `dlist_for_each_safe'
 * descriptions.
 *
 * Example:
 *	dlist_for_each_safe_off(&parent->children, child,
 *		next, offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define dlist_for_each_safe_off(h, i, nxt, off)                                          \
	for (i = dlist_node_to_off_(dlist_debug(h)->n.next, (off)),                      \
	    nxt = dlist_node_to_off_(dlist_node_from_off_(i, (off))->next, (off));       \
		dlist_node_from_off_(i, (off)) != &(h)->n;                               \
		i = nxt,                                                                 \
	    nxt = dlist_node_to_off_(dlist_node_from_off_(i, (off))->next, (off)))

/* Other -off variants. */
#define dlist_entry_off(n, type, off) ((type *)dlist_node_from_off_((n), (off)))

#define dlist_head_off(h, type, off) ((type *)dlist_head_off((h), (off)))

#define dlist_tail_off(h, type, off) ((type *)dlist_tail_((h), (off)))

#define dlist_add_off(h, n, off) dlist_add((h), dlist_node_from_off_((n), (off)))

#define dlist_del_off(n, off) dlist_del(dlist_node_from_off_((n), (off)))

#define dlist_del_from_off(h, n, off) dlist_del_from(h, dlist_node_from_off_((n), (off)))

/* Offset helper functions so we only single-evaluate. */
static inline void *dlist_node_to_off_(struct dlist_node *node, size_t off)
{
	return (void *)((char *)node - off);
}

static inline struct dlist_node *dlist_node_from_off_(void *ptr, size_t off)
{
	return (struct dlist_node *)((char *)ptr + off);
}

/* Get the offset of the member, but make sure it's a dlist_node. */
#define dlist_off_(type, member)                                                         \
	(dlist_container_off(type, member) +                                             \
		check_type(((type *)0)->member, struct dlist_node))

#define dlist_off_var_(var, member)                                                      \
	(dlist_container_off_var(var, member) + check_type(var->member, struct dlist_node))

#endif /* _DPTR_LIST_H_ */
