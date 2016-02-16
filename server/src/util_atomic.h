/**
	\file util_atomic.h
	Defined some useful atomic operations for multithread parallel
*/

#ifndef UTIL_ATOMIC_H
#define UTIL_ATOMIC_H

#define atomic_increase(P)	__sync_fetch_and_add (P, 1)
#define atomic_decrease(P)	__sync_fetch_and_add (P, -1)
#define atomic_fetch_and_add(P, N)	__sync_fetch_and_add (P, N)
#define atomic_fetch_and_add64	atomic_fetch_and_add

#define atomic_cas(P, OLD, NEW)	__sync_bool_compare_and_swap(P, OLD, NEW)

#endif

