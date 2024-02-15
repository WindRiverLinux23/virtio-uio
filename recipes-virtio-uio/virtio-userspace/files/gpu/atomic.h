/*
 * Copyright (c) 2024, Wind River Systems, Inc.
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

/*
modification history
--------------------
28jan24,qsn  ported from ACRN project
*/

#ifndef _ATOMIC_H_
#define _ATOMIC_H_

/* Test for GCC >= 4.7.0 */
#if ((__GNUC__ > 4) || (__GNUC__ == 4 && (__GNUC_MINOR__ >= 7)))

/* Since GCC 4.7.0, the __atomic builtins are introduced as a replacement of the
 * __sync ones. The original __sync builtins maps to their __atomic counter-part
 * using the __ATOMIC_SEQ_CST model and will be eventually deprecated. */

#define atomic_load(ptr)			\
	__atomic_load_n(ptr, __ATOMIC_SEQ_CST)

#define atomic_store(ptr, val)				\
	__atomic_store_n(ptr, val, __ATOMIC_SEQ_CST)

#define atomic_xchg(ptr, val)				\
	__atomic_exchange_n(ptr, val, __ATOMIC_SEQ_CST)

/* Note: expected should also be a pointer. */
#define atomic_cmpxchg(ptr, expected, desired)				\
	__atomic_compare_exchange_n(ptr, expected, desired,		\
				false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)

#define atomic_add_fetch(ptr, val)			\
	__atomic_add_fetch(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_sub_fetch(ptr, val)			\
	__atomic_sub_fetch(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_and_fetch(ptr, val)			\
	__atomic_and_fetch(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_xor_fetch(ptr, val)			\
	__atomic_xor_fetch(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_or_fetch(ptr, val)			\
	__atomic_or_fetch(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_nand_fetch(ptr, val)			\
	__atomic_nand_fetch(ptr, val, __ATOMIC_SEQ_CST)

#define atomic_fetch_add(ptr, val)			\
	__atomic_fetch_add(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(ptr, val)			\
	__atomic_fetch_sub(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_fetch_and(ptr, val)			\
	__atomic_fetch_and(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor(ptr, val)			\
	__atomic_fetch_xor(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_fetch_or(ptr, val)			\
	__atomic_fetch_or(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_fetch_nand(ptr, val)			\
	__atomic_fetch_nand(ptr, val, __ATOMIC_SEQ_CST)

#define atomic_test_and_set(ptr)		\
	__atomic_test_and_set(ptr, __ATOMIC_SEQ_CST)
#define atomic_clear(ptr)			\
	__atomic_clear(ptr, __ATOMIC_SEQ_CST)
#define atomic_thread_fence()			\
	__atomic_thread_fence(__ATOMIC_SEQ_CST)
#define atomic_signal_fence()			\
	__atomic_signal_fence(__ATOMIC_SEQ_CST)

#else  /* not GCC >= 4.7.0 */

/* __sync builtins do not have load/store interfaces. Use add_fetch and xchg to
 * mimic their functinality.
 *
 * Also note that __sync_lock_test_and_set is rather an atomic exchange
 * operation per GCC manual on the __sync builtins.
 */
#define atomic_load(ptr)			\
	__sync_add_and_fetch(ptr, 0)

#define atomic_store(ptr, val)			\
	(void)(__sync_lock_test_and_set(ptr, val))

#define atomic_xchg(ptr, val)			\
	__sync_lock_test_and_set(ptr, val)

/* Note: expected should also be a pointer. */
#define atomic_cmpxchg(ptr, expected, desired)			\
	__sync_bool_compare_and_swap(ptr, (*(expected)), desired)

#define atomic_add_fetch(ptr, val)		\
	__sync_add_and_fetch(ptr, val)
#define atomic_sub_fetch(ptr, val)		\
	__sync_sub_and_fetch(ptr, val)
#define atomic_and_fetch(ptr, val)		\
	__sync_and_and_fetch(ptr, val)
#define atomic_xor_fetch(ptr, val)		\
	__sync_xor_and_fetch(ptr, val)
#define atomic_or_fetch(ptr, val)		\
	__sync_or_and_fetch(ptr, val)
#define atomic_nand_fetch(ptr, val)		\
	__sync_nand_and_fetch(ptr, val)

#define atomic_fetch_add(ptr, val)		\
	__sync_fetch_and_add(ptr, val)
#define atomic_fetch_sub(ptr, val)		\
	__sync_fetch_and_sub(ptr, val)
#define atomic_fetch_and(ptr, val)		\
	__sync_fetch_and_and(ptr, val)
#define atomic_fetch_xor(ptr, val)		\
	__sync_fetch_and_xor(ptr, val)
#define atomic_fetch_or(ptr, val)		\
	__sync_fetch_and_or(ptr, val)
#define atomic_fetch_nand(ptr, val)		\
	__sync_fetch_and_nand(ptr, val)

#define atomic_test_and_set(ptr)		\
	(bool)(__sync_lock_test_and_set(ptr, 1))
#define atomic_clear(ptr)			\
	__sync_lock_release(ptr)
#define atomic_thread_fence()			\
	__sync_synchronize()
#define atomic_signal_fence()			\
	__sync_synchronize()

#endif /* GCC >= 4.7.0 */

#endif /* _ATOMIC_H_ */
