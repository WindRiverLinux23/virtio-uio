/*
 * Copyright (C) 2018-2022 Intel Corporation.
 * SPDX-License-Identifier: BSD-3-Clause
 */

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

#ifndef _TIMER_H_
#define _TIMER_H_

#include <time.h>  // for struct itimerspec
#include <sys/param.h>

struct acrn_timer {
	int32_t fd;
	int32_t clockid;
	struct mevent *mevp;
	void (*callback)(void *, uint64_t);
	void *callback_param;
};

int32_t
acrn_timer_init(struct acrn_timer *timer, void (*cb)(void *, uint64_t), void *param);
void
acrn_timer_deinit(struct acrn_timer *timer);
int32_t
acrn_timer_settime(struct acrn_timer *timer, const struct itimerspec *new_value);
int32_t
acrn_timer_settime_abs(struct acrn_timer *timer,
		const struct itimerspec *new_value);
int32_t
acrn_timer_gettime(struct acrn_timer *timer, struct itimerspec *cur_value);

#define NS_PER_SEC	(1000000000ULL)

static inline uint64_t
ts_to_ticks(const uint32_t freq, const struct timespec *const ts)
{
	uint64_t tv_sec_ticks, tv_nsec_ticks;

	tv_sec_ticks = ts->tv_sec * freq;
	tv_nsec_ticks = (ts->tv_nsec * freq) / NS_PER_SEC;

	return tv_sec_ticks + tv_nsec_ticks;
}

static inline void
ticks_to_ts(const uint32_t freq, const uint64_t ticks,
		struct timespec *const ts)
{
	uint64_t ns;

	ns = howmany(ticks * NS_PER_SEC, freq);

	ts->tv_sec = ns / NS_PER_SEC;
	ts->tv_nsec = ns % NS_PER_SEC;
}

int32_t
acrn_timer_disable(struct acrn_timer *timer);
int32_t
acrn_timer_enable(struct acrn_timer *timer);

#endif /* _VTIMER_ */
