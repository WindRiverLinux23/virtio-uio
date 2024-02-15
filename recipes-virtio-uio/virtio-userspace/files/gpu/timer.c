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

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/timerfd.h>

#include  <stdint.h>

#include "../mevent.h"
#include "timer.h"
#include "virtio_host_gpu_cfg.h"

/* We can use timerfd and epoll mechanism to emulate kinds of timers like
 * PIT/RTC/WDT/PMTIMER/... in device model under Linux.
 * Compare with sigevent mechanism, timerfd has a advantage that it could
 * avoid race condition on resource accessing in the async sigev thread.
 *
 * Please note timerfd and epoll are all Linux specific. If the code need to be
 * ported to other OS, we can modify the api with POSIX timers and sigevent
 * mechanism.
 */

static void
timer_handler(int fd __attribute__((unused)),
		  enum ev_type t __attribute__((unused)),
		  void *arg)
{
	struct acrn_timer *timer = arg;
	uint64_t nexp;
	ssize_t size;
	void (*cb)(void *, uint64_t);

	if (timer == NULL) {
		return;
	}

	/* Consume I/O event for default EPOLLLT type.
	 * Here is a temporary solution, the processing could be moved to
	 * mevent.c once EVF_TIMER is supported.
	 */
	size = read(timer->fd, &nexp, sizeof(nexp));

	if (size < 0) {
		if (errno != EAGAIN) {
			VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "acrn_timer read timerfd error");
		}
		return;
	}

	/* check the validity of timer expiration. */
	if ((size == 0) || (nexp == 0))
		return;

	if ((cb = timer->callback) != NULL) {
		(*cb)(timer->callback_param, nexp);
	}
}

int32_t
acrn_timer_init(struct acrn_timer *timer, void (*cb)(void *, uint64_t),
		void *param)
{
	if ((timer == NULL) || (cb == NULL)) {
		return -1;
	}

	timer->fd = -1;
	if ((timer->clockid == CLOCK_REALTIME) ||
			(timer->clockid == CLOCK_MONOTONIC)) {
		timer->fd = timerfd_create(timer->clockid,
					TFD_NONBLOCK | TFD_CLOEXEC);
	} else {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "acrn_timer clockid is not supported.\n");
	}

	if (timer->fd <= 0) {
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "acrn_timer create failed.\n");
		return -1;
	}

	timer->mevp = mevent_add(timer->fd, EVF_READ, timer_handler, timer, NULL, NULL);
	if (timer->mevp == NULL) {
		close(timer->fd);
		VIRTIO_GPU_DEV_DBG(VIRTIO_GPU_DEV_DBG_ERR, "acrn_timer mevent add failed.\n");
		return -1;
	}

	timer->callback = cb;
	timer->callback_param = param;

	return 0;
}

void
acrn_timer_deinit(struct acrn_timer *timer)
{
	if (timer == NULL) {
		return;
	}

	if (timer->mevp != NULL) {
		mevent_delete_close(timer->mevp);
		timer->mevp = NULL;
	}

	timer->fd = -1;
	timer->callback = NULL;
	timer->callback_param = NULL;
}

int32_t
acrn_timer_settime(struct acrn_timer *timer, const struct itimerspec *new_value)
{
	if (timer == NULL) {
		errno = EINVAL;
		return -1;
	}

	return timerfd_settime(timer->fd, 0, new_value, NULL);
}

int32_t
acrn_timer_settime_abs(struct acrn_timer *timer,
		const struct itimerspec *new_value)
{
	if (timer == NULL) {
		errno = EINVAL;
		return -1;
	}

	return timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, new_value, NULL);
}

int32_t
acrn_timer_gettime(struct acrn_timer *timer, struct itimerspec *cur_value)
{
	if (timer == NULL) {
		errno = EINVAL;
		return -1;
	}

	return timerfd_gettime(timer->fd, cur_value);
}

int32_t
acrn_timer_disable(struct acrn_timer *timer)
{
        if (timer == NULL) {
                errno = EINVAL;
                return -1;
        }

        return mevent_disable(timer->mevp);
}

int32_t
acrn_timer_enable(struct acrn_timer *timer)
{
        if (timer == NULL) {
                errno = EINVAL;
                return -1;
        }

        return mevent_enable(timer->mevp);
}

