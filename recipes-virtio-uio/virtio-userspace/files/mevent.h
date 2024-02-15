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

#ifndef	_MEVENT_H_
#define	_MEVENT_H_

enum ev_type {
	EVF_READ,
	EVF_WRITE,
	EVF_READ_ET,
	EVF_WRITE_ET,
	EVF_TIMER,		/* Not supported yet */
	EVF_SIGNAL		/* Not supported yet */
};

struct mevent;

struct mevent *mevent_add(int fd, enum ev_type type,
			  void (*run)(int, enum ev_type, void *), void *param,
			  void (*teardown)(void *), void *teardown_param);
int	mevent_enable(struct mevent *evp);
int	mevent_disable(struct mevent *evp);
int	mevent_delete(struct mevent *evp);
int	mevent_delete_close(struct mevent *evp);
int	mevent_notify(void);

void	mevent_dispatch(void);
int	mevent_init(void);
void	mevent_deinit(void);

#define list_foreach_safe(var, head, field, tvar)	\
for ((var) = LIST_FIRST((head));			\
	(var) && ((tvar) = LIST_NEXT((var), field), 1);\
	(var) = (tvar))

#endif	/* _MEVENT_H_ */
