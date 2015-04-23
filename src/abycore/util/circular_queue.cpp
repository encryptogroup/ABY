/**
 \file 		circular_queue.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Circular Queue Implementation
 */

#include "circular_queue.h"

CQueue::CQueue(int maxsize) {
	head = 0;
	tail = 0;

	queuesize = maxsize;
	queue = (int*) malloc(sizeof(int) * queuesize);
}

void CQueue::enq(int ele) {
	queue[head] = ele;
	head = (head + 1) % queuesize;
}

int CQueue::deq() {
	int ret = queue[tail];
	tail = (tail + 1) % queuesize;
	return ret;
}

int CQueue::size() {
	int rem = (head - tail) % queuesize;
	if (rem < 0)
		return queuesize + rem;
	else
		return rem;
}

