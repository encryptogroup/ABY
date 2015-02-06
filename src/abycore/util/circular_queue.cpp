/**
 \file 		circular_queue.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
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

