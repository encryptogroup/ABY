/*
 * rcv_thread.h
 *
 *  Created on: Mar 9, 2015
 *      Author: mzohner
 */

#ifndef RCV_THREAD_H_
#define RCV_THREAD_H_

#include "typedefs.h"
#include "constants.h"
#include "socket.h"
#include "thread.h"

typedef struct {
	uint8_t *buf;
	uint64_t rcvbytes;
} rcv_ctx;

//A receive task listens to a particular id and writes incoming data on that id into rcv_buf and triggers event
struct rcv_task {
	std::queue<rcv_ctx*>* rcv_buf;
	//std::queue<uint64_t> rcvbytes;
	CEvent* rcv_event;
	CEvent* fin_event;
	BOOL inuse;
	BOOL forward_notify_fin;
};


class RcvThread: public CThread {
public:
	RcvThread(CSocket* sock) {
		mysock = sock;
		rcvlock = new CLock();
		listeners = (rcv_task*) calloc(MAX_NUM_COMM_CHANNELS, sizeof(rcv_task));
		for(uint32_t i = 0; i < MAX_NUM_COMM_CHANNELS; i++) {
			listeners[i].rcv_buf = new queue<rcv_ctx*>;
		}
		listeners[ADMIN_CHANNEL].inuse = true;
	}
	;
	~RcvThread() {
		this->Wait();
		for(uint32_t i = 0; i < MAX_NUM_COMM_CHANNELS; i++) {
			flush_queue(i);
			delete listeners[i].rcv_buf;
		}
		free(listeners);
		delete rcvlock;
	}
	;

	void flush_queue(uint8_t channelid) {
		while(!listeners[channelid].rcv_buf->empty()) {
			rcv_ctx* tmp = listeners[channelid].rcv_buf->front();
			free(tmp->buf);
			free(tmp);
			listeners[channelid].rcv_buf->pop();
		}
	}

	void remove_listener(uint8_t channelid) {
		rcvlock->Lock();
		if(listeners[channelid].inuse) {
			listeners[channelid].fin_event->Set();
			listeners[channelid].inuse = false;

#ifdef DEBUG_RECEIVE_THREAD
			cout << "Unsetting channel " << (uint32_t) channelid << endl;
#endif
		} else {
			listeners[channelid].forward_notify_fin = true;
		}
		rcvlock->Unlock();

	}
	queue<rcv_ctx*>* add_listener(uint8_t channelid, CEvent* rcv_event, CEvent* fin_event) {
		rcvlock->Lock();
#ifdef DEBUG_RECEIVE_THREAD
		cout << "Registering listener on channel " << (uint32_t) channelid << endl;
#endif

		if(listeners[channelid].inuse || channelid == ADMIN_CHANNEL) {
			cerr << "A listener has already been registered on channel " << (uint32_t) channelid << endl;
			assert(!listeners[channelid].inuse);
			assert(channelid != ADMIN_CHANNEL);
		}

		//listeners[channelid].rcv_buf = rcv_buf;
		listeners[channelid].rcv_event = rcv_event;
		listeners[channelid].fin_event = fin_event;
		listeners[channelid].inuse = true;
//		assert(listeners[channelid].rcv_buf->empty());

		//cout << "Successfully registered on channel " << (uint32_t) channelid << endl;

		rcvlock->Unlock();

		if(listeners[channelid].forward_notify_fin) {
			listeners[channelid].forward_notify_fin = false;
			remove_listener(channelid);
		}
		return listeners[channelid].rcv_buf;
	}


	void ThreadMain() {
		uint8_t channelid;
		uint64_t rcvbytelen;
		uint8_t* tmprcvbuf;
		uint64_t rcv_len;
		while(true) {
			//cout << "Starting to receive data" << endl;
			rcv_len = 0;
			rcv_len += mysock->Receive(&channelid, sizeof(uint8_t));
			rcv_len += mysock->Receive(&rcvbytelen, sizeof(uint64_t));

			if(rcv_len > 0) {
#ifdef DEBUG_RECEIVE_THREAD
				cout << "Received value on channel " << (uint32_t) channelid << " with " << rcvbytelen <<
						" bytes length (" << rcv_len << ")" << endl;
#endif

				if(channelid == ADMIN_CHANNEL) {
					tmprcvbuf = (uint8_t*) malloc(rcvbytelen);
					mysock->Receive(tmprcvbuf, rcvbytelen);

					//TODO: Right now finish, can be used for other maintenance tasks
					free(tmprcvbuf);
					//cout << "Got message on Admin channel, shutting down" << endl;
#ifdef DEBUG_RECEIVE_THREAD
					cout << "Receiver thread is being killed" << endl;
#endif
					return;//continue;
				}

				if(rcvbytelen == 0) {
					remove_listener(channelid);
				} else {
					rcv_ctx* rcv_buf = (rcv_ctx*) malloc(sizeof(rcv_ctx));
					rcv_buf->buf = (uint8_t*) malloc(rcvbytelen);
					rcv_buf->rcvbytes = rcvbytelen;

					mysock->Receive(rcv_buf->buf, rcvbytelen);
					listeners[channelid].rcv_buf->push(rcv_buf);

					if(listeners[channelid].inuse)
						listeners[channelid].rcv_event->Set();
				}
			}

		}

	}
	;
private:
	CLock* rcvlock;
	CSocket* mysock;
	rcv_task* listeners;
};



#endif /* RCV_THREAD_H_ */
