/*
 * snd_thread.h
 *
 *  Created on: Mar 9, 2015
 *      Author: mzohner
 */

#ifndef SND_THREAD_H_
#define SND_THREAD_H_

#include "typedefs.h"
#include "constants.h"
#include "socket.h"
#include "thread.h"

struct snd_task {
	uint8_t channelid;
	uint64_t bytelen;
	uint8_t* snd_buf;
};


class SndThread: public CThread {
public:
	SndThread(CSocket* sock) {
		mysock = sock;
		sndlock = new CLock();
		send = new CEvent();
	}
	;

	void stop() {
		kill_task();
	}

	~SndThread() {
		kill_task();
		this->Wait();
	}
	;

	void add_snd_task_start_len(uint8_t channelid, uint64_t sndbytes, uint8_t* sndbuf, uint64_t startid, uint64_t len) {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		assert(channelid != ADMIN_CHANNEL);
		task->channelid = channelid;
		task->bytelen = sndbytes + 2 * sizeof(uint64_t);
		task->snd_buf = (uint8_t*) malloc(task->bytelen);
		memcpy(task->snd_buf, &startid, sizeof(uint64_t));
		memcpy(task->snd_buf+sizeof(uint64_t), &len, sizeof(uint64_t));
		memcpy(task->snd_buf+2*sizeof(uint64_t), sndbuf, sndbytes);

		//cout << "Adding a new task that is supposed to send " << task->bytelen << " bytes on channel " << (uint32_t) channelid  << endl;

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
	}


	void add_snd_task(uint8_t channelid, uint64_t sndbytes, uint8_t* sndbuf) {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		assert(channelid != ADMIN_CHANNEL);
		task->channelid = channelid;
		task->bytelen = sndbytes;
		task->snd_buf = (uint8_t*) malloc(sndbytes);
		memcpy(task->snd_buf, sndbuf, task->bytelen);

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
		//cout << "Event set" << endl;

	}

	void signal_end(uint8_t channelid) {
		uint8_t dummy_val;
		add_snd_task(channelid, 0, &dummy_val);
		//cout << "Signalling end on channel " << (uint32_t) channelid << endl;
	}

	void kill_task() {
		snd_task* task = (snd_task*) malloc(sizeof(snd_task));
		task->channelid = ADMIN_CHANNEL;
		task->bytelen = 1;
		task->snd_buf = (uint8_t*) malloc(1);

		sndlock->Lock();
		send_tasks.push(task);
		sndlock->Unlock();
		send->Set();
#ifdef DEBUG_SEND_THREAD
		cout << "Killing channel " << (uint32_t) task->channelid << endl;
#endif
	}

	void ThreadMain() {
		uint8_t channelid;
		uint32_t iters;
		snd_task* task;
		bool run = true;
		while(run) {
			if(send_tasks.empty())
				send->Wait();
			//cout << "Awoken" << endl;

			sndlock->Lock();
			iters = send_tasks.size();
			sndlock->Unlock();

			while((iters--) && run) {
				task = send_tasks.front();
				send_tasks.pop();
				channelid = task->channelid;
				mysock->Send(&channelid, sizeof(uint8_t));
				mysock->Send(&task->bytelen, sizeof(uint64_t));
				if(task->bytelen > 0) {
					mysock->Send(task->snd_buf, task->bytelen);
				}

#ifdef DEBUG_SEND_THREAD
				cout << "Sending on channel " <<  (uint32_t) channelid << " a message of " << task->bytelen << " bytes length" << endl;
#endif

				free(task->snd_buf);
				free(task);

				if(channelid == ADMIN_CHANNEL) {
					delete sndlock;
					delete send;
					run = false;
				}
			}
		}
	}
	;
private:
	CLock* sndlock;
	CSocket* mysock;
	CEvent* send;
	std::queue<snd_task*> send_tasks;
};



#endif /* SND_THREAD_H_ */
