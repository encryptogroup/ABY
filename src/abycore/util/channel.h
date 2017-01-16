/*
 * channel.h
 *
 *  Created on: Mar 9, 2015
 *      Author: mzohner
 */

#ifndef CHANNEL_H_
#define CHANNEL_H_

#include "typedefs.h"
#include "socket.h"
#include "rcvthread.h"
#include "sndthread.h"

class channel {
public:
	channel(uint8_t channelid, RcvThread* rcver, SndThread* snder) {
		m_cRcver = rcver;
		m_cSnder = snder;
		m_bChannelID = channelid;
		m_eRcved = new CEvent;
		m_eFin = new CEvent;
		m_qRcvedBlocks = rcver->add_listener(channelid, m_eRcved, m_eFin);
		m_bSndAlive = true;
		m_bRcvAlive = true;
	}

	~channel() {
		if(m_bRcvAlive) {
			m_cRcver->remove_listener(m_bChannelID);
		}

		delete m_eRcved;
		delete m_eFin;
	}

	void send(uint8_t* buf, uint64_t nbytes) {
		assert(m_bSndAlive);
		m_cSnder->add_snd_task(m_bChannelID, nbytes, buf);
	}
	void send_id_len(uint8_t* buf, uint64_t nbytes, uint64_t id, uint64_t len) {
		assert(m_bSndAlive);
		m_cSnder->add_snd_task_start_len(m_bChannelID, nbytes, buf, id, len);
	}

	//buf needs to be freed, data contains the payload
	uint8_t* blocking_receive_id_len(uint8_t** data, uint64_t* id, uint64_t* len) {
		uint8_t* buf = blocking_receive();
		*data = buf;
		*id = *((uint64_t*) *data);
		(*data)  += sizeof(uint64_t);
		*len = *((uint64_t*) *data);
		(*data) += sizeof(uint64_t);

		return buf;
	}

	uint8_t* blocking_receive() {
		assert(m_bRcvAlive);
		while(m_qRcvedBlocks->empty())
			m_eRcved->Wait();
		uint8_t* ret_block = ((rcv_ctx*)m_qRcvedBlocks->front())->buf;
		m_qRcvedBlocks->pop();

		return ret_block;
	}

	void blocking_receive(uint8_t* rcvbuf, uint64_t rcvsize) {
		assert(m_bRcvAlive);
		while(m_qRcvedBlocks->empty())
			m_eRcved->Wait();


		uint8_t* ret_block = ((rcv_ctx*) m_qRcvedBlocks->front())->buf;
		uint64_t rcved_this_call = ((rcv_ctx*) m_qRcvedBlocks->front())->rcvbytes;
		if(rcved_this_call == rcvsize) {
			m_qRcvedBlocks->pop();
		} else if(rcvsize < rcved_this_call) {
			//if the block contains too much data, copy only the receive size
			((rcv_ctx*) m_qRcvedBlocks->front())->rcvbytes -= rcvsize;
			uint8_t* newbuf = (uint8_t*) malloc(((rcv_ctx*) m_qRcvedBlocks->front())->rcvbytes);
			memcpy(newbuf, ((rcv_ctx*) m_qRcvedBlocks->front())->buf+rcvsize, ((rcv_ctx*) m_qRcvedBlocks->front())->rcvbytes);
			((rcv_ctx*) m_qRcvedBlocks->front())->buf = newbuf;
			rcved_this_call = rcvsize;
		} else {
			//I want to receive more data than are in that block. Perform recursive call (might become troublesome for too many recursion steps)
			m_qRcvedBlocks->pop();
			uint8_t* new_rcvbuf_start = rcvbuf + rcved_this_call;
			uint64_t new_rcvsize = rcvsize -rcved_this_call;

			blocking_receive(new_rcvbuf_start, new_rcvsize);
		}
		memcpy(rcvbuf, ret_block, rcved_this_call);
		free(ret_block);
	}


	bool is_alive() {
		return (!(m_qRcvedBlocks->empty() && m_eFin->IsSet()));
	}

	bool data_available() {
		return !m_qRcvedBlocks->empty();
	}

	void signal_end() {
		m_cSnder->signal_end(m_bChannelID);
		m_bSndAlive = false;
	}

	void wait_for_fin() {
		m_eFin->Wait();
		m_bRcvAlive = false;
	}

	//TODO
	void synchronize() {

	}

	void synchronize_end() {
		if(m_bSndAlive)
			signal_end();
		if(m_bRcvAlive)
			m_cRcver->flush_queue(m_bChannelID);
		if(m_bRcvAlive)
			wait_for_fin();

	}

private:
	RcvThread* m_cRcver;
	SndThread* m_cSnder;
	CEvent* m_eRcved;
	CEvent* m_eFin;
	uint8_t m_bChannelID;
	queue<rcv_ctx*>* m_qRcvedBlocks;
	bool m_bSndAlive;
	bool m_bRcvAlive;
};


#endif /* CHANNEL_H_ */
