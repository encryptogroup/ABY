/**
 \file 		abysetup.h
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Contains all methods that are processed during the setup phase of ABY
 */

#ifndef __ABYSETUP_H__
#define __ABYSETUP_H__

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include "../ABY_utils/ABYconstants.h"
#include <ot/naor-pinkas.h>
#include <ot/ot-ext.h>
#include <ot/xormasking.h>
#include "../ot/arithmtmasking.h"
#include <ot/iknp-ot-ext-snd.h>
#include <ot/iknp-ot-ext-rec.h>
#include <ot/kk-ot-ext-snd.h>
#include <ot/kk-ot-ext-rec.h>
#include "../DJN/djnparty.h"
#include "../DGK/dgkparty.h"
#include <ENCRYPTO_utils/constants.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <memory>
#include <mutex>

struct comm_ctx {
	std::unique_ptr<RcvThread> rcv_std, rcv_inv;
	std::unique_ptr<SndThread> snd_std, snd_inv;
};


//#define DEBUGSETUP
//define BENCH_PRECOMP

/* Unification for the required OTs */
struct IKNPOTSenderVals {
	CBitVector* X0; //X0 in the OTs
	CBitVector* X1; //X1 in the OTs
};

struct KKOTSenderVals {
	CBitVector** X; //X values in the 1ooN OT
};

struct OTReceiverVals {
	CBitVector* C; //choice bits in the OTs
	CBitVector* R; //received strings
};

struct PKMTGenVals {
	CBitVector* A;
	CBitVector* B;
	CBitVector* C;
	uint32_t numMTs;
	uint32_t sharebitlen;
};

union IKNPPartyValues {
	struct IKNPOTSenderVals sndval;
	struct OTReceiverVals rcvval;
};

union KKPartyValues {
	struct KKOTSenderVals sndval;
	struct OTReceiverVals rcvval;
};

struct IKNP_OTTask {
	//BYTE ottype; //which OT type (G-OT, C-OT, R-OT)
	snd_ot_flavor snd_flavor; //whether to perform Snd_OT, Snd_C_OT, Snd_R_OT, Snd_GC_OT
	rec_ot_flavor rec_flavor; //whether to perform Rec_OT, Rec_R_OT
	uint32_t numOTs;	//number of OTs that are performed
	uint32_t bitlen; //bitlen in the OTs
	MaskingFunction* mskfct; //the masking function used
	BOOL delete_mskfct; // whether or not to delete mskfct when the task is done
	IKNPPartyValues pval;   //contains the sender and receivers input and output
};

struct KK_OTTask {
	//BYTE ottype; //which OT type (G-OT, C-OT, R-OT)
	snd_ot_flavor snd_flavor; //whether to perform Snd_OT, Snd_C_OT, Snd_R_OT, Snd_GC_OT
	rec_ot_flavor rec_flavor; //whether to perform Rec_OT, Rec_R_OT
	uint32_t nsndvals;
	uint32_t numOTs;	//number of OTs that are performed
	uint32_t bitlen; //bitlen in the OTs
	MaskingFunction* mskfct; //the masking function used
	BOOL delete_mskfct; // whether or not to delete mskfct when the task is done
	KKPartyValues pval;   //contains the sender and receivers input and output
};

struct SendTask {
	uint64_t sndbytes; 	//number of bytes to be sent
	BYTE* sndbuf; 	  	//buffer for the result
};

struct ReceiveTask {
	uint64_t rcvbytes; 	//number of bytes to be sent
	BYTE* rcvbuf; 	  	//buffer for the result
};

class ABYSetup {

public:
	ABYSetup(crypto* crypt, uint32_t numThreads, e_role role, e_mt_gen_alg mtalgo);
	~ABYSetup();

	void Reset();

	BOOL PrepareSetupPhase(comm_ctx* comm);
	BOOL PerformSetupPhase();
	BOOL FinishSetupPhase();

	void AddOTTask(IKNP_OTTask* task, uint32_t inverse) {
		m_vIKNPOTTasks[inverse].push_back(task);
	}
	;

	void AddOTTask(KK_OTTask* task, uint32_t inverse) {
		m_vKKOTTasks[inverse].push_back(task);
	}
	;

	void AddPKMTGenTask(PKMTGenVals* task) {
		m_vPKMTGenTasks.push_back(task);
	}
	;

	//Both methods start a new thread but may stop if there is a thread already running
	void AddSendTask(BYTE* sndbuf, uint64_t sndbytes);
	void AddReceiveTask(BYTE* rcvbuf, uint64_t rcvbytes);

	BOOL WaitForTransmissionEnd();

private:
	BOOL Init();
	void Cleanup();

	BOOL ThreadRunNPSnd();
	BOOL ThreadRunNPRcv();

	BOOL ThreadRunIKNPSnd(uint32_t threadid);
	BOOL ThreadRunIKNPRcv(uint32_t threadid);

	BOOL ThreadRunKKSnd(uint32_t threadid);
	BOOL ThreadRunKKRcv(uint32_t threadid);

	BOOL ThreadSendData(uint32_t threadid);
	BOOL ThreadReceiveData();

	BOOL ThreadRunPaillierMTGen(uint32_t threadid);
	BOOL ThreadRunDGKMTGen(uint32_t threadid);

	// IKNP OTTask values
	std::vector<std::vector<IKNP_OTTask*> > m_vIKNPOTTasks;

	// KK OTTask values
	std::vector<std::vector<KK_OTTask*> > m_vKKOTTasks;

	std::vector<PKMTGenVals*> m_vPKMTGenTasks;
	DJNParty* m_cPaillierMTGen = nullptr;
	DGKParty** m_cDGKMTGen = nullptr;

	uint32_t m_nNumOTThreads;
	e_role m_eRole;

	SendTask m_tsndtask;
	ReceiveTask m_trcvtask;

	e_mt_gen_alg m_eMTGenAlg;

	crypto* m_cCrypt = nullptr;

	OTExtSnd *iknp_ot_sender = nullptr;
	OTExtRec *iknp_ot_receiver = nullptr;

	OTExtSnd *kk_ot_sender = nullptr;
	OTExtRec *kk_ot_receiver = nullptr;

	comm_ctx* m_tComm = nullptr;

	channel* m_tSetupChan = nullptr;
	//SndThread *sndthread_otsnd, *sndthread_otrcv;
	//RcvThread *rcvthread_otsnd, *rcvthread_otrcv;

	/* Thread information */

	enum EJobType {
		e_IKNPOTExt, e_KKOTExt, e_NP, e_Send, e_Receive, e_Transmit, e_Stop, e_MTPaillier, e_MTDGK, e_Undefined
	};

	BOOL WakeupWorkerThreads(EJobType);
	BOOL WaitWorkerThreads();
	BOOL ThreadNotifyTaskDone(BOOL);

	class CWorkerThread: public CThread {
	public:
		CWorkerThread(uint32_t i, ABYSetup* callback) :
				threadid(i), m_pCallback(callback) {
			m_eJob = e_Undefined;
		}
		void PutJob(EJobType e) {
			std::lock_guard<std::mutex> lock(m_eJob_mutex_);
			m_eJob = e;
			m_evt.Set();
		}
		CEvent* GetEvent() {
			return &m_evt;
		}
	private:
		void ThreadMain();
		uint32_t threadid;
		ABYSetup* m_pCallback;
		CEvent m_evt;
		EJobType m_eJob;
		std::mutex m_eJob_mutex_;
	};

	std::vector<CWorkerThread*> m_vThreads;
	CEvent m_evt;
	CLock m_lock;

	uint32_t m_nWorkingThreads;
	BOOL m_bWorkerThreadSuccess;


};

#endif //__ABYSETUP_H__
