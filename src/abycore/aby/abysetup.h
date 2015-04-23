/**
 \file 		abysetup.h
 \author	michael.zohner@ec-spride.de
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
 \brief		Contains all methods that are processed during the setup phase of ABY
 */

#ifndef __ABYSETUP_H__
#define __ABYSETUP_H__

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../ot/naor-pinkas.h"
#include "../ot/ot-extension.h"
#include "../ot/xormasking.h"
#include "../ot/arithmtmasking.h"
#include "../DJN/djnparty.h"
#include "../DGK/dgkparty.h"
#include "../util/constants.h"

//#define DEBUGSETUP
//define BENCH_PRECOMP

/* Unification for the required OTs */
struct OTSenderVals {
	CBitVector* X0; //X0 in the OTs
	CBitVector* X1; //X1 in the OTs
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

union PartyValues {
	struct OTSenderVals sndval;
	struct OTReceiverVals rcvval;
};

struct OTTask {
	BYTE ottype; //which OT type (G-OT, C-OT, R-OT)
	uint32_t numOTs;	//number of OTs that are performed
	uint32_t bitlen; //bitlen in the OTs
	MaskingFunction* mskfct; //the masking function used
	PartyValues pval;   //contains the sender and receivers input and output
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
	~ABYSetup() {
		Cleanup();
	}

	void Reset();

	BOOL PrepareSetupPhase(vector<CSocket>& sockets);
	BOOL PerformSetupPhase(vector<CSocket>& sockets);

	//TODO: the OTTasks are still quite unstraightforward, also combine in an intuitive way with multthreading
	void AddOTTask(OTTask* task, uint32_t inverse) {
		m_vOTTasks[inverse].push_back(task);
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

	BOOL ThreadRunNPSnd(uint32_t exec);
	BOOL ThreadRunNPRcv(uint32_t exec);

	BOOL ThreadRunIKNPSnd(uint32_t exec);
	BOOL ThreadRunIKNPRcv(uint32_t exec);

	BOOL ThreadSendData(uint32_t exec);
	BOOL ThreadReceiveData(uint32_t exec);

	BOOL ThreadRunPaillierMTGen(uint32_t exec);
	BOOL ThreadRunDGKMTGen(uint32_t threadid);

	// OTTask values
	vector<vector<OTTask*> > m_vOTTasks;

	vector<PKMTGenVals*> m_vPKMTGenTasks;
	DJNParty* m_cPaillierMTGen;
	DGKParty** m_cDGKMTGen;

	// NTL: Naor-Pinkas OT
	BaseOT *np;
	CBitVector m_vU;
	uint32_t m_nIKNPProgress;
	BYTE* m_vKeySeeds;
	BYTE* m_vKeySeedMtx;
	uint32_t m_nSndVals;
	uint32_t m_nNumOTThreads;
	vector<CSocket> m_vSockets;
	//BYTE*					m_aSeed;
	e_role m_eRole;

	SendTask m_tsndtask;
	ReceiveTask m_trcvtask;

	e_mt_gen_alg m_eMTGenAlg;

	crypto* m_cCrypt;

	/* Thread information */

	enum EJobType {
		e_OTExt, e_NP, e_Send, e_Receive, e_Transmit, e_Stop, e_MTPaillier, e_MTDGK,
	};

	BOOL WakeupWorkerThreads(EJobType);
	BOOL WaitWorkerThreads();
	BOOL ThreadNotifyTaskDone(BOOL);

	class CWorkerThread: public CThread {
	public:
		CWorkerThread(uint32_t i, ABYSetup* callback) :
				threadid(i), m_pCallback(callback) {
		}
		void PutJob(EJobType e) {
			m_eJob = e;
			m_evt.Set();
		}
		void ThreadMain();
		uint32_t threadid;
		ABYSetup* m_pCallback;
		CEvent m_evt;
		EJobType m_eJob;
	};

	vector<CWorkerThread*> m_vThreads;
	CEvent m_evt;
	CLock m_lock;

	uint32_t m_nWorkingThreads;
	BOOL m_bWorkerThreadSuccess;

};

#endif //__ABYSETUP_H__

