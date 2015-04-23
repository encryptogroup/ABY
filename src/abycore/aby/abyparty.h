/**
 \file 		abyparty.h
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
 \brief		ABYParty class.
 */

#ifndef __ABYPARTY_H__
#define __ABYPARTY_H__

#include "../util/typedefs.h"
#include "../util/crypto/crypto.h"
#include "../circuit/abycircuit.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "abysetup.h"
#include "../sharing/sharing.h"
#include "../sharing/boolsharing.h"
#include <vector>
#include "../util/timer.h"
#include "../sharing/yaoclientsharing.h"
#include "../sharing/yaoserversharing.h"
#include "../sharing/arithsharing.h"

#include "../util/yaokey.h"

#include <limits.h>
#include "../util/connection.h"

//#define ABYDEBUG
//#define PRINT_OUTPUT
//#define DEBUGABYPARTY
//#define BENCHONLINEPHASE
//#define PRINT_PERFORMANCE_STATS
//#define DEBUGCOMM
//#define BATCH

using namespace std;

class ABYParty {
public:
	ABYParty(e_role pid, char* addr, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mg_algo = MT_OT);
	~ABYParty();

	vector<Sharing*>& GetSharings() {
		return m_vSharings;
	}
	CBitVector ExecCircuit();
	CBitVector ExecSetupPhase();
	uint32_t GetMyInput(CBitVector& in); //TODO deprecated, used only for benchmarking reasons where input is random
	uint32_t GetOtherInput(CBitVector &otherin); //used for verification, parties exchange inputs

	uint32_t GetOutput(CBitVector& out);
	void Reset();

	double GetTiming(ABYPHASE phase);

private:
	BOOL Init();
	void Cleanup();

	BOOL InitCircuit(uint32_t bitlen);

	BOOL EstablishConnection();

	BOOL ABYPartyListen();
	BOOL ABYPartyConnect();

	BOOL AssignInputValues();
	BOOL EvaluateCircuit();

	void BuildCircuit();
	void BuildBoolMult(uint32_t bitlen, uint32_t resbitlen, uint32_t nvals);
	void BuildBoolAdd(uint32_t bitlen, uint32_t nvals);

	void InstantiateGate(uint32_t gateid);
	void UsedGate(uint32_t gateid);

	BOOL PerformInteraction();
	BOOL ThreadSendValues();
	BOOL ThreadReceiveValues();

	BOOL PrintInput();
	void PrintOutput();

#ifdef VERIFYABYRES
	BOOL VerifyResult();
#endif

	void PrintPerformanceStatistics();

	e_mt_gen_alg m_eMTGenAlg;
	ABYSetup* m_pSetup;

	// Network Communication
	vector<CSocket> m_vSockets; // sockets for threads
	e_role m_eRole; // thread id
	short m_nPort;
	seclvl m_sSecLvl;

	uint32_t m_nNumOTThreads;

	uint32_t m_nHelperThreads;

	char* m_cAddress;

	uint32_t m_nDepth;

	uint32_t m_nMyNumInBits;
	// Ciruit
	ABYCircuit* m_pCircuit;
	GATE* m_pGates;

	uint32_t m_nSizeOfVal;

	// Input values
	CBitVector m_vInputBits;

	//constant 128-bit seed, IMPORTANT: exclude if used in practice
	BYTE* m_cConstantInsecureSeed;

	vector<Sharing*> m_vSharings;

	crypto* m_cCrypt;

	enum EPartyJobType {
		e_Party_Comm, e_Party_Stop,
	};

	class CPartyWorkerThread: public CThread {
	public:
		CPartyWorkerThread(uint32_t id, ABYParty* callback) :
				threadid(id), m_pCallback(callback) {
		}
		;
		void PutJob(EPartyJobType e) {
			m_eJob = e;
			m_evt.Set();
		}
		void ThreadMain();
		uint32_t threadid;
		ABYParty* m_pCallback;
		CEvent m_evt;
		EPartyJobType m_eJob;
	};

	BOOL WakeupWorkerThreads(EPartyJobType);
	BOOL WaitWorkerThreads();
	BOOL ThreadNotifyTaskDone(BOOL);

	vector<CPartyWorkerThread*> m_vThreads;
	CEvent m_evt;
	CLock m_lock;

	uint32_t m_nWorkingThreads;
	BOOL m_bWorkerThreadSuccess;

};

#endif //__ABYPARTY_H__

