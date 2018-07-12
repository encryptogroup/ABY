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

#include "../ABY_utils/ABYconstants.h"
#include "../ENCRYPTO_utils/timer.h"
#include <memory>
#include <vector>


#ifdef DEBUGCOMM
#include <mutex>
#endif

class ABYCircuit;
class ABYSetup;
class channel;
struct comm_ctx;
class crypto;
class Sharing;
struct GATE;
class CEvent;
class CLock;

class ABYParty {
public:
	ABYParty(e_role pid, const char* addr = (char*) "127.0.0.1", uint16_t port = 7766, seclvl seclvl = LT, uint32_t bitlen = 32,
			uint32_t nthreads =	2, e_mt_gen_alg mg_algo = MT_OT, uint32_t maxgates = 4000000);
	~ABYParty();

	std::vector<Sharing*>& GetSharings();
	void ExecCircuit();

	void Reset();

	double GetTiming(ABYPHASE phase);
	uint64_t GetSentData(ABYPHASE phase);
	uint64_t GetReceivedData(ABYPHASE phase);


private:
	BOOL Init();
	void Cleanup();

	BOOL InitCircuit(uint32_t bitlen, uint32_t maxgates);

	BOOL EstablishConnection();

	BOOL ABYPartyListen();
	BOOL ABYPartyConnect();

	BOOL EvaluateCircuit();

	void BuildCircuit();
	void BuildBoolMult(uint32_t bitlen, uint32_t resbitlen, uint32_t nvals);
	void BuildBoolAdd(uint32_t bitlen, uint32_t nvals);

	void InstantiateGate(uint32_t gateid);
	void UsedGate(uint32_t gateid);

	BOOL PerformInteraction();
	BOOL ThreadSendValues();
	BOOL ThreadReceiveValues();

	void PrintPerformanceStatistics();

	e_mt_gen_alg m_eMTGenAlg;
	ABYSetup* m_pSetup;

	// Network Communication
	std::vector<CSocket*> m_vSockets; // sockets for threads
	e_role m_eRole; // thread id
	uint16_t m_nPort;
	seclvl m_sSecLvl;

	uint32_t m_nNumOTThreads;

	uint32_t m_nHelperThreads;

	const char* m_cAddress;

	uint32_t m_nDepth;

	uint32_t m_nMyNumInBits;
	// Ciruit
	ABYCircuit* m_pCircuit;
	GATE* m_pGates;

	uint32_t m_nSizeOfVal;

	std::vector<Sharing*> m_vSharings;

	crypto* m_cCrypt;
	CLock *glock;

	enum EPartyJobType {
		e_Party_Comm, e_Party_Stop, e_Party_Undefined
	};

	comm_ctx* m_tComm;

	channel* m_tPartyChan;
#ifdef DEBUGCOMM
	std::mutex cout_mutex;
#endif

	class CPartyWorkerThread;

	BOOL WakeupWorkerThreads(EPartyJobType);
	BOOL WaitWorkerThreads();
	BOOL ThreadNotifyTaskDone(BOOL);

	std::vector<CPartyWorkerThread*> m_vThreads;
	std::unique_ptr<CEvent> m_evt;
	std::unique_ptr<CLock> m_lock;

	uint32_t m_nWorkingThreads;
	BOOL m_bWorkerThreadSuccess;

};

#endif //__ABYPARTY_H__

