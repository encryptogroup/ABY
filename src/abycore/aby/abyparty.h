/**
 \file 		abyparty.h
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
 \brief		ABYParty class.
 */

#ifndef __ABYPARTY_H__
#define __ABYPARTY_H__

#include "../ABY_utils/ABYconstants.h"
#include <ENCRYPTO_utils/timer.h>
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
	ABYParty(e_role pid, const std::string& addr = "127.0.0.1", uint16_t port = 7766, seclvl seclvl = LT, uint32_t bitlen = 32,
			uint32_t nthreads =	2, e_mt_gen_alg mg_algo = MT_OT, uint32_t reservegates = 65536, const std::string& abycircdir = ABY_CIRCUIT_DIR);
	~ABYParty();

	/**
	 * Online part of initialization. Needs to be called after ABYParty has been
	 * construced. If not called, it is implicitly called at the first call to
	 * ExecCircuit() for backwards compatibility.
	 */
	void ConnectAndBaseOTs();

	std::vector<Sharing*>& GetSharings();
	void ExecCircuit();

	void Reset();

	double GetTiming(ABYPHASE phase);
	uint64_t GetSentData(ABYPHASE phase);
	uint64_t GetReceivedData(ABYPHASE phase);
	uint32_t GetTotalGates();
	uint32_t GetTotalDepth();

private:
	BOOL Init();
	void Cleanup();

	BOOL InitCircuit(uint32_t bitlen, uint32_t reservegates, const std::string& circdir = ABY_CIRCUIT_DIR);

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
	BOOL ThreadSendValues(uint32_t id);
	BOOL ThreadReceiveValues();

	void PrintPerformanceStatistics();

	// benchmarks AES performance
	void bench_aes() const;

	bool is_online = false;

	std::unique_ptr<crypto> m_cCrypt;
	std::unique_ptr<CLock> glock;

	e_mt_gen_alg m_eMTGenAlg;
	e_role m_eRole; // thread id
	uint32_t m_nNumOTThreads;

	// Order of destruction is important:
	// ABYSetup << comm_ctx << sockets
	std::vector<std::unique_ptr<CSocket>> m_vSockets; // sockets for threads

	std::unique_ptr<comm_ctx> m_tComm;

	std::unique_ptr<ABYSetup> m_pSetup;

	uint16_t m_nPort;
	seclvl m_sSecLvl;


	uint32_t m_nHelperThreads;

	const std::string m_cAddress;

	uint32_t m_nDepth;

	uint32_t m_nMyNumInBits;
	// Ciruit
	ABYCircuit* m_pCircuit;
	std::vector<GATE>* m_vGates;

	uint32_t m_nSizeOfVal;

	std::vector<Sharing*> m_vSharings;

	enum EPartyJobType {
		e_Party_Comm, e_Party_Stop, e_Party_Undefined
	};

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

