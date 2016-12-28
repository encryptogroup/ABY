/**
 \file 		abyparty.cpp
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

 \brief		ABYParty class implementation.
 */

#include "abyparty.h"

#include <sstream>

using namespace std;

#ifdef _DEBUG
#include <cassert>
using namespace std;
#endif

ABYParty::ABYParty(e_role pid, char* addr, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mg_algo, uint32_t maxgates, uint16_t port) {
	StartWatch("Initialization", P_INIT);

	m_eRole = pid;
	//cout << "m_eRole = " << m_eRole << endl;

	m_cAddress = addr;
	m_nPort = port;
	m_sSecLvl = seclvl;

	m_eMTGenAlg = mg_algo;

	//
	m_cCrypt = new crypto(seclvl.symbits);
	//m_aSeed = (uint8_t*) malloc(sizeof(uint8_t) * m_cCrypt->get_hash_bytes());

	//Are doubled to have both parties play both roles
	m_nNumOTThreads = nthreads;
#ifndef BATCH
	cout << "Performing Init" << endl;
#endif

	Init();

	m_pCircuit = NULL;
	StopWatch("Time for initiatlization: ", P_INIT);

#ifndef BATCH
	cout << "Generating circuit" << endl;
#endif
	StartWatch("Generating circuit", P_CIRCUIT);
	if (!InitCircuit(bitlen, maxgates)) {
		cout << "There was an while initializing the circuit, ending! " << endl;
		exit(0);
	}
	StopWatch("Time for circuit generation: ", P_CIRCUIT);

#ifndef BATCH
	cout << "Establishing network connection" << endl;
#endif
	//Establish network connection
	StartWatch("Establishing network connection: ", P_NETWORK);
	if (!EstablishConnection()) {
		cout << "There was an error during establish connection, ending! " << endl;
		exit(0);
	}
	StopWatch("Time for network connect: ", P_NETWORK);

#ifndef BATCH
	cout << "Performing base OTs" << endl;
#endif
	/* Pre-Compute Naor-Pinkas base OTs by starting two threads */
	StartRecording("Starting NP OT", P_BASE_OT, m_vSockets);
	m_pSetup->PrepareSetupPhase(m_tComm);
	StopRecording("Time for NP OT: ", P_BASE_OT, m_vSockets);
}

ABYParty::~ABYParty() {
	Cleanup();
}

BOOL ABYParty::Init() {
	//Threads that support execution by e.g. concurrent sending / receiving
	m_nHelperThreads = 2;

	m_cConstantInsecureSeed = (BYTE*) "00112233445566778899AABBCCDDEEFFF";

	//m_vSockets.resize(m_nNumOTThreads * 2);
	m_vSockets.resize(3);

	//Initialize necessary routines for computing the setup phase
	m_pSetup = new ABYSetup(m_cCrypt, m_nNumOTThreads, m_eRole, m_eMTGenAlg);

	m_vThreads.resize(m_nHelperThreads);
	for (uint32_t i = 0; i < m_nHelperThreads; i++) {
		m_vThreads[i] = new CPartyWorkerThread(i, this); //First thread is started as receiver, second as sender
		m_vThreads[i]->Start();
	}

	m_nMyNumInBits = 0;

	m_tComm = (comm_ctx*) malloc(sizeof(comm_ctx));

	return TRUE;
}

void ABYParty::Cleanup() {
	if (m_pCircuit)
		delete m_pCircuit;

	if (m_pSetup)
		delete m_pSetup;

	if(m_vSharings[S_BOOL])
		delete m_vSharings[S_BOOL];
	if(m_vSharings[S_YAO])
		delete m_vSharings[S_YAO];
	if(m_vSharings[S_ARITH])
		delete m_vSharings[S_ARITH];

	for (uint32_t i = 0; i < m_nHelperThreads; i++) {
		m_vThreads[i]->PutJob(e_Party_Stop);
		m_vThreads[i]->Wait();
		m_vThreads[i]->Kill();
		delete m_vThreads[i];
	}

	delete m_tComm->snd_std;
	delete m_tComm->snd_inv;

	free(m_tComm);

	for (uint32_t i = 0; i < m_vSockets.size(); i++) {
		m_vSockets[i]->Close();
	}
}

CBitVector ABYParty::ExecCircuit() {

#ifndef BATCH
	cout << "Finishing circuit generation" << endl;
#endif
	//Finish the circuit generation TODO check if this is required in later program versions
	m_pCircuit->FinishCircuitGeneration();

	CBitVector result;
	StartRecording("Starting execution", P_TOTAL, m_vSockets);

	//Setup phase
	StartRecording("Starting setup phase: ", P_SETUP, m_vSockets);
	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifndef BATCH
		cout << "Preparing setup phase for " << m_vSharings[i]->sharing_type() << " sharing" << endl;
#endif
		m_vSharings[i]->PrepareSetupPhase(m_pSetup);
	}

#ifndef BATCH
	cout << "Preforming OT extension" << endl;
#endif
	StartRecording("Starting OT Extension", P_OT_EXT, m_vSockets);
	m_pSetup->PerformSetupPhase();
	StopRecording("Time for OT Extension phase: ", P_OT_EXT, m_vSockets);

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifndef BATCH
		cout << "Performing setup phase for " << m_vSharings[i]->sharing_type() << " sharing" << endl;
#endif
		if (i == S_YAO) {
			StartRecording("Starting Circuit Garbling", P_GARBLE, m_vSockets);
		}
		m_vSharings[i]->PerformSetupPhase(m_pSetup);
		m_vSharings[i]->FinishSetupPhase(m_pSetup);
		if (i == S_YAO) {
			StopRecording("Time for Circuit garbling: ", P_GARBLE, m_vSockets);
		}
	}
	StopRecording("Time for setup phase: ", P_SETUP, m_vSockets);

#ifndef BATCH
	cout << "Evaluating circuit" << endl;
#endif
	//Online phase
	StartRecording("Starting online phase: ", P_ONLINE, m_vSockets);
	EvaluateCircuit();
	StopRecording("Time for online phase: ", P_ONLINE, m_vSockets);

	StopRecording("Total Time: ", P_TOTAL, m_vSockets);

#ifdef PRINT_OUTPUT
	//Print input and output gates
	PrintInput();
	PrintOutput();
#endif


#ifdef PRINT_PERFORMANCE_STATS
	PrintPerformanceStatistics();
#endif
	return result;
}

//TODO: deprecated!
CBitVector ABYParty::ExecSetupPhase() {

	//Finish the circuit generation TODO check if this is required in later program versions
	m_pCircuit->FinishCircuitGeneration();

	CBitVector result;
	StartWatch("Starting execution", P_TOTAL);

	//Setup phase
	StartWatch("Starting setup phase: ", P_SETUP);
	for (uint32_t i = 0; i < m_vSharings.size(); i++)
		m_vSharings[i]->PrepareSetupPhase(m_pSetup);

	StartWatch("Starting OT Extension", P_OT_EXT);
	m_pSetup->PerformSetupPhase();
	StopWatch("Time for OT Extension phase: ", P_OT_EXT);

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		if (i == S_YAO) {
			StartWatch("Starting Circuit Garbling", P_GARBLE);
		}
		m_vSharings[i]->PerformSetupPhase(m_pSetup);
		m_vSharings[i]->FinishSetupPhase(m_pSetup);
		if (i == S_YAO) {
			StopWatch("Time for Circuit garbling: ", P_GARBLE);
		}
	}
	StopWatch("Time for setup phase: ", P_SETUP);

	StopWatch("Total Time: ", P_TOTAL);

#ifdef PRINT_OUTPUT
	//Print input and output gates
	PrintInput();
	PrintOutput();
#endif


#ifdef PRINT_PERFORMANCE_STATS
	PrintPerformanceStatistics();
#endif

	return result;
}

BOOL ABYParty::InitCircuit(uint32_t bitlen, uint32_t maxgates) {
	// Specification of maximum amount of gates in constructor in abyparty.h
	m_pCircuit = new ABYCircuit(maxgates);

	//TODO change YaoSharing such that right class is passed back just given the role
	m_vSharings.resize(S_LAST);
	m_vSharings[S_BOOL] = new BoolSharing(m_eRole, 1, m_pCircuit, m_cCrypt);
	if (m_eRole == SERVER)
		m_vSharings[S_YAO] = new YaoServerSharing(m_eRole, m_sSecLvl.symbits, m_pCircuit, m_cCrypt);
	else
		m_vSharings[S_YAO] = new YaoClientSharing(m_eRole, m_sSecLvl.symbits, m_pCircuit, m_cCrypt);
	switch (bitlen) {
	case 8:
		m_vSharings[S_ARITH] = new ArithSharing<UINT8_T>(m_eRole, 1, m_pCircuit, m_cCrypt, m_eMTGenAlg);
		break;
	case 16:
		m_vSharings[S_ARITH] = new ArithSharing<UINT16_T>(m_eRole, 1, m_pCircuit, m_cCrypt, m_eMTGenAlg);
		break;
	case 32:
		m_vSharings[S_ARITH] = new ArithSharing<UINT32_T>(m_eRole, 1, m_pCircuit, m_cCrypt, m_eMTGenAlg);
		break;
	case 64:
		m_vSharings[S_ARITH] = new ArithSharing<UINT64_T>(m_eRole, 1, m_pCircuit, m_cCrypt, m_eMTGenAlg);
		break;
	default:
		m_vSharings[S_ARITH] = new ArithSharing<UINT32_T>(m_eRole, 1, m_pCircuit, m_cCrypt, m_eMTGenAlg);
		break;
	}

	m_pGates = m_pCircuit->Gates();

#ifndef BATCH
	cout << " circuit initialized..." << endl;
#endif

	return TRUE;
}

BOOL ABYParty::EvaluateCircuit() {
#ifdef BENCHONLINEPHASE
	timespec tstart, tend;
	double interaction=0;
	vector<double> localops(4,0);
	vector<double> interactiveops(4,0);
	vector<double> fincirclayer(4,0);
#endif
	m_nDepth = 0;

	m_tPartyChan = new channel(ABY_PARTY_CHANNEL, m_tComm->rcv_std, m_tComm->snd_std);

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		m_vSharings[i]->PrepareOnlinePhase();
	}

	uint32_t maxdepth = 0;

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		maxdepth = max(maxdepth, m_vSharings[i]->GetMaxCommunicationRounds());
	}
#ifdef DEBUGABYPARTY
	cout << "Starting online evaluation with maxdepth = " << maxdepth << endl;
#endif
	//Evaluate Circuit layerwise;
	for (uint32_t depth = 0; depth < maxdepth; depth++, m_nDepth++) {
#ifdef DEBUGABYPARTY
		cout << "Starting evaluation on depth " << depth << endl << flush;
#endif
		for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifdef DEBUGABYPARTY
			cout << "Evaluating local operations of sharing " << i << " on depth " << depth << endl;
#endif
#ifdef BENCHONLINEPHASE
			clock_gettime(CLOCK_MONOTONIC, &tstart);
#endif
			m_vSharings[i]->EvaluateLocalOperations(depth);
#ifdef BENCHONLINEPHASE
			clock_gettime(CLOCK_MONOTONIC, &tend);
			localops[i] += getMillies(tstart, tend);
			clock_gettime(CLOCK_MONOTONIC, &tstart);
#endif
#ifdef DEBUGABYPARTY
			cout << "Evaluating interactive operations of sharing " << i << endl;
#endif
			m_vSharings[i]->EvaluateInteractiveOperations(depth);
#ifdef BENCHONLINEPHASE
			clock_gettime(CLOCK_MONOTONIC, &tend);
			interactiveops[i] += getMillies(tstart, tend);
#endif
		}
#ifdef DEBUGABYPARTY
		cout << "Finished with evaluating operations on depth = " << depth << ", continuing with interactions" << endl;
#endif
#ifdef BENCHONLINEPHASE
		clock_gettime(CLOCK_MONOTONIC, &tstart);
#endif
		PerformInteraction();
#ifdef BENCHONLINEPHASE
		clock_gettime(CLOCK_MONOTONIC, &tend);
		interaction += getMillies(tstart, tend);
#endif
#ifdef DEBUGABYPARTY
		cout << "Done performing interaction, having sharings wrap up this circuit layer" << endl;
#endif
		for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifdef BENCHONLINEPHASE
			clock_gettime(CLOCK_MONOTONIC, &tstart);
#endif
			//cout << "Finishing circuit layer for sharing "<< i << endl;
			m_vSharings[i]->FinishCircuitLayer(depth);
#ifdef BENCHONLINEPHASE
			clock_gettime(CLOCK_MONOTONIC, &tend);
			fincirclayer[i] += getMillies(tstart, tend);
#endif
		}
	}
#ifdef DEBUGABYPARTY
		cout << "Done with online phase; synchronizing "<< endl;
#endif
	m_tPartyChan->synchronize_end();

#ifdef BENCHONLINEPHASE
	cout << "Online time is distributed as follows: " << endl;
	cout << "Bool: local gates: " << localops[S_BOOL] << ", interactive gates: " << interactiveops[S_BOOL] << ", layer finish: " << fincirclayer[S_BOOL] << endl;
	cout << "Yao: local gates: " << localops[S_YAO] << ", interactive gates: " << interactiveops[S_YAO] << ", layer finish: " << fincirclayer[S_YAO] << endl;
	cout << "Arith: local gates: " << localops[S_ARITH] << ", interactive gates: " << interactiveops[S_ARITH] << ", layer finish: " << fincirclayer[S_ARITH] << endl;
	cout << "Communication: " << interaction << endl;
#endif
	return true;
}

BOOL ABYParty::PerformInteraction() {
	WakeupWorkerThreads(e_Party_Comm);
	BOOL success = WaitWorkerThreads();
	return success;
}

BOOL ABYParty::ThreadSendValues() {
	vector<vector<BYTE*> >sendbuf(m_vSharings.size());
	vector<vector<uint64_t> >sndbytes(m_vSharings.size());

	timeval tstart, tend;
	uint64_t snd_buf_size_total = 0, ctr = 0;
	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		m_vSharings[j]->GetDataToSend(sendbuf[j], sndbytes[j]);
		for (uint32_t i = 0; i < sendbuf[j].size(); i++) {
			snd_buf_size_total += sndbytes[j][i];
#ifdef DEBUGCOMM
				cout << "(" << m_nDepth << ") Sending " << sndbytes[j][i] << " bytes on socket " << m_eRole << " for sharing " << j << endl;
#endif
		}
	}
	uint8_t* snd_buf_total = (uint8_t*) malloc(snd_buf_size_total);
	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		for (uint32_t i = 0; i < sendbuf[j].size(); i++) {
			if(sndbytes[j][i] > 0) {
				memcpy(snd_buf_total+ctr, sendbuf[j][i], sndbytes[j][i]);
				ctr+= sndbytes[j][i];
			}
		}
	}
	//gettimeofday(&tstart, NULL);
	if(snd_buf_size_total > 0) {
		m_vSockets[2]->Send(snd_buf_total, snd_buf_size_total);
	}

	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		sendbuf[j].clear();
		sndbytes[j].clear();
	}
	sendbuf.clear();
	sndbytes.clear();

	free(snd_buf_total);

	return true;
}

BOOL ABYParty::ThreadReceiveValues() {
	vector<vector<BYTE*> >rcvbuf(m_vSharings.size());
	vector<vector<uint64_t> >rcvbytes(m_vSharings.size());

	timeval tstart, tend;
	uint8_t* tmpbuf;


	uint64_t rcvbytestotal = 0;
	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		m_vSharings[j]->GetBuffersToReceive(rcvbuf[j], rcvbytes[j]);
		for (uint32_t i = 0; i < rcvbuf[j].size(); i++) {
			rcvbytestotal+=rcvbytes[j][i];
#ifdef DEBUGCOMM
				cout << "(" << m_nDepth << ") Receiving " << rcvbytes[i] << " bytes on socket " << (m_eRole^1) << " for sharing " << j << endl;
#endif
		}
	}
	uint8_t* rcvbuftotal = (uint8_t*) malloc(rcvbytestotal);
	//gettimeofday(&tstart, NULL);
	if(rcvbytestotal > 0)
		m_vSockets[2]->Receive(rcvbuftotal, rcvbytestotal);
	//gettimeofday(&tend, NULL);
	//cout << "(" << m_nDepth << ") Time taken for receiving " << rcvbytestotal << " bytes: " << getMillies(tstart, tend) << endl;

	for (uint32_t j = 0, ctr = 0; j < m_vSharings.size(); j++) {
		for (uint32_t i = 0; i < rcvbuf[j].size(); i++) {
			if(rcvbytes[j][i] > 0) {
				memcpy(rcvbuf[j][i], rcvbuftotal+ctr, rcvbytes[j][i]);
				ctr+= rcvbytes[j][i];
			}
		}
	}
	free(rcvbuftotal);

	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		rcvbuf[j].clear();
		rcvbytes[j].clear();
	}
	rcvbuf.clear();
	rcvbytes.clear();

	return true;
}


void ABYParty::PrintPerformanceStatistics() {
	cout << "Complexities: " << endl;
	m_vSharings[S_BOOL]->PrintPerformanceStatistics();
	m_vSharings[S_YAO]->PrintPerformanceStatistics();
	m_vSharings[S_ARITH]->PrintPerformanceStatistics();
	cout << "Total number of gates: " << m_pCircuit->GetGateHead() << endl;
	PrintTimings();
	PrintCommunication();
}

//=========================================================
// Connection Routines
BOOL ABYParty::EstablishConnection() {
	BOOL success = false;
	if (m_eRole == SERVER) {
		/*#ifndef BATCH
		 cout << "Server starting to listen" << endl;
		 #endif*/
		success = ABYPartyListen();
	} else { //CLIENT
		success = ABYPartyConnect();

	}
	m_tComm->snd_std = new SndThread(m_vSockets[0]);
	m_tComm->rcv_std = new RcvThread(m_vSockets[0]);

	m_tComm->snd_inv = new SndThread(m_vSockets[1]);
	m_tComm->rcv_inv = new RcvThread(m_vSockets[1]);

	m_tComm->snd_std->Start();
	m_tComm->snd_inv->Start();

	m_tComm->rcv_std->Start();
	m_tComm->rcv_inv->Start();
	return success;
}

//Interface to the connection method
BOOL ABYParty::ABYPartyConnect() {
	//Will open m_vSockets.size new sockets to
	for(uint32_t i = 0; i < m_vSockets.size(); i++) {
		m_vSockets[i] = new CSocket();
	}
	return Connect(m_cAddress, m_nPort, m_vSockets, (uint32_t) m_eRole);
}

//Interface to the listening method
BOOL ABYParty::ABYPartyListen() {
	vector<vector<CSocket*> > tempsocks(2);

	for(uint32_t i = 0; i < 2; i++) {
		tempsocks[i].resize(m_vSockets.size());

		for(uint32_t j = 0; j < m_vSockets.size(); j++) {
			tempsocks[i][j] = new CSocket();
			tempsocks[i][j] = new CSocket();
		}
	}

	bool success = Listen(m_cAddress, m_nPort, tempsocks, m_vSockets.size(), (uint32_t) m_eRole);
	for(uint32_t i = 0; i < m_vSockets.size(); i++) {
		m_vSockets[i] = tempsocks[1][i];
	}
	tempsocks[0][0]->Close();
	return success;
}

void ABYParty::InstantiateGate(uint32_t gateid) {
	m_pGates[gateid].gs.val = (UGATE_T*) malloc(sizeof(UGATE_T) * (ceil_divide(m_pGates[gateid].nvals, GATE_T_BITS)));
}

void ABYParty::UsedGate(uint32_t gateid) {
	//Decrease the number of further uses of the gate
	m_pGates[gateid].nused--;
	//If the gate is needed in another subsequent gate, delete it
	if (!m_pGates[gateid].nused) {
		free(m_pGates[gateid].gs.val);

	}
}

void ABYParty::Reset() {
	m_pSetup->Reset();
	m_nDepth = 0;
	m_nMyNumInBits = 0;
	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		m_vSharings[i]->Reset();
	}

	m_pCircuit->Reset();
}

double ABYParty::GetTiming(ABYPHASE phase) {
	return GetTimeForPhase(phase);
}

uint64_t ABYParty::GetSentData(ABYPHASE phase) {
	return GetSentDataForPhase(phase);
}

uint64_t ABYParty::GetReceivedData(ABYPHASE phase) {
	return GetReceivedDataForPhase(phase);
}

//===========================================================================
// Thread Management
BOOL ABYParty::WakeupWorkerThreads(EPartyJobType e) {
	m_bWorkerThreadSuccess = TRUE;

	m_nWorkingThreads = 2;
	uint32_t n = m_nWorkingThreads;

	for (uint32_t i = 0; i < n; i++)
		m_vThreads[i]->PutJob(e);

	return TRUE;
}

BOOL ABYParty::WaitWorkerThreads() {
	if (!m_nWorkingThreads)
		return TRUE;

	for (;;) {
		m_lock.Lock();
		uint32_t n = m_nWorkingThreads;
		m_lock.Unlock();
		if (!n)
			return m_bWorkerThreadSuccess;
		m_evt.Wait();
	}
	return m_bWorkerThreadSuccess;
}

BOOL ABYParty::ThreadNotifyTaskDone(BOOL bSuccess) {
	m_lock.Lock();
	uint32_t n = --m_nWorkingThreads;
	if (!bSuccess)
		m_bWorkerThreadSuccess = FALSE;
	m_lock.Unlock();

	if (!n)
		m_evt.Set();
	return TRUE;
}

void ABYParty::CPartyWorkerThread::ThreadMain() {
	BOOL bSuccess = FALSE;
	for (;;) {
		m_evt.Wait();

		switch (m_eJob) {
		case e_Party_Stop:
			return;
		case e_Party_Comm:
			if (threadid == 0){
				bSuccess = m_pCallback->ThreadSendValues();
			}
			else{
				bSuccess = m_pCallback->ThreadReceiveValues();
			}
			break;
		}

		m_pCallback->ThreadNotifyTaskDone(bSuccess);
	}
}

