/**
 \file 		abyparty.cpp
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		ABYParty class implementation.
 */

#include "abyparty.h"

#include <sstream>
//#define ABYDEBUG

using namespace std;

#ifdef _DEBUG
#include <cassert>
using namespace std;
#endif

ABYParty::ABYParty(e_role pid, char* addr, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mg_algo) {
	StartWatch("Initialization", P_INIT);

	m_eRole = pid;
	//cout << "m_eRole = " << m_eRole << endl;

	m_cAddress = addr;
	m_sSecLvl = seclvl;

	m_eMTGenAlg = mg_algo;

	//
	m_cCrypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);
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
	if (!InitCircuit(bitlen)) {
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
	StartWatch("Starting NP OT", P_BASE_OT);
	m_pSetup->PrepareSetupPhase(m_vSockets);
	StopWatch("Time for NP OT: ", P_BASE_OT);
}

ABYParty::~ABYParty() {
	Cleanup();
}

BOOL ABYParty::Init() {
	m_nPort = 7766;

	//Threads that support execution by e.g. concurrent sending / receiving
	m_nHelperThreads = 2;

	m_cConstantInsecureSeed = (BYTE*) "00112233445566778899AABBCCDDEEFFF";

	m_vSockets.resize(m_nNumOTThreads * 2);

	//Initialize necessary routines for computing the setup phase
	m_pSetup = new ABYSetup(m_cCrypt, m_nNumOTThreads, m_eRole, m_eMTGenAlg);

	m_vThreads.resize(m_nHelperThreads);
	for (uint32_t i = 0; i < m_nHelperThreads; i++) {
		m_vThreads[i] = new CPartyWorkerThread(i, this); //First thread is started as receiver, second as sender
		m_vThreads[i]->Start();
	}

	m_nMyNumInBits = 0;

	return TRUE;
}

void ABYParty::Cleanup() {
	if (m_pCircuit)
		delete m_pCircuit;

	for (uint32_t i = 0; i < m_nHelperThreads; i++) {
		m_vThreads[i]->PutJob(e_Party_Stop);
		m_vThreads[i]->Wait();
		m_vThreads[i]->Kill();
		delete m_vThreads[i];
	}

	for (uint32_t i = 0; i < m_vSockets.size(); i++) {
		m_vSockets[i].Close();
	}
}

CBitVector ABYParty::ExecCircuit() {

#ifndef BATCH
	cout << "Finishing circuit generation" << endl;
#endif
	//Finish the circuit generation TODO check if this is required in later program versions
	m_pCircuit->FinishCircuitGeneration();

	CBitVector result;
	StartWatch("Starting execution", P_TOTAL);

	//Setup phase
	StartWatch("Starting setup phase: ", P_SETUP);
	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifndef BATCH
		cout << "Preparing setup phase for " << m_vSharings[i]->sharing_type() << " sharing" << endl;
#endif
		m_vSharings[i]->PrepareSetupPhase(m_pSetup);
	}

#ifndef BATCH
	cout << "Preforming OT extension" << endl;
#endif
	StartWatch("Starting OT Extension", P_OT_EXT);
	m_pSetup->PerformSetupPhase(m_vSockets);
	StopWatch("Time for OT Extension phase: ", P_OT_EXT);

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifndef BATCH
		cout << "Performing setup phase for " << m_vSharings[i]->sharing_type() << " sharing" << endl;
#endif
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

#ifndef BATCH
	cout << "Evaluating circuit" << endl;
#endif
	//Online phase
	StartWatch("Starting online phase: ", P_ONLINE);
	EvaluateCircuit();
	StopWatch("Time for online phase: ", P_ONLINE);

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
	m_pSetup->PerformSetupPhase(m_vSockets);
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

BOOL ABYParty::InitCircuit(uint32_t bitlen) {
	//TODO only up to 2.000.000 gates can be built, is probably changing in the future
	m_pCircuit = new ABYCircuit(2000000);

	//TODO change YaoSharing such that right class is passed back just given the role
	m_vSharings.resize(3);
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
	timeval tstart, tend;
	double interaction=0;
	vector<double> localops(3,0);
	vector<double> interactiveops(3,0);
	vector<double> fincirclayer(3,0);
#endif
	//First assign the input values to the input gates
	AssignInputValues();
	m_nDepth = 0;

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
	//Evaluate Circuit layerwise
	for (uint32_t depth = 0; depth < maxdepth; depth++, m_nDepth++) {
		for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifdef DEBUGABYPARTY
			cout << "Evaluating local operations of sharing " << i << " on depth " << depth << endl;
#endif
#ifdef BENCHONLINEPHASE
			gettimeofday(&tstart, NULL);
#endif
			m_vSharings[i]->EvaluateLocalOperations(depth);
#ifdef BENCHONLINEPHASE
			gettimeofday(&tend, NULL);
			localops[i] += getMillies(tstart, tend);
			gettimeofday(&tstart, NULL);
#endif
#ifdef DEBUGABYPARTY
			cout << "Evaluating interactive operations of sharing " << i << endl;
#endif
			m_vSharings[i]->EvaluateInteractiveOperations(depth);
#ifdef BENCHONLINEPHASE
			gettimeofday(&tend, NULL);
			interactiveops[i] += getMillies(tstart, tend);
#endif
		}
#ifdef DEBUGABYPARTY
		cout << "Finished with evaluating operations on depth = " << depth << ", continuing with interactions" << endl;
#endif
#ifdef BENCHONLINEPHASE
		gettimeofday(&tstart, NULL);
#endif
		PerformInteraction();
#ifdef BENCHONLINEPHASE
		gettimeofday(&tend, NULL);
		interaction += getMillies(tstart, tend);
#endif
#ifdef DEBUGABYPARTY
		cout << "Done performing interaction, having sharings wrap up this circuit layer" << endl;
#endif
		for (uint32_t i = 0; i < m_vSharings.size(); i++) {
#ifdef BENCHONLINEPHASE
			gettimeofday(&tstart, NULL);
#endif
			//cout << "Finishing circuit layer for sharing "<< i << endl;
			m_vSharings[i]->FinishCircuitLayer();
#ifdef BENCHONLINEPHASE
			gettimeofday(&tend, NULL);
			fincirclayer[i] += getMillies(tstart, tend);
#endif
		}

	}
#ifdef DEBUGABYPARTY
	cout << "Done with online phase "<< endl;
#endif
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
	vector<BYTE*> sendbuf;
	vector<uint32_t> sndbytes;

	timeval tstart, tend;

	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		sendbuf.clear();
		sndbytes.clear();

		m_vSharings[j]->GetDataToSend(sendbuf, sndbytes);

		for (uint32_t i = 0; i < sendbuf.size(); i++) {
			if (sndbytes[i] > 0) {
//				gettimeofday(&tstart, NULL);
				m_vSockets[m_eRole].Send(sendbuf[i], (int) sndbytes[i]);
#ifdef DEBUGCOMM
				cout << "(" << m_nDepth << ") Sending " << sndbytes[i] << " bytes on socket " << m_eRole << endl;
#endif
//				gettimeofday(&tend, NULL);
//				cout << "(" << m_nDepth << ") Time taken for sending " << sndbytes[i] << " bytes: " << getMillies(tstart, tend) << endl;
			}
		}
	}

	return true;
}

BOOL ABYParty::ThreadReceiveValues() {
	vector<BYTE*> rcvbuf;
	vector<uint32_t> rcvbytes;

	timeval tstart, tend;

	for (uint32_t j = 0; j < m_vSharings.size(); j++) {
		rcvbuf.clear();
		rcvbytes.clear();
		//cout << "Getting buffers to receive" << endl;
		m_vSharings[j]->GetBuffersToReceive(rcvbuf, rcvbytes);

		for (uint32_t i = 0; i < rcvbuf.size(); i++) {
			if (rcvbytes[i] > 0) {
#ifdef DEBUGCOMM
				cout << "(" << m_nDepth << ") Receiving " << rcvbytes[i] << " bytes on socket " << (m_eRole^1) << endl;
#endif
				m_vSockets[m_eRole ^ 1].Receive(rcvbuf[i], (int) rcvbytes[i]);

			}
		}
	}

	return true;
}

BOOL ABYParty::AssignInputValues() {
	vector<CBitVector> inputbits(m_vSharings.size());
	vector<uint32_t> inbits(m_vSharings.size());

	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		inbits[i] = m_vSharings[i]->AssignInput(inputbits[i]);
		m_nMyNumInBits += inbits[i];
	}

	m_vInputBits.Create(m_nMyNumInBits);
	for (uint32_t i = 0, startpos = 0; i < m_vSharings.size(); i++) {
		m_vInputBits.SetBits(inputbits[i].GetArr(), (int) startpos, (int) inbits[i]);
		startpos += inbits[i];
	}

	return true;
}

BOOL ABYParty::PrintInput() {
	cout << "My Input: ";
	m_vInputBits.Print(0, m_nMyNumInBits);
	return true;
}

void ABYParty::PrintOutput() {
	CBitVector out;
	uint32_t outbitlen = GetOutput(out);
	cout << "My Output: ";
	out.Print(0, outbitlen);
}

uint32_t ABYParty::GetOutput(CBitVector& out) {
	uint32_t totaloutbits = 0;

	vector<uint32_t> outbits(m_vSharings.size());
	vector<CBitVector> tmpout(m_vSharings.size());
	for (uint32_t i = 0; i < m_vSharings.size(); i++) {
		outbits[i] = m_vSharings[i]->GetOutput(tmpout[i]);
		totaloutbits += outbits[i];
	}
	out.Create(totaloutbits);
	for (uint32_t i = 0, startpos = 0; i < m_vSharings.size(); i++) {
		out.SetBits(tmpout[i].GetArr(), (int) startpos, (int) outbits[i]);
		startpos += outbits[i];
	}
	return totaloutbits;
}

void ABYParty::PrintPerformanceStatistics() {
	cout << "Complexities: " << endl;
	m_vSharings[S_BOOL]->PrintPerformanceStatistics();
	m_vSharings[S_YAO]->PrintPerformanceStatistics();
	m_vSharings[S_ARITH]->PrintPerformanceStatistics();
	PrintTimings();
}

//=========================================================
// Connection Routines
BOOL ABYParty::EstablishConnection() {
	if (m_eRole == SERVER) {
		/*#ifndef BATCH
		 cout << "Server starting to listen" << endl;
		 #endif*/
		return ABYPartyListen();
	} else { //CLIENT
		return ABYPartyConnect();
	}
}

//Interface to the connection method
BOOL ABYParty::ABYPartyConnect() {
	//Will open m_vSockets.size new sockets to
	return Connect(m_cAddress, m_nPort, m_vSockets, (uint32_t) m_eRole);
}

//Interface to the listening method
BOOL ABYParty::ABYPartyListen() {
	vector<vector<CSocket> > tempsocks(2);
	tempsocks[0].resize(m_nNumOTThreads * 2);
	tempsocks[1].resize(m_nNumOTThreads * 2);

	bool success = Listen(m_cAddress, m_nPort, tempsocks, 2 * m_nNumOTThreads, (uint32_t) m_eRole);
	m_vSockets = tempsocks[1];
	tempsocks[0][0].Close();
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

uint32_t ABYParty::GetMyInput(CBitVector &myin) {
	myin.Create(m_nMyNumInBits);
	myin.Copy(m_vInputBits);
	return m_nMyNumInBits;
}

//TODO used mainly for verification, returns number of bits
uint32_t ABYParty::GetOtherInput(CBitVector &otherin) {

	uint32_t othernuminbits = 0; // = m_pCircuit->GetNumInputBitsForParty((ROLE) (!m_eRole));
	m_vSockets[0].Send(&m_nMyNumInBits, sizeof(uint32_t));
	m_vSockets[0].Send(m_vInputBits.GetArr(), (int) ceil_divide(m_nMyNumInBits, 8));

	m_vSockets[0].Receive(&othernuminbits, sizeof(uint32_t));
	otherin.Create(othernuminbits);
	m_vSockets[0].Receive(otherin.GetArr(), (int) ceil_divide(othernuminbits, 8));
	return othernuminbits;
}


void ABYParty::Reset() {
	m_pSetup->Reset();
	m_nDepth = 0;
	m_nMyNumInBits = 0;
	for (uint32_t i = 0; i < m_vSharings.size(); i++)
		m_vSharings[i]->Reset();

	m_pCircuit->Reset();

	m_vInputBits.delCBitVector();
}

double ABYParty::GetTiming(ABYPHASE phase) {
	return GetTimeForPhase(phase);
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
	BOOL bSuccess;
	for (;;) {
		m_evt.Wait();

		switch (m_eJob) {
		case e_Party_Stop:
			return;
		case e_Party_Comm:
			if (threadid == 0)
				bSuccess = m_pCallback->ThreadSendValues();
			else
				bSuccess = m_pCallback->ThreadReceiveValues();
			break;
		}

		m_pCallback->ThreadNotifyTaskDone(bSuccess);
	}
}

