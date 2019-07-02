/**
 \file 		abysetup.cpp
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
 \brief		ABYSetup class implementation.
 */

#include "abysetup.h"
#include <cstdlib>
#include <iostream>

ABYSetup::ABYSetup(crypto* crypt, uint32_t numThreads, e_role role, e_mt_gen_alg mtalgo) {
	m_nNumOTThreads = numThreads;
	m_cCrypt = crypt;
	m_eRole = role;
	m_eMTGenAlg = mtalgo;

	if (!Init()) {
		std::cerr << "Error in ABYSetup init" << std::endl;
		std::exit(EXIT_FAILURE);
	}
}

ABYSetup::~ABYSetup() {
	Cleanup();
}

BOOL ABYSetup::Init() {
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
//	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	m_vIKNPOTTasks.resize(2);
	m_vKKOTTasks.resize(2);

	uint32_t threadsize = 2 * m_nNumOTThreads;
	m_vThreads.resize(threadsize);
	for (uint32_t i = 0; i < threadsize; i++) { //double the number of threads for role-flippling
		m_vThreads[i] = new CWorkerThread(i, this);
		m_vThreads[i]->Start();
	}

	//the bit length of the DJN party is irrelevant here, since it is set for each MT Gen task independently
	if (m_eMTGenAlg == MT_PAILLIER) {
#ifndef BATCH
		std::cout << "Creating new DJNPart with key bitlen = " << m_cCrypt->get_seclvl().ifcbits << std::endl;
#endif
		m_cPaillierMTGen = new DJNParty(m_cCrypt->get_seclvl().ifcbits, sizeof(uint16_t) * 8);
	}
// we cannot create a DGKParty here, since we do not know the share bit length yet.
// for DGK this will be done in PerformSetupPhase()

// 	else if (m_eMTGenAlg == MT_DGK) {
// #ifndef BATCH
// 		std::cout << "Creating new DGKPart with key bitlen = " << m_cCrypt->get_seclvl().ifcbits << std::endl;
// #endif
// #ifdef BENCH_PRECOMP
// 		m_cDGKMTGen = (DGKParty**) malloc(sizeof(DGKParty*));
// 		m_cDGKMTGen[0] = new DGKParty(m_sSecLvl.ifcbits, sizeof(uint64_t) * 8, 0);
// #endif
// 		//m_cDGKMTGen = new DGKParty(m_cCrypt->get_seclvl().ifcbits, sizeof(uint16_t) * 8);
// 	}

	return true;
}

void ABYSetup::Cleanup() {
	for(size_t i = 0; i < m_vThreads.size(); i++) {
		m_vThreads[i]->PutJob(e_Stop);
		m_vThreads[i]->Wait();
		delete m_vThreads[i];
	}
	if(m_tSetupChan) {
		m_tSetupChan->synchronize_end();
		delete m_tSetupChan;
	}
	if(iknp_ot_sender) {
		delete iknp_ot_sender;
	}
	if(iknp_ot_receiver) {
		delete iknp_ot_receiver;
	}
	if(m_cPaillierMTGen){
		delete m_cPaillierMTGen;
	}


#ifdef USE_KK_OT
	//FIXME: deleting kk_ot_receiver or sender causes a SegFault in AES with Yao
	if(kk_ot_receiver) {
		delete kk_ot_receiver;
	}
	if(kk_ot_sender) {
		delete kk_ot_sender;
	}
#endif

}

BOOL ABYSetup::PrepareSetupPhase(comm_ctx* comm) {
	m_tComm = comm;

	m_tSetupChan = new channel(ABY_SETUP_CHANNEL, m_tComm->rcv_std.get(), m_tComm->snd_std.get());

#if BENCH_HARDWARE
	uint8_t dummyrcv = 0;
	timespec start, end;
	uint32_t benchrounds = 16;
	uint64_t tmparraysize = 1024*1024*4; // 4 MiB block
	BYTE * benchtmp = new BYTE[tmparraysize];
#endif

	if (m_eRole == SERVER) {

#if BENCH_HARDWARE
		clock_gettime(CLOCK_MONOTONIC, &start);
		for (uint32_t round = 0; round < benchrounds; round++) {
			m_tSetupChan->send(&dummyrcv, (uint64_t) 1);
			m_tSetupChan->blocking_receive(&dummyrcv, (uint64_t) 1);
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		std::cout << "RTT: " << getMillies(start, end) / benchrounds << " ms" << std::endl;

		clock_gettime(CLOCK_MONOTONIC, &start);
		for (uint32_t round = 0; round < benchrounds; round++) {
			m_tSetupChan->send(benchtmp, (uint64_t) tmparraysize);
			m_tSetupChan->blocking_receive(benchtmp, (uint64_t) tmparraysize);
		}

		clock_gettime(CLOCK_MONOTONIC, &end);
		std::cout << "Throughput: " << 2 * (tmparraysize >> 20) * benchrounds / (getMillies(start, end) / 1000) << " MiB/s" << std::endl;
		delete[] benchtmp;
#endif

		iknp_ot_sender = new IKNPOTExtSnd(m_cCrypt, m_tComm->rcv_std.get(), m_tComm->snd_std.get(),
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
		iknp_ot_receiver = new IKNPOTExtRec(m_cCrypt, m_tComm->rcv_inv.get(), m_tComm->snd_inv.get(),
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);

#ifdef USE_KK_OT
		kk_ot_sender = new KKOTExtSnd(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std,
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
		kk_ot_receiver = new KKOTExtRec(m_cCrypt, m_tComm->rcv_inv, m_tComm->snd_inv,
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
#endif
	} else { // CLIENT

#if BENCH_HARDWARE
		clock_gettime(CLOCK_MONOTONIC, &start);
		for (uint32_t round = 0; round < benchrounds; round++) {
			m_tSetupChan->blocking_receive(&dummyrcv, (uint64_t) 1);
			m_tSetupChan->send(&dummyrcv, (uint64_t) 1);
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		std::cout << "RTT: " << getMillies(start, end) / benchrounds << " ms" << std::endl;

		clock_gettime(CLOCK_MONOTONIC, &start);
		for (uint32_t round = 0; round < benchrounds; round++) {
			m_tSetupChan->blocking_receive(benchtmp, (uint64_t) tmparraysize);
			m_tSetupChan->send(benchtmp, (uint64_t) tmparraysize);
		}

		clock_gettime(CLOCK_MONOTONIC, &end);
		std::cout << "Throughput: " << 2 * (tmparraysize>>20)*benchrounds / (getMillies(start, end) / 1000) << " MiB/s" << std::endl;
				delete benchtmp;
#endif
		iknp_ot_receiver = new IKNPOTExtRec(m_cCrypt, m_tComm->rcv_std.get(), m_tComm->snd_std.get(),
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
		iknp_ot_sender = new IKNPOTExtSnd(m_cCrypt, m_tComm->rcv_inv.get(), m_tComm->snd_inv.get(),
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);

#ifdef USE_KK_OT
		kk_ot_receiver = new KKOTExtRec(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std,
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
		kk_ot_sender = new KKOTExtSnd(m_cCrypt, m_tComm->rcv_inv, m_tComm->snd_inv,
				/* num_ot_blocks */ 1024, /* verify_ot */ false, /* use_fixed_aes_key_hashing */ true);
#endif
	}
	//Start Naor-Pinkas base OTs
	WakeupWorkerThreads(e_NP);
	BOOL success = WaitWorkerThreads();

	if (m_eMTGenAlg == MT_PAILLIER) {
		//Start Paillier key generation for the MT generation
		m_cPaillierMTGen->keyExchange(m_tSetupChan);
	}

	return success;
}

BOOL ABYSetup::PerformSetupPhase() {
	/* Compute OT extension */
	WakeupWorkerThreads(e_IKNPOTExt);
	BOOL success = WaitWorkerThreads();

#ifdef USE_KK_OT
	WakeupWorkerThreads(e_KKOTExt);
	success &= WaitWorkerThreads();
#endif

	if (m_eMTGenAlg == MT_PAILLIER) {
		//Start Paillier MT generation
		WakeupWorkerThreads(e_MTPaillier);
		success &= WaitWorkerThreads();
	}
	else if (m_eMTGenAlg == MT_DGK) {
	// we cannot create the DGK parties earlier
	// since share length in m_vPKMTGenTasks[i]->sharebitlen is required and only known from here on
#ifndef BENCH_PRECOMP
		m_cDGKMTGen = (DGKParty**) malloc(sizeof(DGKParty*) * m_vPKMTGenTasks.size());
#endif
		for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
#ifndef BENCH_PRECOMP
			m_cDGKMTGen[i] = new DGKParty(m_cCrypt->get_seclvl().ifcbits, m_vPKMTGenTasks[i]->sharebitlen, 1);
#endif
			m_cDGKMTGen[i]->keyExchange(m_tSetupChan);
		}
		//Start DGK MT generation
		WakeupWorkerThreads(e_MTDGK);
		success &= WaitWorkerThreads();

		for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
			delete m_cDGKMTGen[i];
		}
		free(m_cDGKMTGen);
	}
	return success;
}

BOOL ABYSetup::FinishSetupPhase() {
	//Do nothing atm
	return true;
}

BOOL ABYSetup::ThreadRunNPSnd() {
	BOOL success = true;
	iknp_ot_sender->ComputeBaseOTs(P_FIELD);
#ifdef USE_KK_OT
	kk_ot_sender->ComputeBaseOTs(P_FIELD);
#endif
	return success;
}

BOOL ABYSetup::ThreadRunNPRcv() {
	BOOL success = true;
	iknp_ot_receiver->ComputeBaseOTs(P_FIELD);
#ifdef USE_KK_OT
	kk_ot_receiver->ComputeBaseOTs(P_FIELD);
#endif
	return success;
}

//Receiver and Sender switch roles in the beginning of the OT extension protocol to obliviously transfer a matrix T
BOOL ABYSetup::ThreadRunIKNPSnd(uint32_t threadid) {
	bool success = true;

	uint32_t inverse = threadid ^ m_eRole;
	uint32_t nsndvals = 2;

	CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);
	for (uint32_t i = 0; i < m_vIKNPOTTasks[inverse].size(); i++) {
		IKNP_OTTask* task = m_vIKNPOTTasks[inverse][i]; //m_vOTTasks[inverse][0];
		uint32_t numOTs = task->numOTs;
		X[0] = (task->pval.sndval.X0);
		X[1] = (task->pval.sndval.X1);

#ifndef BATCH
		std::cout << "Starting OT sender routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << std::endl;
#endif
		success &= iknp_ot_sender->send(numOTs, task->bitlen, nsndvals, X, task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		std::cout << "OT sender results for bitlen = " << task->bitlen << ": " << std::endl;
		std::cout << "X0: ";
		task->pval.sndval.X0->PrintHex();
		std::cout << "X1: ";
		task->pval.sndval.X1->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vIKNPOTTasks[inverse].resize(0);
	free(X);
	return success;
}

BOOL ABYSetup::ThreadRunIKNPRcv(uint32_t threadid) {
	bool success = true;

	uint32_t inverse = threadid ^ m_eRole;
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	uint32_t nsndvals = 2;

	for (uint32_t i = 0; i < m_vIKNPOTTasks[inverse].size(); i++) {

		IKNP_OTTask* task = m_vIKNPOTTasks[inverse][i];
		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		std::cout << "Starting OT receiver routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << std::endl;
#endif
		success = iknp_ot_receiver->receive(numOTs, task->bitlen, nsndvals, (task->pval.rcvval.C), (task->pval.rcvval.R), task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		std::cout << "OT receiver results for bitlen = " << task->bitlen << ": " << std::endl;
		std::cout << "C: ";
		task->pval.rcvval.C->PrintBinary();
		std::cout << "R: ";
		task->pval.rcvval.R->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vIKNPOTTasks[inverse].resize(0);
	return success;
}


//KK13 OT extension sender and receiver routine outsourced in separate threads
BOOL ABYSetup::ThreadRunKKSnd(uint32_t threadid) {
	bool success = true;

	uint32_t inverse = threadid ^ m_eRole;

	for (uint32_t i = 0; i < m_vKKOTTasks[inverse].size(); i++) {
		KK_OTTask* task = m_vKKOTTasks[inverse][i];

		uint32_t numOTs = task->numOTs;
		CBitVector** X = task->pval.sndval.X;

		/*std::cout << "Address of X = " << (uint64_t) X << std::endl;
		for(uint32_t j = 0; j < task->nsndvals; j++) {
			std::cout << (uint64_t) X[j] << std::endl;
		}*/


#ifndef BATCH
		std::cout << "Starting 1oo" << task->nsndvals << " KK OT sender routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << std::endl;
#endif
		success &= kk_ot_sender->send(numOTs, task->bitlen, task->nsndvals, X, task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		std::cout << "OT sender results for bitlen = " << task->bitlen << ": " << std::endl;
		for(uint32_t j = 0; j < task->nsndvals; j++) {
			std::cout << "X" << j << ": ";
			X[j]->PrintHex();
		}
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vKKOTTasks[inverse].resize(0);
	return success;
}

BOOL ABYSetup::ThreadRunKKRcv(uint32_t threadid) {
	bool success = true;

	uint32_t inverse = threadid ^ m_eRole;
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
//	uint32_t nsndvals = 2;

	for (uint32_t i = 0; i < m_vKKOTTasks[inverse].size(); i++) {

		KK_OTTask* task = m_vKKOTTasks[inverse][i];
		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		std::cout << "Starting 1oo" << task->nsndvals << " KK OT receiver routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << std::endl;
#endif
		success = kk_ot_receiver->receive(numOTs, task->bitlen, task->nsndvals, (task->pval.rcvval.C), (task->pval.rcvval.R), task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		std::cout << "OT receiver results for bitlen = " << task->bitlen << ": " << std::endl;
		std::cout << "C: ";
		task->pval.rcvval.C->PrintBinary();
		std::cout << "R: ";
		task->pval.rcvval.R->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vKKOTTasks[inverse].resize(0);
	return success;
}

BOOL ABYSetup::ThreadRunPaillierMTGen(uint32_t threadid) {
	uint32_t nthreads = 2 * m_nNumOTThreads;

	channel* djnchan = new channel(DJN_CHANNEL + threadid, m_tComm->rcv_std.get(), m_tComm->snd_std.get());

	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		// equally distribute MTs to threads. Number of MTs per thread must be multiple of 2.
		uint32_t nummtsperthread = ptask->numMTs / (nthreads * 2);
		uint32_t threadmod = ptask->numMTs % (nthreads * 2);
		uint32_t mynummts = (nummtsperthread + ((threadid * 2) < threadmod)) * 2;

		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);
		if (mynummts > 0) {
			uint32_t mystartpos = 0;

			// add up previous threads numMTs to find start index for this thread
			for (uint32_t t = 0; t < threadid; ++t) {
				mystartpos += (nummtsperthread + ((t * 2) < threadmod)) * 2;
			}
			mystartpos *= sharebytelen;

			//add an offset depending on the role of the party
			uint32_t roleoffset = mystartpos + sharebytelen * (mynummts / 2);

			m_cPaillierMTGen->setShareBitLength(ptask->sharebitlen);

			if (m_eRole == SERVER) {
				m_cPaillierMTGen->computeArithmeticMTs(
					ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos,
					ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset,
					mynummts, djnchan);
			} else {
				m_cPaillierMTGen->computeArithmeticMTs(
					ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset,
					ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos,
					mynummts, djnchan);
			}
		}
	}
	djnchan->synchronize_end();
	delete djnchan;

	return true;
}

BOOL ABYSetup::ThreadRunDGKMTGen(uint32_t threadid) {
	uint32_t nthreads = 2 * m_nNumOTThreads;

	channel* dgkchan = new channel(DGK_CHANNEL + threadid, m_tComm->rcv_std.get(), m_tComm->snd_std.get());

	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		// equally distribute MTs to threads. Number of MTs per thread must be multiple of 2.
		uint32_t nummtsperthread = ptask->numMTs / (nthreads * 2);
		uint32_t threadmod = ptask->numMTs % (nthreads * 2);
		uint32_t mynummts = (nummtsperthread + ((threadid * 2) < threadmod)) * 2;

		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);

		if (mynummts > 0) {
			uint32_t mystartpos = 0;

			// add up previous threads numMTs to find start index for this thread
			for (uint32_t t = 0; t < threadid; ++t) {
				mystartpos += (nummtsperthread + ((t * 2) < threadmod)) * 2;
			}
			mystartpos *= sharebytelen;

			//add an offset depending on the role of the party
			uint32_t roleoffset = mystartpos + sharebytelen * (mynummts / 2);

			if (m_eRole == SERVER) {
				m_cDGKMTGen[i]->computeArithmeticMTs(
					ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos,
					ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset,
					mynummts, dgkchan);
			} else {
				m_cDGKMTGen[i]->computeArithmeticMTs(
					ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset,
					ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos,
					mynummts, dgkchan);
			}
		}
	}
	dgkchan->synchronize_end();
	delete dgkchan;

	return true;
}

//starts a new sending thread but may stop if there is a thread already running
void ABYSetup::AddSendTask(BYTE* sndbuf, uint64_t sndbytes) {
	WaitWorkerThreads();
	m_tsndtask.sndbytes = sndbytes;
	m_tsndtask.sndbuf = sndbuf;
	WakeupWorkerThreads(e_Send);
}

BOOL ABYSetup::WaitForTransmissionEnd() {
	return WaitWorkerThreads();
}

//starts a new receivingthread but may stop if there is a thread already running
void ABYSetup::AddReceiveTask(BYTE* rcvbuf, uint64_t rcvbytes) {
	WaitWorkerThreads();
	m_trcvtask.rcvbytes = rcvbytes;
	m_trcvtask.rcvbuf = rcvbuf;
	WakeupWorkerThreads(e_Receive);
}


BOOL ABYSetup::ThreadSendData(uint32_t threadid) {
	m_tSetupChan->blocking_send(m_vThreads[threadid]->GetEvent(), m_tsndtask.sndbuf, m_tsndtask.sndbytes);
	return true;
}


BOOL ABYSetup::ThreadReceiveData() {
	 m_tSetupChan->blocking_receive(m_trcvtask.rcvbuf, m_trcvtask.rcvbytes);
	return true;
}

//===========================================================================
// Thread Management
BOOL ABYSetup::WakeupWorkerThreads(EJobType e) {
	m_bWorkerThreadSuccess = TRUE;

	m_nWorkingThreads = 2;

	if (e == e_MTPaillier || e == e_MTDGK) {
		m_nWorkingThreads = 2 * m_nNumOTThreads;
	} else if (e == e_Send || e == e_Receive) {
		m_nWorkingThreads = 1;
	}

	uint32_t n = m_nWorkingThreads;

	for (uint32_t i = 0; i < n; i++){
		m_vThreads[i]->PutJob(e);
	}

	return TRUE;
}

BOOL ABYSetup::WaitWorkerThreads() {
	{
		std::lock_guard<CLock> lock(m_lock);
		if (!m_nWorkingThreads)
			return TRUE;
	}

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

BOOL ABYSetup::ThreadNotifyTaskDone(BOOL bSuccess) {
	m_lock.Lock();
	uint32_t n = --m_nWorkingThreads;
	if (!bSuccess){
		m_bWorkerThreadSuccess = FALSE;
	}
	m_lock.Unlock();

	if (!n)
		m_evt.Set();
	return TRUE;
}

void ABYSetup::CWorkerThread::ThreadMain() {
	BOOL bSuccess = FALSE;
	for (;;) {
		m_evt.Wait();

		EJobType job;
		{
			std::lock_guard<std::mutex> lock(m_eJob_mutex_);
			job = m_eJob;
		}

		switch (job) {
		case e_Stop:
			return;
		case e_IKNPOTExt:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunIKNPSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunIKNPRcv(threadid);
			break;
		case e_KKOTExt:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunKKSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunKKRcv(threadid);
			break;
		case e_NP:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunNPSnd();
			else
				bSuccess = m_pCallback->ThreadRunNPRcv();
			break;
		case e_MTPaillier:
			bSuccess = m_pCallback->ThreadRunPaillierMTGen(threadid);
			break;
		case e_MTDGK:
			bSuccess = m_pCallback->ThreadRunDGKMTGen(threadid);
			break;
		case e_Send:
			bSuccess = m_pCallback->ThreadSendData(threadid);
			break;
		case e_Receive:
			bSuccess = m_pCallback->ThreadReceiveData();
			break;
		case e_Transmit:
		case e_Undefined:
		default:
			std::cerr << "Error: Undefined / unimplemented OT Job!" << std::endl;
		}
		m_pCallback->ThreadNotifyTaskDone(bSuccess);
	}
}

void ABYSetup::Reset() {
	/* Clear any remaining IKNP OT tasks */
	for (uint32_t i = 0; i < m_vIKNPOTTasks.size(); i++) {
		m_vIKNPOTTasks[i].clear();
	}
	/* Clear any remaining KK OT tasks */
	for (uint32_t i = 0; i < m_vKKOTTasks.size(); i++) {
		m_vKKOTTasks[i].clear();
	}

	/* Clear any remaining MTGen tasks */
	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
		free(m_vPKMTGenTasks[i]);
	}
	m_vPKMTGenTasks.clear();
}
