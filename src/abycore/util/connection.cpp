/**
 \file 		connection.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Connection Implementation
 */

#include "connection.h"

BOOL Connect(string address, short port, vector<CSocket> &sockets, int id) {
	int nNumConnections;

	BOOL bFail = FALSE;
	LONG lTO = CONNECT_TIMEO_MILISEC;
	//cout << "Connecting" << endl;
	ostringstream os;
#ifndef BATCH
	cout << "Connecting party "<< id <<": " << address << ", " << port << endl;
#endif

	for (int j = 0; j < sockets.size(); j++) {
		for (int i = 0; i < RETRY_CONNECT; i++) {
			if (!sockets[j].Socket())
				goto connect_failure;
			if (sockets[j].Connect(address, port, lTO)) {
				// send pid when connected
				sockets[j].Send(&id, sizeof(int));
				sockets[j].Send(&j, sizeof(int));
#ifndef BATCH
				os.str("");
				os << " (" << id << ") (" << j << ") connected" << endl;
				cout << os.str() << flush;
#endif
				if (j == sockets.size() - 1) {
					return TRUE;
				} else {
					break;
				}
			}
			SleepMiliSec(10);
			sockets[j].Close();
		}
	}

	connect_failure:

	os.str("");
	os << " (" << id << ") connection failed due to timeout!" << endl;
	cout << os.str() << flush;
	return FALSE;

}

BOOL Listen(string address, short port, vector<vector<CSocket> > &sockets, int numConnections, int myID) {
	// everybody except the last thread listenes
	ostringstream os;

#ifndef BATCH
	cout << "Listening: " << address << ":" << port << endl;
#endif
	if (!sockets[myID][0].Socket()) {
		cerr << "Error: a socket could not be created " << endl;
		goto listen_failure;
	}
	if (!sockets[myID][0].Bind(port, address)) {
		cerr << "Error: a socket could not be bound" << endl;
		goto listen_failure;
	}
	if (!sockets[myID][0].Listen()) {
		cerr << "Error: could not listen on the socket " << endl;
		goto listen_failure;
	}

	for (int i = 0; i < numConnections; i++) //twice the actual number, due to double sockets for OT
			{
		CSocket sock;
		if (!sockets[myID][0].Accept(sock)) {
			cerr << "Error: could not accept connection" << endl;
			goto listen_failure;
		}
		// receive initial pid when connected
		UINT nID;
		UINT conID; //a mix of threadID and role - depends on the application
		sock.Receive(&nID, sizeof(int));
		sock.Receive(&conID, sizeof(int));

		if (nID >= sockets.size()) //Not more than two parties currently allowed
				{
			sock.Close();
			i--;
			continue;
		}
		if (conID >= sockets[myID].size()) {
			sock.Close();
			i--;
			continue;
		}

#ifndef BATCH
		os.str("");
		os << " (" << conID <<") (" << conID << ") connection accepted" << endl;

		cout << os.str() << flush;
#endif
		// locate the socket appropriately
		sockets[nID][conID].AttachFrom(sock);
		sock.Detach();
	}

#ifndef BATCH
	cout << "Listening finished" << endl;
#endif
	return TRUE;

	listen_failure: cout << "Listen failed" << endl;
	return FALSE;
}
