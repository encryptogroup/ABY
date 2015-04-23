/**
 \file 		socket.h
 \author 	Seung Geol Choi
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
 \brief		Socket Implementation
 */

#ifndef __SOCKET_H__BY_SGCHOI 
#define __SOCKET_H__BY_SGCHOI 

#include "typedefs.h"

class CSocket {
public:
	CSocket() {
		m_hSock = INVALID_SOCKET;
	}
	~CSocket() {
		//Close();
	}

public:
	BOOL Socket() {
		BOOL success = false;
		BOOL bOptVal = true;
		int bOptLen = sizeof(BOOL);

#ifdef WIN32
		static BOOL s_bInit = FALSE;

		if (!s_bInit) {
			WORD wVersionRequested;
			WSADATA wsaData;

			wVersionRequested = MAKEWORD(2, 0);
			WSAStartup(wVersionRequested, &wsaData);
			s_bInit = TRUE;
		}
#endif

		Close();

		success = (m_hSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET;

		return success;

	}

	void Close() {
		if (m_hSock == INVALID_SOCKET)
			return;

#ifdef WIN32
		shutdown(m_hSock, SD_SEND);
		closesocket(m_hSock);
#else
		shutdown(m_hSock, SHUT_WR);
		close(m_hSock);
#endif

		m_hSock = INVALID_SOCKET;
	}

	void AttachFrom(CSocket& s) {
		m_hSock = s.m_hSock;
	}

	void Detach() {
		m_hSock = INVALID_SOCKET;
	}

public:
	string GetIP() {
		sockaddr_in addr;
		UINT addr_len = sizeof(addr);

		if (getsockname(m_hSock, (sockaddr *) &addr, (socklen_t *) &addr_len) < 0)
			return "";
		return inet_ntoa(addr.sin_addr);
	}

	USHORT GetPort() {
		sockaddr_in addr;
		UINT addr_len = sizeof(addr);

		if (getsockname(m_hSock, (sockaddr *) &addr, (socklen_t *) &addr_len) < 0)
			return 0;
		return ntohs(addr.sin_port);
	}

	BOOL Bind(USHORT nPort = 0, string ip = "") {
		// Bind the socket to its port
		sockaddr_in sockAddr;
		memset(&sockAddr, 0, sizeof(sockAddr));
		sockAddr.sin_family = AF_INET;

		if (ip != "") {
			int on = 1;
			setsockopt(m_hSock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof(on));

			sockAddr.sin_addr.s_addr = inet_addr(ip.c_str());

			if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
				hostent* phost;
				phost = gethostbyname(ip.c_str());
				if (phost != NULL)
					sockAddr.sin_addr.s_addr = ((in_addr*) phost->h_addr)->s_addr;
					else
					return FALSE;
				}
			}
			else
			{
				sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
			}

		sockAddr.sin_port = htons(nPort);

		return bind(m_hSock, (sockaddr *) &sockAddr, sizeof(sockaddr_in)) >= 0;
	}

	BOOL Listen(int nQLen = 5) {
		return listen(m_hSock, nQLen) >= 0;
	}

	BOOL Accept(CSocket& sock) {
		sock.m_hSock = accept(m_hSock, NULL, 0);
		if (sock.m_hSock == INVALID_SOCKET)
			return FALSE;

		return TRUE;
	}

	BOOL Connect(string ip, USHORT port, LONG lTOSMilisec = -1) {
		sockaddr_in sockAddr;
		memset(&sockAddr, 0, sizeof(sockAddr));
		sockAddr.sin_family = AF_INET;
		sockAddr.sin_addr.s_addr = inet_addr(ip.c_str());

		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
			hostent* lphost;
			lphost = gethostbyname(ip.c_str());
			if (lphost != NULL)
				sockAddr.sin_addr.s_addr = ((in_addr*) lphost->h_addr)->s_addr;
				else
				return FALSE;
			}

		sockAddr.sin_port = htons(port);

#ifdef WIN32

		DWORD dw = 100000;

		if( lTOSMilisec > 0 )
		{
			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, (char*) &lTOSMilisec, sizeof(lTOSMilisec));
		}

		int ret = connect(m_hSock, (sockaddr*)&sockAddr, sizeof(sockAddr));

		if( ret >= 0 && lTOSMilisec > 0 )
		setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, (char*) &dw, sizeof(dw));

#else

		timeval tv;
		socklen_t len;

		if (lTOSMilisec > 0) {
			tv.tv_sec = lTOSMilisec / 1000;
			tv.tv_usec = (lTOSMilisec % 1000) * 1000;

			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}

		int ret = connect(m_hSock, (sockaddr*) &sockAddr, sizeof(sockAddr));

		if (ret >= 0 && lTOSMilisec > 0) {
			tv.tv_sec = 100000;
			tv.tv_usec = 0;

			setsockopt(m_hSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}

#endif
		return ret >= 0;
	}

	uint64_t Receive(void* pBuf, uint64_t nLen, int nFlags = 0) {
		char* p = (char*) pBuf;
		uint64_t n = nLen;
		uint64_t ret = 0;
		while (n > 0) {
			ret = recv(m_hSock, p, n, 0);
#ifdef WIN32
			if( ret <= 0 )
			{
				return ret;
			}
#else
			if (ret < 0) {
				if ( errno == EAGAIN) {
					cerr << "socket recv eror: EAGAIN" << endl;
					SleepMiliSec(200);
					continue;
				} else {
					cerr << "socket recv error: " << errno << endl;
					perror("Socket error ");
					return ret;
				}
			} else if (ret == 0) {
				return ret;
			}
#endif

			p += ret;
			n -= ret;
		}
		return nLen;
	}

	int Send(const void* pBuf, uint64_t nLen, int nFlags = 0) {
		return send(m_hSock, (char*) pBuf, nLen, nFlags);
	}

private:
	SOCKET m_hSock;
};

#endif //SOCKET_H__BY_SGCHOI

