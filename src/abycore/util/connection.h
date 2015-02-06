/**
 \file 		connection.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		connection Implementation
 */

#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "cbitvector.h"
#include <sstream>

BOOL Connect(string address, short port, vector<CSocket> &sockets, int id);
BOOL Listen(string address, short port, vector<vector<CSocket> > &sockets, int numConnections, int myID);

#endif
