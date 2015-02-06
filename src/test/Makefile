#Makefile for ABY tests

#DO NOT MODIFY THIS FILE, unless you know what you're doing

#You should not need to call this makefile separately. It will me called from the Makefile in the root directory

#relative project folders
BIN = ../../bin
SRC = ..
CORE=${SRC}/abycore

SOURCES := $(shell find . -type f -name '*.cpp')
OBJECTS := $(patsubst %.cpp, %.o, ${SOURCES})

# object files for the test cases
OBJECTS_MILLIONAIRE_CIRC=${SRC}/examples/millionaire_prob/common/millionaire_prob.o
OBJECTS_AES_CIRC=${SRC}/examples/aes/common/aescircuit.o
#OBJECTS_LOWMC_CIRC=${SRC}/examples/lowmc/common/lowmccircuit.o
OBJECTS_LOWMC_CIRC=

# directory for the Miracl library
MIRACL_LIB_DIR=${CORE}/util/miracl_lib
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

# all source files and corresponding object files in abycore
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/util/Miracl/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)

# compiler settings
CC=g++
COMPILER_OPTIONS=-O2
DEBUG_OPTIONS=-g3 -Wall
BATCH=
ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
GNU_LIB_PATH:=x86_64
else
GNU_LIB_PATH:=i386
endif
INCLUDE=-I..  -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include
CFLAGS=
LIBRARIES=-lgmp -lgmpxx -lpthread ${CORE}/util/miracl_lib/miracl.a -L /usr/lib  -lssl -lcrypto -lglib-2.0

#name fixed to test-aby
EXAMPLE = test-aby


all: ${BIN}/${EXAMPLE}.exe

${BIN}/${EXAMPLE}.exe: ${OBJECTS_CORE} ${OBJECTS} ${OBJECTS_MILLIONAIRE_CIRC} ${OBJECTS_AES_CIRC} ${OBJECTS_LOWMC_CIRC} ${OBJECTS_MIRACL}
	${CC} ${COMPILER_OPTIONS} -o $@ ${CFLAGS} $^ ${LIBRARIES}


%.o: %.cpp
	${CC} $^ ${COMPILER_OPTIONS} -c ${INCLUDE} ${CFLAGS} ${BATCH} -o $@

.PHONY: clean

clean:
	rm ${OBJECTS}
