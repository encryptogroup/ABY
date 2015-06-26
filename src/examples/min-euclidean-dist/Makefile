#Makefile for ABY examples

#DO NOT MODIFY THIS FILE, unless you know what you're doing

#You should not need to call this makefile separately. It will me called from the Makefile in the root directory

#relative project folders
BIN = ../../../bin
SRC = ../..
CORE=${SRC}/abycore

SOURCES := $(shell find . -type f -name '*.cpp')
OBJECTS := $(patsubst %.cpp, %.o, ${SOURCES})

# all source files and corresponding object files in abycore
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/util/Miracl/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)

# directory for the Miracl library
MIRACL_LIB_DIR=${CORE}/util/miracl_lib
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

# compiler settings
CC=g++
COMPILER_OPTIONS=-O2
DEBUG_OPTIONS=-g3 -Wall -Wextra
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

#take the current directory's name as name for the executable in ${BIN}
EXAMPLE = $(lastword $(subst /, ,${CURDIR}))

all: ${BIN}/${EXAMPLE}.exe

${BIN}/${EXAMPLE}.exe: ${OBJECTS} ${OBJECTS_CORE} ${OBJECTS_MIRACL}
	${CC} ${COMPILER_OPTIONS} ${CFLAGS} $^ ${LIBRARIES} -o $@

%.o: %.cpp %.h
	${CC} $< ${COMPILER_OPTIONS} -c ${INCLUDE} ${CFLAGS} ${BATCH} -o $@

.PHONY: clean

clean:
	rm ${OBJECTS}
