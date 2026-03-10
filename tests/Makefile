CC=gcc
CFLAGS=-g -O2 -Wall -fcf-protection=none -fno-stack-protector

CXX=g++
CXXFLAGS=-g -O2 -Wall -fcf-protection=none -fno-stack-protector

RM=rm
RMFLAGS=-rf

all: calc figures

calc: calc.c

figures: figures.cpp

clean:
	$(RM) $(RMFLAGS) calc figures

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.cc.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<
