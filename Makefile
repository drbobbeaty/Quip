#
#  Simple Makefile for quip solver
#

CC = gcc
CCOPTS = -O2
RM = rm

quip:
	$(CC) $(CCOPTS) -o quip quip.c

clean:
	$(RM) quip

