#
#  Simple Makefile for quip solver
#

CC = gcc
CCOPTS = -O2 -g
RM = rm

quip: quip.c
	$(CC) $(CCOPTS) -o quip quip.c

clean:
	$(RM) quip

