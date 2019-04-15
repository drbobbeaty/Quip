# Quip

The standard CryptoQuip, as it appears in the comics, is a simple substitution
cypher where one character of the solution is provided, and it's up to the
player to figure out the rest from the provided cyphertext and the clue. It's
a fun little puzzle to play, but that doesn't stop a more _analytical_ approach.

This project is about a few different attacks on solving the general CryptoQuip
puzzle in as short a time as possible. There are other versions of this same
attack, and there are several different attack schemes. This just happens to be
the fastest we've found.

This version is in ANSI C, and is the oldest version we have of the solver as
it exists. There are older - a _Turbo Pascal_ version, was the first, but that
was lost on a 5.25" floppy long ago. It is primarily a benchmark for the
language. This was written in 2002 after I'd decided to move off my IBM PC and
_Turbo Pascal_, and onto the University's computers and C.

## The Origin Story

It all starts at Purdue University in the Fall of 1985, in the EE007 office of a
few friends, and _The Exponent_, the daily campus paper, was publishing the
CryptoQuip puzzle. Jim wanted to solve them himself, and I was simply not
that interested, but I could see that there was a way to _automate_ the
finding of a solution if we simply had a set of _reference_ words.

The first attempt at a solution was really a solution for a _single word_ - which
was a simply `grep` command on the school's BSD unix machines hitting
`/usr/dict/words` and the pattern of the unknown word. That worked for
a while, and then I realized that all I needed was the file of words, and I could
write something on my PC with _Turbo Pascal_ and I could do _all_ the words
in the puzzle.

One thing lead to another... Jim wrote a shell script... I finished my Pascal
version... and at this point, another officemate joined in: Bret. We each
wanted to be able to solve the puzzle as quickly as possible - just by
entering the puzzle and the given hint.

## The Basic Solution

The current algorithm is based on the idea that each cyphertext word is really
a simple pattern of characters. This pattern can then be used to filter out those
words from the master list that simply don't match the pattern. At this point,
each of the cyphertext words will have a series of _possible_ words which then
have to be compared to all the other _possible_ words for all the other
cyphertext words to see what words "match" and create a complete solution.

This is the purpose of the _Legend_. This is simply the potential key to
decoding the puzzle. New _Legends_ will be tried and see if they decode the
plaintext words properly, and if so, we keep checking, if not, we discard that
_Legend_, and try another.

There are a few other things - like what order to check the words, and how to
prune the search tree, but those are all in the code as comments.

## Usage

It's a standard C console app - the `showUsage()` function lists all the options
for submitting the cyphertext, and key. It's still some pretty decent C code.