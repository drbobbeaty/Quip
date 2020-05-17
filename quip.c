
/*
 *	quip.c - a simple cryptoquip solver based on the idea that any
 *			 quip might have several valid legends, or valid
 *			 substitution sets.
 *
 *			 For those that don't know, a cruptoquip is a simple
 *			 substitution cypher typically found on newspaper comics
 *			 pages. A cyphertext is given along with a single character
 *			 'hint' decoded. It's then the job of the solver to decode
 *			 the rest of the cyphertext.
 *
 *	$Id: quip.c,v 1.6 2002/12/13 00:57:28 drbob Exp $
 *
 *	Copyright 2000 Robert E. Beaty, Ph.D. All Rights Reserved
 */

/*
 *	Standard system-level includes
 */
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

/*
 *	System-level & Data type definitions
 */
// nobody but NeXT ever seems to do Boolean data right
#ifndef TRUE
#define TRUE 1
#endif
#ifndef YES
#define YES 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NO
#define NO 0
#endif
#ifndef BOOL
typedef int BOOL;
#endif
// some systems don't have the unsigned long like macOS
#ifndef uint64_t
typedef u_int64_t uint64_t;
#endif

/*
 *	Public Constants
 */
// define the version for this program
#ifndef QUIP_VERSION_MAJOR
#define QUIP_VERSION_MAJOR		0
#endif
#ifndef QUIP_VERSION_MINOR
#define QUIP_VERSION_MINOR		1
#endif
#ifndef QUIP_VERSION_RELEASE
#define QUIP_VERSION_RELEASE	0
#endif
#define QUIP_VERSION	QUIP_VERSION_MAJOR.QUIP_VERSION_MINOR.QUIP_VERSION_RELEASE

// this is the default filename of the words file
#define DEFAULT_WORDS_FILE		"words"

// this is the default logging file
#define DEFAULT_LOG_FILE		"/tmp/quip.log"

// assume that we don't need logging
#define LOG						NO

/*
 *	When creating a new cypherword, the array of possibles starts
 *	this large, and then jumps up in increments this large. This
 *	is to keep the number of reallocations to a minimum and keep
 *	memory usage to a reasonable level.
 */
#define STARTING_POSSIBLES_SIZE		50
#define INCREMENT_POSSIBLES_SIZE	10


/*
 *	We need to have some structures for dealing with the data.
 *	Let's put them all here to make it easy.
 */
/*
 *	This is the 'solution' to the quip - the substitution pattern
 *	that, when applied to the cyphertext yields the plaintext. The
 *	mapping is read: the legend element in the cyphertext and the
 *	value of the legend element is the plaintext.
 */
typedef union {
	char a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z;
	char map[26];
} legend_t;
typedef legend_t legend;
typedef legend *legend_ptr;

/*
 *	This is the 'meat' of the problem - a single cypherword. This
 *	word contains it's size (for convenience) and a list of all
 *	possible matching words based on the structure of the cypherword.
 *	When a legend is applied to a cypherword, some of the possible
 *	words will be generated for that legend, and they can be used
 *	with other 'solutions' from the other cypherwords in the system
 *	to achieve a total cyphertext 'solution'.
 */
typedef struct {
	int		length;
	char	*cyphertext;
	int		numberOfPossibles;
	char	**possiblePlaintext;
	int		possiblePlaintextSize;
} cypherword_t;
typedef cypherword_t cypherword;
typedef cypherword *cypherword_ptr;

/*
 *	One of the utilities we have at our disposal is a character
 *	frequency counter. This is useful for looking at the relative
 *	frequency of both plaintext characters as well as cyphertext
 *	characters. The routine that calculates these numbers is called
 *	GenerateCharacterHistogramWithLegend(legend *map, BOOL showHisto)
 *	and takes a legend to use as the 'givens'. There's also a routine
 *	that prints out the table of relative hits, etc.
 */
typedef struct {
	int		crossMatch[26][26];
	int		plaintext[26];
	int		cyphertext[26];
} characterFrequencyData_t;
typedef characterFrequencyData_t characterFrequencyData;
typedef characterFrequencyData *characterFrequencyData_ptr;


/************************************************************************
 *
 *	Forward-reference Function Definitions
 *
 *	These are all the functions in this file. They are placed here
 *	as prototypes so that the compiler doesn't have to sort out
 *	how something is called, and I don't have to worry about what
 *	order the functions are defined.
 *
 ************************************************************************/
// ...these are the cypherword functions
BOOL 		DoPatternsMatch(char *cyphertext, char *plaintext);
BOOL		CanCypherAndLegendMakePlain(char *cyphertext, legend *map, char *plaintext, BOOL mustBeComplete);
char 		*GetPossibleOfCypherwordForLegend(cypherword *word, legend *map, BOOL mustBeComplete);
BOOL 		IsCypherwordDecryptedByLegend(cypherword *word, legend *map);
cypherword 	*CreateCypherword(char *str);
cypherword 	*DestroyCypherword(cypherword *word);
BOOL 		CheckCypherwordForPossiblePlaintext(cypherword *word, char *str);

// ...these are the legend functions
legend 		*CreateLegend(char cryptChar, char plainChar);
legend 		*DestroyLegend(legend *map);
legend 		*DuplicateLegend(legend *map);
void 		SetLegendToLegend(legend *dest, legend *src);
BOOL		DoesLegendEqualLegend(legend *a, legend *b);
void		PrintLegend(legend *map);
char 		CypherToPlainChar(legend *map, char c);
char 		PlainToCypherChar(legend *map, char c);
char 		*CypherToPlainString(legend *map, char *cyphertext);
char 		*PlainToCypherString(legend *map, char *plaintext);

// ...these are the high-level cypherword and encrypting functions
BOOL 		ReadAndProcessPlaintextFile(char* filename);
void 		EncryptPlaintext(char *text, BOOL showLegend, BOOL genCmdLine);
BOOL 		CreateCypherwordsFromCyphertext(char *text);

// ...these are the character frequency counting routines
characterFrequencyData 	*GenerateCharacterCountsWithLegend(legend *map);
void 		PrintCrossMatchData(characterFrequencyData *data);

// ...these are the frequency attack functions
BOOL 		DoFrequencyAttack(legend *map, int maxSec);
void 		BuildFreqAttackLegend(int cyphercharIndex, legend *map);
void 		TestFreqAttackLegend(legend *map);

// ...these are the word block attack functions
BOOL 		DoWordBlockAttack(int cypherwordIndex, legend *map, int maxSec);
BOOL 		IncorporateCypherToPlainMapInLegend(char *cyphertext, char *plaintext, legend *map);

// ...these are the general UI functions
void 		showUsage();
void		logIt(char *msg);


/************************************************************************
 *
 *	Global Definitions
 *
 ************************************************************************/
/*
 *	These are the global variables that will be used in this program.
 */
int				wordCount = 0;
cypherword		**words = NULL;
int				legendCount = 0;
legend			**legends = NULL;
legend			*userLegend = NULL;
unsigned int	randSeed;
char			*initialCyphertext = NULL;
char			**plainText;
int				plainTextMaxCnt;
int				plainTextCnt;
BOOL			htmlOutput = NO;


/************************************************************************
 *
 *	Cypherword functions
 *
 *	These functions are used to allow the main code to manipulate
 *	the cypherwords at a very high level and not have to do a loe
 *	of low-level textual manipulation. In a more OO design, these
 *	would be the methods on the cyphertext object.
 *
 ************************************************************************/
/*
 *	This is an interesting little routine - it looks at a
 *	plaintext and cyphertext and sees if the pattern of
 *	characters exhibited in both match. If they do, then
 *	this routine returns TRUE, if not, then it returns
 *	FALSE.
 */
BOOL DoPatternsMatch(char *cyphertext, char *plaintext) {
	BOOL		error = NO;
	BOOL		matched = YES;
	BOOL		finished = NO;

	// first, see if we have an easy match or not...
	if (!error && !finished) {
		if ((cyphertext == NULL) && (plaintext == NULL)) {
			// they are both NULL, so they match - sort-of...
			matched = YES;
			finished = YES;
		} else if ((cyphertext == NULL) || (plaintext == NULL)) {
			// one is NULL and the other isn't - no match
			matched = NO;
			finished = YES;
		}
	}

	// OK... check the length of the strings
	if (!error && !finished) {
		if (strlen(cyphertext) != strlen(plaintext)) {
			// wrong length
			matched = NO;
			finished = YES;
		}
	}

	// now check the pattern of characters
	if (!error && !finished) {
		int		i, j;
		int		len = strlen(cyphertext);
		char	cypherchar, plainchar;

		for (i = 0; (i < len) && (!finished); i++) {
			// get the cyphertext and plaintext characters
			cypherchar = cyphertext[i];
			plainchar = plaintext[i];

			// check all the remaining chars for the same match
			for (j = (i+1); (j < len) && (!finished); j++) {
				/*
				 *	Check for a repeating in one text and not
				 *	in the other. If they both don't match,
				 *	then stop checking.
				 */
				if (((cyphertext[j] == cypherchar) &&
				     (plaintext[j] != plainchar)) ||
				    ((plaintext[j] == plainchar) &&
					 (cyphertext[j] != cypherchar))) {
					matched = NO;
					finished = YES;
					break;
				}
			}
		}
	}

	return error ? error : matched;
}


/*
 *	This is an interesting little routine... It takes three things:
 *	a cyphertext, a legned and a plaintext - along with a
 *	'mustBeComplete' boolean flag, and sees if the legend can be
 *	used to generate the plaintext from the cyphertext. If the
 *	'mustBeComplete' is YES, then the legend must completly decode
 *	the cyphertext into the plaintext. Otherwise, 'holes' in the
 *	conversion are assumed to be in the favor of the match.
 *
 *	This can be used to see if a legend and a cyphertext are on
 *	the right track to the plsintext - or, if they are 100% there.
 *	The boolean return value simply says 'Yes' they match.
 */
BOOL CanCypherAndLegendMakePlain(char *cyphertext, legend *map, char *plaintext, BOOL mustBeComplete) {
	BOOL		error = NO;
	BOOL		finished = NO;
	BOOL		mismatch = NO;

	// first, let's make sure we have something to do
	if (!error && !finished) {
		if (cyphertext == NULL) {
			error = YES;
			printf("*** Error in CanCypherAndLegendMakePlain() ***\n"
				   "    The cyphertext is NULL, and that means we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}
	if (!error && !finished) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in CanCypherAndLegendMakePlain() ***\n"
				   "    The legend is NULL, and that means that we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}
	if (!error && !finished) {
		if (plaintext == NULL) {
			error = YES;
			printf("*** Error in CanCypherAndLegendMakePlain() ***\n"
				   "    The plaintext is NULL, and that means we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}

	// well... see if they are the right length
	if (!error && !finished) {
		if (strlen(cyphertext) != strlen(plaintext)) {
			mismatch = YES;
			finished = YES;
		}
	}

	// now we need to check each character in the mapping
	if (!error && !finished) {
		int			i;
		char		ppc;

		for (i = 0; i < strlen(cyphertext); i++) {
			// get the possible plaintext char from the mapping
			ppc = CypherToPlainChar(map, tolower(cyphertext[i]));

			// check for completness based on the user's desires
			if ((ppc == 0) && mustBeComplete) {
				mismatch = YES;
				finished = YES;
				break;
			}

			// now see if they match
			if (ppc != 0) {
				if (tolower(ppc) != tolower(plaintext[i])) {
					mismatch = YES;
					finished = YES;
				}
			}
		}
	}

	return error ? NO : !mismatch;
}


/*
 *	This is an interesting little routine... It takes a cypherword
 *	and a legend and sees which, if any, of the possible plaintexts
 *	this cypherword has matches the legend and the cyphertext. If
 *	'mustBeComplete' is TRUE, then there can be no 'missing' letters
 *	in the mapping. If it's FALSE, then missing letters are OK.
 *
 *	The return value will be a pointer to a copy of the cypherword's
 *	possible plaintext, or NULL, if none is found. The caller is
 *	expected to free this copy when they are done with it.
 */
char *GetPossibleOfCypherwordForLegend(cypherword *word, legend *map, BOOL mustBeComplete) {
	BOOL		error = NO;
	BOOL		finished = NO;
	char		*retval = NULL;

	// first, let's make sure we have something to do
	if (!error && !finished) {
		if (word == NULL) {
			error = YES;
			printf("*** Error in GetPossibleOfCypherwordForLegend() ***\n"
				   "    The cypherword is NULL, and that means we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}
	if (!error && !finished) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in GetPossibleOfCypherwordForLegend() ***\n"
				   "    The legend is NULL, and that means that we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}

	// next, we need to look at each one of the possibles and check it
	if (!error && !finished) {
		int		i;

		for (i = 0; (i < word->numberOfPossibles) && !finished; i++) {
			if (CanCypherAndLegendMakePlain(word->cyphertext, map, word->possiblePlaintext[i], mustBeComplete)) {
				// we have a match!
				finished = YES;
				// ...now copy it for return to the caller
				retval = strdup(word->possiblePlaintext[i]);
				if (retval == NULL) {
					error = YES;
					printf("*** Error in GetPossibleOfCypherwordForLegend() ***\n"
						   "    A copy of the plaintext word that matches this cypherword\n"
						   "    and legend could not be obtained due to memory allocation\n"
						   "    problems. This is too bad because we had a solution.\n");
				}
			}
		}
	}

	return error ? NULL : retval;
}


/*
 *	This is an interesting routine... it returns TRUE if the legend
 *	TOTALLY decodes the cypherword into one of it's possible
 *	plaintext words. This routine calls the more general routine
 *	GetPossibleOfCypherwordForLegend() with the 'mustBeComplete'
 *	argument set to TRUE.
 *
 *	This routine is very helpful in testing a legend to see if it
 *	decodes all the cypherwords - one at a time.
 */
BOOL IsCypherwordDecryptedByLegend(cypherword *word, legend *map) {
	BOOL		error = NO;
	BOOL		retval = NO;
	char		*plaintext = NULL;

	// first, let's make sure we have something to do
	if (!error) {
		if (word == NULL) {
			error = YES;
			printf("*** Error in IsCypherwordDecryptedByLegend() ***\n"
				   "    The cypherword is NULL, and that means we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in IsCypherwordDecryptedByLegend() ***\n"
				   "    The legend is NULL, and that means that we have\n"
				   "    nothing to do. Please make sure it isn't NULL.\n");
		}
	}

	// next, let's see what the word might be...
	if (!error) {
		plaintext = GetPossibleOfCypherwordForLegend(word, map, TRUE);
		if (plaintext == NULL) {
			retval = NO;
		} else {
			retval = YES;
			// don't forget to free the plaintext we received
			free(plaintext);
		}
	}

	return error ? error : retval;
}


/*
 *	This routine creates a new cypherword based on the passed-in
 *	character string as the basis of the cyphertext. The cypherword
 *	structure that's returned is completly initialized for use in
 *	this system.
 */
cypherword *CreateCypherword(char *str) {
	BOOL		error = NO;
	cypherword	*retval = NULL;

	// first, make sure we have something to do
	if (!error) {
		if (str == NULL) {
			error = YES;
			printf("*** Error in CreateCypherword() ***\n"
				   "    The passed-in cyphertext was NULL and so no\n"
				   "    cypherword will be created. Try to call this\n"
				   "    routine with a valid cyphertext string.\n");
		}
	}

	// next, we need to allocate a new cypherword structure
	if (!error) {
		retval = (cypherword *) malloc(sizeof(cypherword));
		if (retval == NULL) {
			error = YES;
			printf("*** Error in CreateCypherword() ***\n"
				   "    A new, blank, cypherword could not be allocated.\n"
				   "    This is a significant problem and we can't do anymore.\n");
		}
	}

	// now we can set up the cypherword's internal variables
	if (!error) {
		// first, set the length of the cyphertext
		retval->length = strlen(str);

		// next, copy the cyphertext
		retval->cyphertext = strdup(str);
		if (retval->cyphertext == NULL) {
			error = YES;
			printf("*** Error in CreateCypherword() ***\n"
				   "    While trying to initialize the new cypherword, the\n"
				   "    cyphertext could not be copied into the cypherword's\n"
				   "    internal structures. This is a serious problem.\n");
		}

		// next, allocate the starting possible array
		if (!error) {
			retval->possiblePlaintext = (char **) malloc(STARTING_POSSIBLES_SIZE * sizeof(char*));
			if (retval->possiblePlaintext == NULL) {
				error = YES;
				printf("*** Error in CreateCypherword() ***\n"
					   "    The initial array for holding possible plaintext matches\n"
					   "    to this cypherword could not be allocated. This is a\n"
					   "    serious problem and is cause for great concern.\n");
			} else {
				// all went OK, so save the size and number used
				retval->possiblePlaintextSize = STARTING_POSSIBLES_SIZE;
				retval->numberOfPossibles = 0;
			}
		}
	}

	// if I've run into troubles, I need to free what I might have allocated
	if (error) {
		if (retval != NULL) {
			retval = DestroyCypherword(retval);
		}
	}

	return error ? NULL : retval;
}


/*
 *	When a cypherword structure is no longer needed, this routine
 *	can be called to carefully remove all the resources used in
 *	the structure so that when it's gone, there's a 'zero sum'
 *	resource game.
 */
cypherword *DestroyCypherword(cypherword *word) {
	BOOL		error = NO;
	BOOL		finished = NO;

	// first, make sure we have something to do
	if (!error && !finished) {
		if (word == NULL) {
			// while we could flag this as an error, we can
			// leave it be as a NULL is already 'destroyed'
			finished = YES;
		}
	}

	// now we need to release the cyphertext in this cypherword
	if (!error && !finished) {
		if (word->cyphertext != NULL) {
			free(word->cyphertext);
		}
	}

	// now we need to release all the possible plaintexts
	if (!error && !finished) {
		int		i;

		if (word->possiblePlaintext != NULL) {
			// first, release each word in the array
			for (i = 0; i < word->numberOfPossibles; i++) {
				if (word->possiblePlaintext[i] != NULL) {
					free(word->possiblePlaintext[i]);
				}
			}

			// ...and now release the array itself
			free(word->possiblePlaintext);
		}
	}

	// finally, we need to release the cypherword itself
	if (!error && !finished) {
		free(word);
	}

	return NULL;
}


/*
 *	This routine takes a cypherword and a character string and
 *	checks to see if the string has the right structural pattern
 *	to match the cypherword. If so, the cypherword copies this
 *	character string into it's list of possible plaintext words.
 *	The cypherword will take care of the deallocation of these
 *	resources when the time comes.
 */
BOOL CheckCypherwordForPossiblePlaintext(cypherword *word, char *str) {
	BOOL		error = NO;
	BOOL		finished = NO;

	// first, check and see if we have something to do
	if (!error && !finished) {
		if (word == NULL) {
			error = YES;
			printf("*** Error in CheckCypherwordForPossiblePlaintext() ***\n"
				   "    The passed-in cypherword was NULL, and therefore nothing\n"
				   "    can be used to check against the plaintext. This is most\n"
				   "    likely a bad argument call.\n");
		}
	}
	if (!error && !finished) {
		if (str == NULL) {
			error = YES;
			printf("*** Error in CheckCypherwordForPossiblePlaintext() ***\n"
				   "    The passed in plaintext is NULL, and therefore nothing\n"
				   "    can really be done. Please check arguments before calling.\n");
		}
	}

	// now we need to see if the pattern matches
	if (!error && !finished) {
		if (!DoPatternsMatch(word->cyphertext, str)) {
			// they don't match, so stop checking
			finished = YES;
		}
	}

	/*
	 *	If we're here, then add it to the array of possibles.
	 *	First, see if we have room in the already allocated array,
	 *	and if not, we need to up that by the appropriate amount.
	 *	When we have room in the array, we then need to copy the
	 *	plaintext over to the next available slot.
	 *
	 *	First, check to see if we have room in this array...
	 */
	if (!error && !finished) {
		if (word->numberOfPossibles == word->possiblePlaintextSize) {
			/*
			 *	OK... we need to expand the array the right amount.
			 */
			if (word->possiblePlaintextSize == 0) {
				word->possiblePlaintext = (char **) malloc(STARTING_POSSIBLES_SIZE * sizeof(char *));
			} else {
				word->possiblePlaintext = (char **) realloc(word->possiblePlaintext, (word->possiblePlaintextSize + INCREMENT_POSSIBLES_SIZE)*sizeof(char *));
			}
			if (word->possiblePlaintext == NULL) {
				error = YES;
				printf("*** Error in CheckCypherwordForPossiblePlaintext() ***\n"
					   "    While trying to add the plaintext word '%s' to the\n"
					   "    array of possible plaintext words for this cypherword,\n"
					   "	the array needed to be expanded to hold %d words, but\n"
					   "    couldn't. This is a real big problem!\n", str,
					   (word->possiblePlaintextSize == 0 ? STARTING_POSSIBLES_SIZE : (word->possiblePlaintextSize + INCREMENT_POSSIBLES_SIZE)) );

				// if it's gone, we need to update the sizes
				word->possiblePlaintextSize = 0;
				word->numberOfPossibles = 0;
			} else {
				/*
				 *	OK! it worked, so let's reflect the size change
				 */
				word->possiblePlaintextSize += INCREMENT_POSSIBLES_SIZE;
			}
		}
	}

	// now, we can get a copy of the string and place it in the next slot
	if (!error && !finished) {
		word->possiblePlaintext[word->numberOfPossibles] = strdup(str);
		if (word->possiblePlaintext[word->numberOfPossibles] == NULL) {
			error = YES;
			printf("*** Error in CheckCypherwordForPossiblePlaintext() ***\n"
				   "    A copy of the plaintext '%s' could not be obtained\n"
				   "    for this cypherword. This is a problem because it might\n"
				   "    have been the key to the whole puzzle... too bad. Check\n"
				   "    on it.\n", str);
		} else {
			// went well, so up the count
			word->numberOfPossibles++;
		}
	}

	return !error;
}


/************************************************************************
 *
 *	Legend functions
 *
 *	These functions are used to manipulate the decryption data a.k.a.
 *	the legend in a manner that is very high level so that the user
 *	doesn't have to fiddle around with low-level allocation routines
 *	to get the job done. In a more OO design, these functions would
 *	be the methods on the legend object.
 *
 ************************************************************************/
/*
 *	This routine creates a new legend structure with the single
 *	character mapping of the 'plainChar' for the 'cryptChar' in
 *	the cyphertext. This is useful, for example, in the beginning
 *	when a single mapping pair is given to the program to start.
 */
legend *CreateLegend(char cryptChar, char plainChar) {
	BOOL		error = NO;
	legend		*retval = NULL;

	// first, let's get the space, if we can
	if (!error) {
		retval = (legend *) malloc(sizeof(legend));
		if (retval == NULL) {
			error = YES;
			printf("*** Error in CreateLegend() ***\n"
				   "    The creation of the legend structure failed in\n"
				   "    trying to get the necessary memory from the\n"
				   "    pool. This is a serious memory problem.\n");
		}
	}

	// let's zero out the legend to start with
	if (!error) {
		int		i;

		for (i = 0; i < 26; i++) {
			retval->map[i] = 0;
		}
	}

	// now, let's assign the character we have
	if (!error) {
		retval->map[cryptChar - 'a'] = plainChar;
	}

	return error ? NULL : retval;
}


/*
 *	This routine takes care of releasing the resources used in the
 *	passed-in legend structure, and then the structure itself.
 */
legend *DestroyLegend(legend* map) {

	// first, free up the resources of the legend
	if (map != NULL) {
		// this is easy - now... there's nothing to do
	}

	// now free up the legend structure itself
	if (map != NULL) {
		free(map);
	}

	return NULL;
}


/*
 *	This routine returns a copy of the passed-in legend structure
 *	which is useful if there's a know good part of a key, but the
 *	user wants to experiment with additional keys without having
 *	to keep track of what's been changed in the original legend.
 */
legend *DuplicateLegend(legend* map) {
	BOOL		error = NO;
    legend		*retval = NULL;

	// first, see if we have anything to do
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in DuplicateLegend() ***\n"
				   "    The passed-in legend is NULL. This is most\n"
				   "    likely a simple coding mistake.\n");
		}
	}

	// next, create any old legend
	if (!error) {
		retval = CreateLegend('a', 'a');
		if (retval == NULL) {
			error = YES;
			printf("*** Error in DuplicateLegend() ***\n"
				   "    While trying to duplicate a legend structure\n"
				   "    the new legend could not be created. This is\n"
				   "    a serious problem that needs to be addressed.\n");
		} else {
			// now we can copy over the contents of the old legend
			SetLegendToLegend(retval, map);
		}
	}

	return error ? NULL : retval;
}


/*
 *	This routine simply takes two legends and copies all the data
 *	from the source legend to the destination legend. Both have
 *	to exist, of course.
 */
void SetLegendToLegend(legend* dest, legend *src) {
	BOOL		error = NO;

	// first, make sure we have something to do
	if (!error) {
		if ((dest == NULL) || (src == NULL)) {
			error = YES;
			printf("*** Error in SetLegendToLegend() ***\n"
				   "    Either the source or destination legend is NULL. For\n"
				   "    this routine to work, bpth have to be non-NULL. Please\n"
				   "    make sure that they are both non-NULL.\n");
		}
	}

	// now copy over the data from one to the other
	if (!error) {
		int		i;

		for (i = 0; i < 26; i++) {
			dest->map[i] = src->map[i];
		}
	}
}


/*
 *	This routine returns TRUE if the two legends are equal in
 *	content - though they may not be the same actual object.
 *	This is a simple way to see if two legends under construction
 *	are the same.
 */
BOOL DoesLegendEqualLegend(legend *a, legend *b) {
	BOOL		error = NO;
	BOOL		isEqual = YES;

	// first, make sure we have something to do
	if (!error) {
		if ((a == NULL) || (b == NULL)) {
			error = YES;
			printf("*** Error in DoesLegendEqualLegend() ***\n"
				   "    Either the source or destination legend is NULL. For\n"
				   "    this routine to work, bpth have to be non-NULL. Please\n"
				   "    make sure that they are both non-NULL.\n");
		}
	}

	// next, check each element for a mismatch
	if (!error) {
		int		i;

		for (i = 0; (i < 26) && isEqual; i++) {
			if (a->map[i] != b->map[i]) {
				isEqual = NO;
			}
		}
	}

	// return what we have to the caller
	return isEqual;
}


/*
 *	This useful routine prints out the legend so that the user
 *	can see what's contained within it.
 */
void PrintLegend(legend *map) {
	int		i;

	puts("cypher: abcdefghijklmnopqrstuvwxyz");
	printf("plain:  ");
	for (i = 0; i < 26; i++) {
		printf("%c", (map->map[i] == 0 ? '.' : map->map[i]));
	}
	printf("\n");
}


/*
 *	This routine takes a cyphertext character and a legend and
 *	returns the plaintext character. This is used to decode the
 *	cyphertext into plaintext - one character at a time.
 */
char CypherToPlainChar(legend *map, char c) {
	BOOL		error = NO;
	BOOL		upperCase = NO;
	char		retval = c;

	// make sure we have something to map through
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in CypherToPlainChar() ***\n"
				   "    The passed-in legend structure was NULL which\n"
				   "    means that there can be no mapping. This is\n"
				   "    a serious problem - please look into it.\n");
		}
	}

	// now, see if the character can be converted
	if (!error) {
		// see if it's upper case
		if (isupper(retval)) {
			upperCase = YES;
			retval = tolower(retval);
		}

		if (islower(retval)) {
			retval = map->map[retval - 'a'] + (upperCase ? ('A' - 'a') : 0);
		}
	}

	// now return it to the caller
	return error ? 0 : retval;
}


/*
 *	This routine takes a plaintext character and a legend and
 *	returns the cyphertext character. This is used to encode the
 *	plaintext into cyphertext - one character at a time.
 */
char PlainToCypherChar(legend *map, char c) {
	BOOL		error = NO;
	BOOL		upperCase = NO;
	char		retval = c;

	// make sure we have something to map through
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in PlainToCypherChar() ***\n"
				   "    The passed-in legend structure was NULL which\n"
				   "    means that there can be no mapping. This is\n"
				   "    a serious problem - please look into it.\n");
		}
	}

	// now, see if the character can be converted
	if (!error) {
		// see if it's upper case
		if (isupper(retval)) {
			upperCase = YES;
			retval = tolower(retval);
		}

		if (islower(retval)) {
			// this is a back-search through the map
			int		i;

			for (i = 0; i < 26; i++) {
				if (map->map[i] == retval) {
					retval = (i + 'a') + (upperCase ? ('A' - 'a') : 0);
					break;
				}
			}
		}
	}

	// now return it to the caller
	return error ? 0 : retval;
}


/*
 *	This routine takes a cyphertext character string and converts
 *	it to plaintext based on the legend provided. This is useful
 *	for doing a complete decryption on a string based on a given
 *	legend. The returned value is a new character string that
 *	the caller is responsible for freeing - or NULL in case of
 *	an error.
 */
char *CypherToPlainString(legend *map, char *cyphertext) {
	BOOL		error = NO;
	char		*retval = NULL;

	// first, make sure we have something to do
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in CypherToPlainString() ***\n"
				   "    The legend structure passed-in to this routine\n"
				   "    is NULL, and therefore no transformation can\n"
				   "    take place. This is a serious problem that needs\n"
				   "    to be looked at.\n");
		}
	}
	if (!error) {
		if (cyphertext == NULL) {
			error = YES;
			printf("*** Error in CypherToPlainString() ***\n"
				   "    The cyphertext string passed-in to this routine\n"
				   "    is NULL, and therefore no transformation can\n"
				   "    take place. This is a serious problem that needs\n"
				   "    to be looked at.\n");
		}
	}

	// now, I need to create a new string that's the right size
	if (!error) {
		retval = (char *) malloc((strlen(cyphertext)+1) * sizeof(char));
		if (retval == NULL) {
			error = YES;
			printf("*** Error in CypherToPlainString() ***\n"
				   "    A new string to contain the plaintext could not be\n"
				   "    allocated. This is a serious error.\n");
		}
	}

	// now I can do the right conversion a character at a time
	if (!error) {
		int		i;
		int		len = strlen(cyphertext);

		for (i = 0; i < len; i++) {
			retval[i] = CypherToPlainChar(map, cyphertext[i]);
		}
		retval[len] = '\0';
	}

	// if I had an error, ditch anything I might have allocated
	if (error) {
		if (retval != NULL) {
			free(retval);
		}
	}

	return error ? NULL : retval;
}


/*
 *	This routine takes a plaintext character string and converts
 *	it to cyphertext based on the legend provided. This is useful
 *	for doing a complete encryption on a string based on a given
 *	legend. The returned value is a new character string that
 *	the caller is responsible for freeing - or NULL in case of
 *	an error.
 */
char *PlainToCypherString(legend *map, char *plaintext) {
	BOOL		error = NO;
	char		*retval = NULL;

	// first, make sure we have something to do
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in PlainToCypherString() ***\n"
				   "    The legend structure passed-in to this routine\n"
				   "    is NULL, and therefore no transformation can\n"
				   "    take place. This is a serious problem that needs\n"
				   "    to be looked at.\n");
		}
	}
	if (!error) {
		if (plaintext == NULL) {
			error = YES;
			printf("*** Error in PlainToCypherString() ***\n"
				   "    The plaintext string passed-in to this routine\n"
				   "    is NULL, and therefore no transformation can\n"
				   "    take place. This is a serious problem that needs\n"
				   "    to be looked at.\n");
		}
	}

	// now, I need to create a new string that's the right size
	if (!error) {
		retval = (char *) malloc((strlen(plaintext)+1) * sizeof(char));
		if (retval == NULL) {
			error = YES;
			printf("*** Error in PlainToCypherString() ***\n"
				   "    A new string to contain the cyphertext could not be\n"
				   "    allocated. This is a serious error.\n");
		}
	}

	// now I can do the right conversion a character at a time
	if (!error) {
		int		i;
		int		len = strlen(plaintext);

		for (i = 0; i < len; i++) {
			retval[i] = PlainToCypherChar(map, plaintext[i]);
		}
		retval[len] = '\0';
	}

	// if I had an error, ditch anything I might have allocated
	if (error) {
		if (retval != NULL) {
			free(retval);
		}
	}

	return error ? NULL : retval;
}


/*************************************************************************
 *
 *	Cyphertext functions
 *
 *	These functions are used at a high level to manipulate the
 *	individual cypherwords in the system to try and find those
 *	legends that completly and accurately specify the solution
 *	to the problem.
 *
 ************************************************************************/
/*
 *	This function takes the name of a text file that has one
 *	word per line and reads in each word and passes it to each
 *	of the known cypherwords in the system.
 */
BOOL ReadAndProcessPlaintextFile(char* filename) {
	BOOL		error = NO;
	FILE		*fp = NULL;
	char		linebuf[2048];

	// first, make sure we have something to do
	if (!error) {
		if (filename == NULL) {
			error = YES;
			printf("*** Error in ReadAndProcessPlaintextFile() ***\n"
				   "    The name of the file is NULL, and this means no\n"
				   "    processing can be done because no file. Try giving\n"
				   "    this routine a valid filename.\n");
		}
	}

	// next, try to open the file for reading
	if (!error) {
		fp = fopen(filename, "r");
		if (fp == NULL) {
			error = YES;
			printf("*** Error in ReadAndProcessPlaintextFile() ***\n"
				   "    The file '%s' could not be opened for reading.\n"
				   "    This is a serious problem as the file is the basis\n"
				   "    for the decryption of the cyphertext.\n", filename);
		}
	}

	// next, go through all the words in the file and process each
	if (!error) {
		int		lpos;
		int		i;

		while (!error && (fgets(linebuf, 2048, fp) != NULL)) {
			// skip past anything not a character in the buffer
			lpos = 0;
			while (!isalpha(linebuf[lpos]) && (lpos < 2048)) {
				lpos++;
			}

			// ...go through the word that is on this line...
			i = lpos;
			while ((isalpha(linebuf[i]) || (linebuf[i] == '\'') || (linebuf[i] == '-')) && (i < 2048)) {
				i++;
			}

			// ...and NULL terminate it when it's done
			linebuf[i] = '\0';

			for (i = 0; i < wordCount; i++) {
				if (!CheckCypherwordForPossiblePlaintext(words[i], &(linebuf[lpos]))) {
					error = YES;
					printf("*** Error in ReadAndProcessPlaintextFile() ***\n"
						   "    While checking the plaintext word '%s' against\n"
						   "    the cypherwords, an error occurred. Check the logs\n"
						   "    to see why this might have happened.\n", linebuf);
				}
			}
		}
	}

	// now we can close the file because we're done
	if (!error) {
		if (fp != NULL) {
			fclose(fp);
		}
	}

	return !error;
}


/*
 *	This routine takes a plaintext character string and encrypts
 *	it so that it might be used for feeding into programs such
 *	as this. This might be considered a program within a program
 *	but it exists to make testing of the decoding program much
 *	simpler and much faster.
 */
void EncryptPlaintext(char *text, BOOL showLegend, BOOL genCmdLine) {
	BOOL		error = NO;
	BOOL		keepGoing = YES;
	legend		*encryptingLegend = NULL;
	char		*encrypted = NULL;

	// first, make sure that we have something to do
	if (!error && keepGoing) {
		if (text == NULL) {
			error = YES;
			printf("*** Error in EncryptPlaintext() ***\n"
				   "    The plaintext was NULL so there's nothing\n"
				   "    we can really do. Check this before calling\n"
				   "    this routine.\n");
		}
	}

	/*
	 *	Next, we need a 1:1 legend and then we need to
	 *	scramble it up so that it's an encrypting legend
	 */
	if (!error && keepGoing) {
		encryptingLegend = CreateLegend('a', 'a');
		if (encryptingLegend == NULL) {
			error = YES;
			printf("*** Error in EncryptPlaintext() ***\n"
				   "    While trying to encrypt the plaintext, the legend\n"
				   "    could not be created. This is a serious allocation\n"
				   "    problem that needs to be looked into.\n");
		}
	}

	// now we need to populate the rest of the legend
	if (!error && keepGoing) {
		char	c;

		for (c = 'b'; c <= 'z'; c++) {
			encryptingLegend->map[c - 'a'] = c;
		}
	}

	// now we need to scramble it up quite a bit
	if (!error && keepGoing) {
		int		i;
		int		ia, ib;
		char	t;

		for (i = 0; i < 500; i++) {
			ia = rand_r(&randSeed) % 26;
			ib = (ia + (rand_r(&randSeed) % 26)) % 26;

			t = encryptingLegend->map[ib];
			encryptingLegend->map[ib] = encryptingLegend->map[ia];
			encryptingLegend->map[ia] = t;
		}

		// check the integrity of the legend by checking the scramble
		for (i = 0; i < 26; i++) {
			if (encryptingLegend->map[i] == ('a' + i)) {
				// switch this 'a' = 'a' with someone else
				ib = (i + (rand_r(&randSeed) % 26)) % 26;
				if (i == ib) {
					ib = (i + 1) % 26;
				}

				t = encryptingLegend->map[ib];
				encryptingLegend->map[ib] = encryptingLegend->map[i];
				encryptingLegend->map[i] = t;
			}
		}
	}

	// now I need to show it to the user, if he wants to see it
	if (!error && keepGoing) {
		if (showLegend) {
			int		i;

			printf("Generated encryption legend:\n");
			for (i = 0; i < 26; i++) {
				printf("   %c = %c\n", ('a' + i), encryptingLegend->map[i]);
			}
			printf("\n");
		}
	}

	/*
	 *	Next, let's encrypt this string with the new legend
	 */
	if (!error && keepGoing) {
		encrypted = PlainToCypherString(encryptingLegend, text);
		if (encrypted == NULL) {
			error = YES;
			printf("*** Error in EncryptPlaintext() ***\n"
				   "    The encrypted string could not be generated from\n"
				   "    the plaintext and the newly created legend. This\n"
				   "    is a serious problem.\n");
		}
	}

	/*
	 *	Next, we need to output the encrypted string in the
	 *	right format based on what the user wants to see.
	 */
	if (!error && keepGoing) {
		int		i;

		// show the user the encrypted string
		printf("%s%s%s", (genCmdLine ? "quip '" : ""), encrypted, (genCmdLine ? "'" : "\n"));

		// now, pick a hint character to give them
		i = rand_r(&randSeed) % strlen(text);
		while (!isalpha(text[i])) {
			i = (i + 1) % strlen(text);
		}
		printf(" %s%c=%c\n", (genCmdLine ? "-k" : ""), PlainToCypherChar(encryptingLegend, text[i]), text[i]);
	}

	// now we can free the resources we've used in this routine
	if (encryptingLegend != NULL) {
		encryptingLegend = DestroyLegend(encryptingLegend);
	}
	if (encrypted != NULL) {
		free(encrypted);
	}
}


/*
 *	This routine initializes the list of cyberwords by scanning
 *	the provided text and makes all the cyberwords necessary to
 *	model the decryption process.
 */
BOOL CreateCypherwordsFromCyphertext(char *text) {
	BOOL		error = NO;
	int			i;
	char		*word = NULL;

	// first, make sure that I have something to do
	if (!error) {
		if (text == NULL) {
			error = YES;
			if (htmlOutput) {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
					   "    The passed-in cyphertext was NULL and so no parsing<BR>\n"
					   "    could be done. This is probably a programming error.<BR>\n");
			} else {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
					   "    The passed-in cyphertext was NULL and so no parsing\n"
					   "    could be done. This is probably a programming error.\n");
			}
		} else {
			int		len = strlen(text);

			// make sure it contains nothing but legal characters
			for (i = 0; i < len; i++) {
				if (!(isspace(text[i]) || isalpha(text[i]) || ispunct(text[i]))) {
					error = YES;
					if (htmlOutput) {
						printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
							   "    The passed-in cyphertext contains characters other<BR>\n"
							   "    than A-Z, a-z, spaces and simple punctuation. This<BR>\n"
							   "    is the only form of the cyphertext that this parser<BR>\n"
							   "    understands.<BR>\n");
					} else {
						printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
							   "    The passed-in cyphertext contains characters other\n"
							   "    than A-Z, a-z, spaces and simple punctuation. This\n"
							   "    is the only form of the cyphertext that this parser\n"
							   "    understands.\n");
					}
					break;
				}
			}
		}
	}

	// now I need to reset the list of cypherwords
	if (!error) {
		if ((words != NULL) && (wordCount > 0)) {
			// first, ditch all the individual existing words
			for (i = 0; i < wordCount; i++) {
				words[i] = DestroyCypherword(words[i]);
			}

			// ...now free the array itself
			free(words);
			words = NULL;

			// ...and reset the number of words in it
			wordCount = 0;
		}
	}

	// now I need to make a temp word buffer of the maximum size
	if (!error) {
		word = (char *) malloc((strlen(text)+1) * sizeof(char));
		if (word == NULL) {
			error = YES;
			if (htmlOutput) {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
					   "    The temporary word buffer could not be created.<BR>\n"
					   "    This is serious because this is used in the parsing<BR>\n"
					   "    of the cyphertext into cypherwords.<BR>\n");
			} else {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
					   "    The temporary word buffer could not be created.\n"
					   "    This is serious because this is used in the parsing\n"
					   "    of the cyphertext into cypherwords.\n");
			}
		}
	}

	// now I need to count the number of words to know what to do
	if (!error) {
		int		len = strlen(text);
		BOOL	countWord;

		i = 0;
		while (!error && (i < len)) {
			// pass up any whitespace and stop at a character
			while ((isspace(text[i]) || ispunct(text[i])) && (i < len)) {
				i++;
			}

			// go through anything not whitespace
			countWord = NO;
			while ((isalpha(text[i]) || ispunct(text[i])) && (i < len)) {
				i++;
				countWord = YES;
			}

			// up the count if we actually had a word
			if (countWord) {
				wordCount++;
			}
		}

		// now see if we had any words at all in the text
		if (wordCount == 0) {
			error = YES;
			if (htmlOutput) {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
					   "    There were no words found in the cyphertext. This<BR>\n"
					   "    represents a trivial condition and won't be done.<BR>\n");
			} else {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
					   "    There were no words found in the cyphertext. This\n"
					   "    represents a trivial condition and won't be done.\n");
			}
		}
	}

	// now with the number of words, I can allocate the words array
	if (!error) {
		words = (cypherword **) malloc(wordCount * sizeof(cypherword *));
		if (words == NULL) {
			error = YES;
			if (htmlOutput) {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
					   "    The array of cypherwords could not be allocated.<BR>\n"
					   "    This is a serious problem because this is used to<BR>\n"
					   "    hold the cypherwords from the cyphertext.<BR>\n");
			} else {
				printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
					   "    The array of cypherwords could not be allocated.\n"
					   "    This is a serious problem because this is used to\n"
					   "    hold the cypherwords from the cyphertext.\n");
			}
		}
	}

	// now I can go through the cyphertext again making cypherwords
	if (!error) {
		int		len = strlen(text);
		int		j;
		int		w = 0;

		i = 0;
		while (!error && (i < len)) {
			// pass up any whitespace and stop at a character
			while ((isspace(text[i]) || ispunct(text[i])) && (i < len)) {
				i++;
			}

			// go through anything reasonable and save it
			j = 0;
			while ((isalpha(text[i]) || (text[i] == '\'')) && (i < len)) {
				word[j++] = text[i++];
			}
			word[j] = '\0';

			// create a new cypherword if there was a word
			if (j > 0) {
				words[w] = CreateCypherword(word);
				if (words[w] == NULL) {
					error = YES;
					if (htmlOutput) {
						printf("*** Error in CreateCypherwordsFromCyphertext() ***<BR>\n"
							   "    The cypherword '%s' could not be created properly.<BR>\n"
							   "    This is a serious problem and we can't go on.<BR>\n", word);
					} else {
						printf("*** Error in CreateCypherwordsFromCyphertext() ***\n"
							   "    The cypherword '%s' could not be created properly.\n"
							   "    This is a serious problem and we can't go on.\n", word);
					}
				} else {
					w++;
				}
			}
		}
	}

	// in the end, I have to release whatever I've used in this routine
	if (word != NULL) {
		free(word);
	}

	return !error;
}


/*************************************************************************
 *
 *	Frequency Counting and Histogram Routines
 *
 ************************************************************************/
/*
 *	This is an interesting little routine to determine the
 *	frequency of each possible matching of plainchar to
 *	cypherchar in the list of cypherwords. It also counts
 *	the frequency of plaintext characters as well as the
 *	frequency of cyphertext characters. This might be
 *	useful in large lists of cypherwords to get some idea
 *	of the possible legend for the solution based on the
 *	relative frequency of characters in matched words.
 *	The return value is a characterFrequencyData structure
 *	that the caller MUST free on it's own.
 *
 *	The purpose of the legend is to say 'calculate the data
 *	but only for the possible words that ALSO match this
 *	legend'. In this way, there can be many different data
 *	sets - one for each possible legend for the solution.
 */
characterFrequencyData *GenerateCharacterCountsWithLegend(legend *map) {
	BOOL					error = NO;
	characterFrequencyData	*retval = NULL;
	int						cypherchar, plainchar;
	int						i, j;

	// first, make sure we have something to do
	if (!error) {
		if (wordCount == 0) {
			error = YES;
			printf("*** Error in GenerateCharacterCountsWithLegend() ***\n"
				   "    There are no cypherwords to process, this means we\n"
				   "    cannot generate a histogram. Try again with words.\n");
		}
	}

	// next, we need to make a return structure to hold the info
	if (!error) {
		retval = (characterFrequencyData *) malloc(sizeof(characterFrequencyData));
		if (retval == NULL) {
			error = YES;
			printf("*** Error in GenerateCharacterCountsWithLegend() ***\n"
				   "    The characterFrequencyData structure used to return\n"
				   "    the information from this routine could not be allocated.\n"
				   "    This is a serious problem that needs to be addressed.\n");
		}
	}

	// next, clear out the bins we'll be using for counting
	if (!error) {
		for (i = 0; i < 26; i++) {
			// these are the total numbers of each type of character
			retval->plaintext[i] = 0;
			retval->cyphertext[i] = 0;
			for (j = 0; j < 26; j++) {
				// these are the number of 'matches' of each type
				retval->crossMatch[i][j] = 0;
			}
		}
	}

	/*
	 *	Now, for each word in the cypherword list, go through
	 *	each possible plaintext word and tally up the 'hits'
	 *	for each of the characters that might be substituted
	 *	for each cypherchar.
	 */
	if (!error) {
		BOOL		countWord;
		int			pos;
		char		ptc;

		// look at each cypherword in the array we have
		for (i = 0; i < wordCount; i++) {
			// ...for each word, look at each possible plaintext
			for (pos = 0; pos < words[i]->numberOfPossibles; pos++) {
				/*
				 *	Check to see if the legend works for this
				 *	cypher/plain pair - but only do so if the
				 *	legend exists. If not, then assume that all
				 *	words are to be counted.
				 */
				countWord = YES;
				if (map != NULL) {
					for (j = 0; j < words[i]->length; j++) {
						ptc = CypherToPlainChar(map, words[i]->cyphertext[j]);
						if ((ptc != 0) && (tolower(ptc) != tolower(words[i]->possiblePlaintext[pos][j]))) {
							// skip this plaintext word because of legend
							countWord = NO;
							break;
						}
					}
				}

				// if this word passes the legend, count up the hits
				if (countWord) {
					for (j = 0; j < words[i]->length; j++) {
						if (isalpha(words[i]->cyphertext[j])) {
							retval->plaintext[(tolower(words[i]->possiblePlaintext[pos][j]) - 'a')]++;
							retval->cyphertext[(tolower(words[i]->cyphertext[j]) - 'a')]++;
							retval->crossMatch[(tolower(words[i]->cyphertext[j]) - 'a')][(tolower(words[i]->possiblePlaintext[pos][j]) - 'a')]++;
						}
					}
				}
			}
		}
	}

	// if we had any trouble, release what we've created
	if (error) {
		if (retval != NULL) {
			free(retval);
		}
	}

	return error ? NULL : retval;
}


/*
 *	This is a useful little routine that will print out a
 *	nice picture of the cross-character histogram as output
 *	by the routine GenerateCharacterHistogramWithLegend().
 *	Because it's a little bit bigger than 26 lines long, it
 *	won't all fit on a conventional 80x24 screen. But it does
 *	fit in 80 characters wide...
 */
void PrintCrossMatchData(characterFrequencyData *data) {
	BOOL		error = NO;
	int			i, j;

	/*
	 *	The plaintext is across the top and the cyphertext
	 *	is alongthe left side...
	 */
	if (!error) {
		printf("   a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z\n");
		for (i = 0; i < 26; i++) {
			printf("%c ", (i + 'a'));
			for (j = 0; j < 26; j++) {
				printf("%2d ", data->crossMatch[i][j]);
			}
			printf("\n");
		}
	}
}


/*************************************************************************
 *
 *	Frequency-Counting Attack Routines
 *
 ************************************************************************/
/*
 *	These are the quasi-global variables used in the execution
 *	of the frequency attack. They are a pain to pass between
 *	routines, so I'll keep them here as global variables but
 *	defined close to their point of use.
 */
char	possibleChar[26][26];
int		possibleCharHitCnt[26][26];
int		possibleCharCount[26];

/*
 *	This routine tries to solve the decryption using a modified
 *	search algorithm based on the frequency of matched characters
 *	between the cyphertext and the plaintext. Because this 'machine'
 *	is only capable of solving for plaintext words it knows, the
 *	cross-match frequency data tells me the only character-pairs
 *	I need to be checking for in the legend.
 *
 *	With this reduced search space, the job should be much easier
 *	and faster, since I know what I'm trying has some matches to it.
 *
 *	The purpose of the legend here is to reduce the search space
 *	even further based on the "known" keys provided by the user.
 */
BOOL DoFrequencyAttack(legend *map, int maxSec) {
	BOOL					error = NO;
	characterFrequencyData	*histo = NULL;
	legend					*myMap = NULL;

	// first, let's get the frequency data
	if (!error) {
		histo = GenerateCharacterCountsWithLegend(map);
		if (histo == NULL) {
			error = YES;
			printf("*** Error in DoFrequencyAttack() ***\n"
				   "    The basis of this attack is that with the frequency data\n"
				   "    the search space will be drastically reduced. Yet, I can't\n"
				   "    get that data. Check the logs for the cause of the problem.\n");
		}
	}

	// duplicate the passed-in legend so we can fiddle with it
	if (!error) {
		myMap = DuplicateLegend(map);
		if (myMap == NULL) {
			error = YES;
			printf("*** Error in DoFrequencyAttack() ***\n"
				   "    The passed-in legend needs to be copied so that I have a\n"
				   "    legend to work with in trying to solve this problem. As\n"
				   "    it turns out, that copy operation failed. So I won't have\n"
				   "    any luck in trying to get the solution through this plan.\n");
		}
	}

	/*
	 *	Next, we need to build from the histographic data, the
	 *	array of possible plaintext characters for each cyphertext
	 *	character. When we get this 'list' for each cypherchar,
	 *	we'll sort them by number of hits to make the most likely
	 *	plaintext-to-cyphertext matches be the first ones chosen.
	 *	We'll also be counting how many possibilities there are
	 *	for each cypherchar so that we can easily loop through all
	 *	of them and not miss a one.
	 */
	if (!error) {
		int		i, j;
		int		cc;

		// do this for each cypherchar...
		for (cc = 0; cc < 26; cc++) {
			// reset the number of possibles for this character
			possibleCharCount[cc] = 0;

			// copy over the entire line of histographic data
			for (i = 0; i < 26; i++) {
				possibleChar[cc][i] = (i + 'a');
				possibleCharHitCnt[cc][i] = histo->crossMatch[cc][i];
				// see if there is a real 'hit'
				if (possibleCharHitCnt[cc][i] > 0) {
					possibleCharCount[cc]++;
				}
			}

			// now sort the hits by weight along this cypherchar 'line'
			if (possibleCharCount[cc] > 0) {
				char	tempChar;
				int		tempHits;

				// I know a bubble sort is not the best, but it's easy
				for (i = 0; i < 26; i++) {
					for (j = i+1; j < 26; j++) {
						if (possibleCharHitCnt[cc][i] < possibleCharHitCnt[cc][j]) {
							tempChar = possibleChar[cc][i];
							tempHits = possibleCharHitCnt[cc][i];

							possibleChar[cc][i] = possibleChar[cc][j];
							possibleCharHitCnt[cc][i] = possibleCharHitCnt[cc][j];

							possibleChar[cc][j] = tempChar;
							possibleCharHitCnt[cc][j] = tempHits;
						}
					}
				}
			}
		}
	}

	if (!error) {
		int		i, j;

		puts("frequency attack:");
		for (i = 0; i < 26; i++) {
			if (possibleCharCount[i] > 0) {
				printf("%c : ", (i + 'a'));
				for (j = 0; j < possibleCharCount[i]; j++) {
					printf("%c", possibleChar[i][j]);
				}
				printf("\n");
			}
		}
	}

	/*
	 *	At this point, I have a list of possible plaintext
	 *	characters for each cyphertext character - organized
	 *	from highest probability of a match to lowest. I also
	 *	have the corresponding number of possible matches
	 *	by cypherchar so that doing a search over this space
	 *	is both efficient and complete.
	 *
	 *	By calling BuildFreqAttackLegend() we're using
	 *	recursion to scan the complete decoding space and
	 *	call the necessary break-out routines to test a
	 *	possible legend when the time is right.
	 */
	if (!error) {
		BuildFreqAttackLegend(0, myMap);
	}

	// in the end, we need to free our unnecessary resources
	if (histo != NULL) {
		free(histo);
	}

	return !error;
}


/*
 *	This routine is complex to follow, but it's worth it.
 *	The goal of the frequency attack is to reduce the number
 *	of possible legends to try by first determining what the
 *	possible make-up of all legends must be. The main attack
 *	routine already did this. Now it's up to me to try each
 *	of these different possibilities as a solution. To do
 *	this is interesting... we need to use recursion in the
 *	middle of the 'for' loop because I want to scan 'down'
 *	the list of cyphertext characters before I move to the
 *	next possible value of any given cyphertext character.
 *
 *	There's also the possibility that there are no known
 *	possible values for a cyphertext character. This could
 *	easily happen because a certain letter is not used in
 *	a particular cyphertext. In this case, we have to act
 *	as though everything is fine and continue on processing.
 */
void BuildFreqAttackLegend(int cyphercharIndex, legend *map) {
	// first, see if the cypherchar doesn't have any possibilities
	if (possibleCharCount[cyphercharIndex] == 0) {
		// is it the 'z'?
		if (cyphercharIndex == 25) {
			// yep, so we need to see if this legend is 'good'
			TestFreqAttackLegend(map);
		} else {
			// nope, go get the next cypherchar to add to the legend
			BuildFreqAttackLegend((cyphercharIndex + 1), map);
		}
	} else {
		int		i, j;
		BOOL	skip;

		// OK... we have some to try
		for (i = 0; i < possibleCharCount[cyphercharIndex]; i++) {
			/*
			 *	If we're past the sypher 'a', then make sure that
			 *	the character we want to substitute isn't already
			 *	in the legend. If it is, then skip the character
			 *	because we KNOW that the mapping is 1:1 and non-
			 *	repeating.
			 */
			if (cyphercharIndex > 0) {
				skip = NO;
				for (j = (cyphercharIndex - 1); (j >= 0) && !skip; j--) {
					if (map->map[j] == possibleChar[cyphercharIndex][i]) {
						skip = YES;
					}
				}
			}

			/*
			 *	If we aren't supposed to skip this one due to
			 *	duplicates in the legend, then carry on and do it.
			 */
			if (!skip) {
				// try the next one in the list
				map->map[cyphercharIndex] = possibleChar[cyphercharIndex][i];
				// are we at the 'z'?
				if (cyphercharIndex == 25) {
					// yep, so we need to see if this legend is 'good'
					TestFreqAttackLegend(map);
				} else {
					// nope, go get the next cypherchar to add to the legend
					BuildFreqAttackLegend((cyphercharIndex + 1), map);
				}
			}
		}
	}
}


/*
 *	This routine takes a single completed legend from the
 *	frequency attack plan and tests it against all the
 *	cypherwords to see if it decrypts each. If so, it
 *	prints out the answer. If not, then we'll figure out
 *	if it gets close, and what to do about that later.
 */
void TestFreqAttackLegend(legend *map) {
	BOOL		error = NO;
	BOOL		missed = NO;
	int			hits = 0;

	// first, make sure we have something to do
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in TestFreqAttackLegend() ***\n"
				   "    The legend to test was NULL, and this simply\n"
				   "    can't happen. Please verify that the legend\n"
				   "    is non-NULL before calling this routine.\n");
		}
	}

	// now check each cypherword for a miss
	if (!error) {
		int		i;

		for (i = 0; i < wordCount; i++) {
			if (IsCypherwordDecryptedByLegend(words[i], map)) {
				// yeah! add another hit to the total
				hits++;
			} else {
				// darn! it's a miss on this word!
				missed = YES;
			}
		}
	}

	// see if we have a 100% winner
	if (!error) {
		if ((hits > 0) || (!missed)) {
			char	*decoded = NULL;

			decoded = CypherToPlainString(map, initialCyphertext);
			if (decoded == NULL) {
				error = YES;
				printf("*** Error in TestFreqAttackLegend() ***\n"
					   "    We obtained a perfect decrypting legend for the\n"
					   "    cyphertext, but were unable to decrypt it to show\n"
					   "    it to you. This is a real shame because it worked.\n");
			} else {
				int		j;
				BOOL	newPlainText = YES;

				// see if it matches any of the answers we have
				for (j = 0; (j < plainTextCnt) && newPlainText; j++) {
					if (strcmp(decoded, plainText[j]) == 0) {
						newPlainText = NO;
					}
				}

				// if it's a new answer then save it and write it out
				if (newPlainText) {
					// see if there's enough room in the list
					if (plainTextCnt == plainTextMaxCnt) {
						/*
						 *	OK... we need to expand the array the right
						 *	amount.
						 */
						if (plainTextMaxCnt == 0) {
							plainText = (char **) malloc(STARTING_POSSIBLES_SIZE * sizeof(char *));
						} else {
							plainText = (char **) realloc(plainText, (plainTextMaxCnt + INCREMENT_POSSIBLES_SIZE)*sizeof(char *));
						}
						if (plainText == NULL) {
							error = YES;
							printf("*** Error in TestFreqAttackLegend() ***\n"
								   "    While trying to add the plaintext answer '%s' to the\n"
								   "    array of valid decodings for this cyphertext,\n"
								   "	the array needed to be expanded to hold %d decodings, but\n"
								   "    couldn't. This is a real big problem!\n", decoded,
								   (plainTextMaxCnt == 0 ? STARTING_POSSIBLES_SIZE : (plainTextMaxCnt + INCREMENT_POSSIBLES_SIZE)) );

							// if it's gone, we need to update the sizes
							plainTextCnt = 0;
							plainTextMaxCnt = 0;
						} else {
							/*
							 *	OK! it worked, so let's reflect the size
							 *	change
							 */
							plainTextMaxCnt += INCREMENT_POSSIBLES_SIZE;
						}
					}

					// save it for the caller to print out
					if (!error) {
						plainText[plainTextCnt++] = decoded;
						if (missed) {
							printf("[%d/%d]: '%s'\n", hits, wordCount, decoded);
						}
					}
				}
			}
		}
	}
}


/*************************************************************************
 *
 *	Word Block Attack Routines
 *
 ************************************************************************/
/*
 *	This is the general routine for carrying out the word block
 *	attack on the cyphertext. The idea is that we start with a
 *	user-supplied legend, and then for each plaintext word in the
 *	first cypherword that matches the legend, we add those keys
 *	not in the legend, but supplied by the plaintext to the legend
 *	and then try the next cypherword in the same manner.
 *
 *	There will be quite a few 'passes' in this attack plan, but
 *	hopefully not nearly as many as a character-based scheme.
 */
BOOL DoWordBlockAttack(int cypherwordIndex, legend *map, int maxSec) {
	BOOL		error = NO;
	int			startTime = time(NULL);

	// first, see if we really have any time to do this
	if (!error) {
		if (maxSec <= 0) {
			error = YES;
			printf("*** Error in DoWordBlockAttack() ***\n"
					"    The passed-in maximum time allotment is 0 which\n"
					"    means that there's no time to do anything. This is\n"
					"    too bad, but unaviodable in some cases.\n");
		}
	}

	// now do the meat of the word attack loop
	if (!error) {
		int			i;

		// search over all possibles for this cypherword
		for (i = 0; (i < words[cypherwordIndex]->numberOfPossibles) && !error; i++) {
			// does this map fit - allowing for missing gaps?
			if (CanCypherAndLegendMakePlain(words[cypherwordIndex]->cyphertext, map, words[cypherwordIndex]->possiblePlaintext[i], NO)) {
				// good! Now let's see if we are done with  all words
				if (cypherwordIndex == (wordCount - 1)) {
					// make sure we can really match the last word
					if (IncorporateCypherToPlainMapInLegend(words[cypherwordIndex]->cyphertext, words[cypherwordIndex]->possiblePlaintext[i], map)) {
						// yeah! we have a successful decoding
						char	*decoded = NULL;

						// ...and use this complete legend to decode the text
						decoded = CypherToPlainString(map, initialCyphertext);
						if (decoded == NULL) {
							error = YES;
							printf("*** Error in DoWordBlockAttack() ***\n"
								   "    We obtained a perfect decrypting legend for the\n"
								   "    cyphertext, but were unable to decrypt it to show\n"
								   "    it to you. This is a real shame because it worked.\n");
						} else {
							int		j;
							BOOL	newPlainText = YES;

							// see if it matches any of the answers we have
							for (j = 0; (j < plainTextCnt) && newPlainText; j++) {
								if (strcmp(decoded, plainText[j]) == 0) {
									newPlainText = NO;
								}
							}

							// if it's a new answer then save it and write it out
							if (newPlainText) {
								// see if there's enough room in the list
								if (plainTextCnt == plainTextMaxCnt) {
									/*
									 *	OK... we need to expand the array the right
									 *	amount.
									 */
									if (plainTextMaxCnt == 0) {
										plainText = (char **) malloc(STARTING_POSSIBLES_SIZE * sizeof(char *));
									} else {
										plainText = (char **) realloc(plainText, (plainTextMaxCnt + INCREMENT_POSSIBLES_SIZE)*sizeof(char *));
									}
									if (plainText == NULL) {
										error = YES;
										printf("*** Error in DoWordBlockAttack() ***\n"
											   "    While trying to add the plaintext answer '%s' to the\n"
											   "    array of valid decodings for this cyphertext,\n"
											   "	the array needed to be expanded to hold %d decodings, but\n"
											   "    couldn't. This is a real big problem!\n", decoded,
											   (plainTextMaxCnt == 0 ? STARTING_POSSIBLES_SIZE : (plainTextMaxCnt + INCREMENT_POSSIBLES_SIZE)) );

										// if it's gone, we need to update the sizes
										plainTextCnt = 0;
										plainTextMaxCnt = 0;
									} else {
										/*
										 *	OK! it worked, so let's reflect the size
										 *	change
										 */
										plainTextMaxCnt += INCREMENT_POSSIBLES_SIZE;
									}
								}

								// save it for the caller to print out
								if (!error) {
									plainText[plainTextCnt++] = decoded;
								}
							}
						}
					}
				} else {
					/*
					 *	OK, we had a match but we have more cypherwords
					 *	to check. So, copy the legend, add in the assumed
					 *	values from the plaintext, and move to the next
					 *	word.
					 *
					 *	BUT FIRST, we need to check the run-time. If we're
					 *	past the alloted time given to us then we need to
					 *	bail out - regardless of the state of the
					 *	decryption.
					 */
					int			remainingSec = -1;
					legend		*nextGenMap = NULL;

					/*
					 *	First, check the runtime... Get the remaining time
					 *	for later, if it's applicable.
					 */
					remainingSec = maxSec - (time(NULL) - startTime);
					if (remainingSec <= 0) {
						// no time left - gotta bail out now
						error = YES;
						printf("*** Error in DoWordBlockAttack() ***\n"
								"    We simply ran out of time while trying to solve the\n"
								"    problem. This could be because of too small a word\n"
								"    set or too many possibilities in the words themselves.\n");
						break;
					}

					/*
					 *	Now we can set things up to check the next word
					 */
					nextGenMap = DuplicateLegend(map);
					if (nextGenMap == NULL) {
						error = YES;
						printf("*** Error in DoWordBlockAttack() ***\n"
							   "    The legend passed for cypherword #%d, so we need\n"
							   "    to make a copy to move to the next word. This copy\n"
							   "    could not be made. Please check the logs as to\n"
							   "    why.\n", cypherwordIndex);
						break;
					} else {
						// now we need to augment it from the plaintext
						if (IncorporateCypherToPlainMapInLegend(words[cypherwordIndex]->cyphertext, words[cypherwordIndex]->possiblePlaintext[i], nextGenMap)) {
							// ...and use this new legend for the next word
							DoWordBlockAttack((cypherwordIndex + 1), nextGenMap, remainingSec);
						}

						// ...and don't forget to clean up our messes
						free(nextGenMap);
					}
				}
			}

			/*
			 *	At the end of each loop we really need to see if the amount
			 *	of time we've been given by the caller has elapsed. If it
			 *	has, then we need to quit regardless of what we've found.
			 */
			if ((time(NULL) - startTime) >= maxSec) {
				error = YES;
				printf("*** Error in DoWordBlockAttack() ***\n"
						"    We ran out of time while trying the next word in the\n"
						"    attack. This is too bad, but could be because of too\n"
						"    many words to check.\n");
			}
		}
	}

	return !error;
}


/*
 *	This method sees if we can add the cyphertext-to-plaintext
 *	mapping represented by the two words, into the existing legend
 *	without violating the existing legend, or creating illegal
 *	legend conditions such as different cypherchars going to the
 *	same plainchar, etc.
 */
BOOL IncorporateCypherToPlainMapInLegend(char *cyphertext, char *plaintext, legend *map) {
	BOOL		error = NO;

	// first, make sure we have something to do
	if (!error) {
		if (cyphertext == NULL) {
			error = YES;
			printf("*** Error in IncorporateCypherToPlainMapInLegend() ***\n"
				   "    The passed-in cyphertext was NULL which means that\n"
				   "    there's really nothing to do. Please make sure the\n"
				   "	arguments are non-NULL before calling this routine.\n");
		}
	}
	if (!error) {
		if (plaintext == NULL) {
			error = YES;
			printf("*** Error in IncorporateCypherToPlainMapInLegend() ***\n"
				   "    The passed-in plaintext was NULL which means that\n"
				   "    there's really nothing to do. Please make sure the\n"
				   "	arguments are non-NULL before calling this routine.\n");
		}
	}
	if (!error) {
		if (map == NULL) {
			error = YES;
			printf("*** Error in IncorporateCypherToPlainMapInLegend() ***\n"
				   "    The passed-in legend was NULL which means that\n"
				   "    there's really nothing to do. Please make sure the\n"
				   "	arguments are non-NULL before calling this routine.\n");
		}
	}

	// make sure that the lengths are the same
	if (!error) {
		if (strlen(cyphertext) != strlen(plaintext)) {
			error = YES;
			printf("*** Error in IncorporateCypherToPlainMapInLegend() ***\n"
				   "    The length of the cyphertext was %lu and the length of\n"
				   "    the plaintext was %lu. This means we can't match up the\n"
				   "    characters because they are of different lengths.\n",
				   strlen(cyphertext), strlen(plaintext));
		}
	}

	/*
	 *	OK... now we need to process each character in the cyphertext
	 *	to see if it's already assigned in the legend, etc.
	 */
	if (!error) {
		int		i, j;
		int		len = strlen(cyphertext);
		char	cc, pc;

		for (i = 0; (i < len) && !error; i++) {
			// first, get the plaintext and cyphertext characters
			cc = tolower(cyphertext[i]);
			pc = tolower(plaintext[i]);

			/*
			 *	Next, check for punctuation - if there's a mismatch
			 *	it's no-go... if it's a match, then just skip it.
			 */
			// check for misplaced punctuation
			if ((ispunct(cc) && !ispunct(pc)) || (!ispunct(cc) && ispunct(pc))) {
				// one is punctuation, the other isn't - so no good
				error = YES;
				break;
			}
			// check to see if these are both punctuation
			if (ispunct(cc) && ispunct(pc)) {
				continue;
			}

			// next, see if either side of the mapping already exists
			if (map->map[cc - 'a'] != 0) {
				// OK... is it a match to the existing plaintext?
				if (map->map[cc - 'a'] != pc) {
					// nope... sorry, this is bad news...
					error = YES;
				}
			} else {
				// OK, see if the plaintext char is already mapped
				for (j = 0; (j < 26) && !error; j++) {
					if (map->map[j] == pc) {
						// plaintext is already assigned to another cypherchar
						error = YES;
					}
				}
			}

			// OK... new, valid, mapping data. Let's save it.
			if (!error) {
				map->map[cc - 'a'] = pc;
			}
		}
	}

	return !error;
}


/*************************************************************************
 *
 *	General User interface routines
 *
 ************************************************************************/
/*
 *	This routine simply let's the user know what this program
 *	takes and what it returns. Nothing special here.
 */
void showUsage() {
	printf("quip - %d.%d.%d\n", QUIP_VERSION_MAJOR, QUIP_VERSION_MINOR, QUIP_VERSION_RELEASE);
	puts("  by Robert E. Beaty and James H. Alred");
	puts("");
	puts("Usage: (to create a quip)");
	puts("      quip -e plaintext [-c] [-h]");
	puts("where:");
	puts("      -e - indicates to encode the plaintext");
	puts("      plaintext - is the (quoted) plain text to encode");
	puts("      -c - indicates to create a command line for quip decoding");
	puts("      -l - will show the encrypted legend before cyphertext");
	puts("      -h - print this message");
	puts("");
	puts("Usage: (to decode a quip)");
	puts("      quip cyphertext -ka=b [-ka=b] [-p] [-ffilename] [-F|-W] [-h]");
	puts("where:");
	puts("      cyphertext - is the (quoted) cyphertext to use");
	puts("      -ka=b - indicates known substitution 'b' for 'a'");
	puts("      -Tn - limit the solution search time to (n) sec.");
	puts("      -H - on output, format it as HTML");
	puts("      -ffilename - use the file 'filename' for words");
	puts("      -F - try the 'Frequency Attack' for a solution");
	puts("      -W - try the 'Word Block Attack' for a solution");
	puts("      -h - print this message");
}


/*
 *	This routine logs the message to the appropriate file in the
 *	system with the date and time conveniently displayed at the
 *	beginning of each line for sorting/identification issues.
 */
void logIt(char *msg) {
	BOOL	error = NO;
	char	*dateFmt = NULL;
	FILE	*fp = NULL;

	/*
	 *	First, let's get the date and time into a nice string...
	 */
	if (!error) {
		time_t	now = time(NULL);
		dateFmt = ctime( &now );
		if (dateFmt == NULL) {
			error = YES;
			printf("*** Error in logIt() ***\n"
				   "    The date/time stamp could not be generated for the\n"
				   "    log. This is a serious problem! The message was:\n"
				   "    %s\n", msg);
		} else {
			// drop the '\n' that's in the date/time string
			dateFmt[24] = '\0';
		}
	}

	/*
	 *	Now let's set up the log file for the addition of this message
	 */
	if (!error) {
		fp = fopen(DEFAULT_LOG_FILE, "a");
		if (fp == NULL) {
			error = YES;
			printf("*** Error in logIt() ***\n"
				   "    The log file could not be opened for adding this\n"
				   "    message. This is a serious problem! The message was:\n"
				   "    %s\n", msg);
		} else {
			if (fseek(fp, 0, SEEK_END) == -1) {
				error = YES;
				printf("*** Error in logIt() ***\n"
					   "    The log file could not be positioned for adding this\n"
					   "    message. This is a serious problem! The message was:\n"
					   "    %s\n", msg);
			}
		}
	}

	/*
	 *	Now we can write this message out to the log file
	 */
	if (!error) {
		fprintf(fp, "%s (%s) %s\n", dateFmt, getlogin(), msg);
	}

	/*
	 *	Now clean everything up so that it's all nice and tidy.
	 */
	if (fp != NULL) {
		fclose(fp);
	}
}


/*************************************************************************
 *
 *	MAIN ENTRY POINT
 *
 ************************************************************************/
int main(int argc, char *argv[]) {
	BOOL	error = NO;
	BOOL	keepGoing = YES;
	BOOL	solutionAttempted = NO;
	BOOL	decrypting = YES;
	BOOL	showLegend = NO;
	// default to a reasonable time limit
	int		timeLimit = 20;
	BOOL	creatingCommandLine = NO;
	BOOL	tryingFrequencyAttack = NO;
	BOOL	tryingWordBlockAttack = YES;
	char	*wordsFilename = NULL;
	// this is for logging purposes
	char	logMsg[2408];
	int64_t	runtime_us = 0;

	/*
	 *	First, set up the defaults for this program
	 */
	// reset all the global variables
	if (!error && keepGoing) {
		wordCount = 0;
		words = NULL;
		legendCount = 0;
		legends = NULL;
		userLegend = NULL;
		initialCyphertext = NULL;
		plainText = NULL;
		plainTextCnt = 0;
		plainTextMaxCnt = 0;

		// ...and start the random number generator
		randSeed = time(NULL) % 23487637;
		rand_r(&randSeed);
	}

	/*
	 *	Next, read in the command line options and process each
	 */
	if (!error && keepGoing) {
		int		i;

		for (i = 1; (i < argc) && !error; i++) {
			// check for any options preceeded by a '-'
			if (argv[i][0] == '-') {
				// see what the option is
				switch (argv[i][1]) {
					case 'c' :
						decrypting = NO;
						creatingCommandLine = YES;
						break;
					case 'e' :
						decrypting = NO;
						break;
					case 'f' :
						wordsFilename = strdup(&(argv[i][2]));
						if (wordsFilename == NULL) {
							error = YES;
							printf("*** Error ***\n"
								   "    The file containing the words to use in the\n"
								   "    decryption, '%s', could not be copied for\n"
								   "    later use by the program. This is a serious\n"
								   "    problem and needs to be addressed.\n", &(argv[i][2]));
						}
						break;
					case 'k' :
						// check to see that it's the right format
						if ((!isalpha(argv[i][2])) || (argv[i][3] != '=') || (!isalpha(argv[i][4]))) {
							error = YES;
							printf("*** Error ***\n"
								   "    The format of the '-k' option is bad.\n");
							showUsage();
						}

						// now, add the known info to the user legend
						if (!error) {
							if (userLegend == NULL) {
								// we need to create a new user legend
								userLegend = CreateLegend(argv[i][2], argv[i][4]);
								if (userLegend == NULL) {
									error = YES;
									printf("*** Error ***\n"
										   "    The user-supplied known substitution could not\n"
										   "    be used to create a new user legend structure.\n"
										   "    This is a serious problem because there will be\n"
										   "    no way to know where to start in the solution.\n");
								}
							} else {
								// we can simply add to the existing legend
								userLegend->map[argv[i][2] - 'a'] = argv[i][4];
							}
						}
						break;
					case 'H' :
						htmlOutput = YES;
						break;
					case 'T' :
						if (strlen(argv[i]) > 2) {
							timeLimit = atoi( &(argv[i][2]) );
							if (timeLimit < 0) {
								timeLimit = -1;
							} else if (timeLimit > 300) {
								timeLimit = 300;
							}
						}
						break;
					case 'l' :
						decrypting = NO;
						showLegend = YES;
						break;
					case 'h' :
						showUsage();
						keepGoing = NO;
						break;
					case 'F' :
						tryingFrequencyAttack = YES;
						break;
					case 'W' :
						tryingWordBlockAttack = YES;
						break;
				}
			} else {
				// not an option, so it must be the text
				initialCyphertext = strdup(argv[i]);
				if (initialCyphertext == NULL) {
					error = YES;
					printf("*** Error ***\n"
						   "    The text on the command line: '%s'\n"
						   "    could not be copied for use by this program. This is a\n"
						   "    serious problem in memory allocation.\n", argv[i]);
				}
			}
		}
	}

	/*
	 *	Log what we've got so far - if needed
	 */
	if (!error && keepGoing && LOG) {
		snprintf(logMsg, 2048, "starting: quip='%s' time=%d", initialCyphertext, timeLimit);
		logIt(logMsg);
	}

	/*
	 *	Check to see if we have any cyphertext to process.
	 *	If not, then we need to show the usage and quit.
	 */
	if (!error && keepGoing && (initialCyphertext == NULL)) {
		showUsage();
		keepGoing = NO;
	}

	/*
	 *	At this point, we need to see if we are encrypting the
	 *	plaintext for someone (like me) that needs 'problems'
	 *	to run this program against. If we are generating the
	 *	cyphertext, then let's do that and no more.
	 */
	if (!error && keepGoing && !decrypting) {
		EncryptPlaintext(initialCyphertext, showLegend, creatingCommandLine);

		// now we need to say 'No more' to this program
		keepGoing = NO;
	}

	/*
	 *	If we're here, then we need to split up the rawText
	 *	into a bunch of cypherwords and prepare the system
	 *	for a solution.
	 */
	if (!error && keepGoing) {
		if (!CreateCypherwordsFromCyphertext(initialCyphertext)) {
			error = YES;
			if (htmlOutput) {
				printf("*** Error ***<BR>\n"
					   "    The passsed in cyphertext could not be parsed into<BR>\n"
					   "    cyberwords properly. Please check for messages<BR>\n"
					   "    indicating what might have gone wrong.<BR>\n");
			} else {
				printf("*** Error ***\n"
					   "    The passsed in cyphertext could not be parsed into\n"
					   "    cyberwords properly. Please check for messages\n"
					   "    indicating what might have gone wrong.\n");
			}
		}
	}

	/*
	 *	Next, we need to read in the file of words and
	 *	process each word to see if it's a possible match to
	 *	each cypherword.
	 */
	if (!error && keepGoing) {
		if (!ReadAndProcessPlaintextFile((wordsFilename == NULL ? DEFAULT_WORDS_FILE : wordsFilename))) {
			error = YES;
			printf("*** Error ***\n"
				   "    The file of words could not be processed properly.\n"
				   "    This is a serious problem, but there should be\n"
				   "    some indication as to the cause in the log.\n");
		}
	}

	/*
	 *	Let's try a frequency-based attack on the problem.
	 *	it isn't as 'smart' as others, but it's a complete
	 *	search through all possible legends, and with a
	 *	reduced search space, it should be reasonably fast.
	 */
	if (!error && keepGoing && tryingFrequencyAttack) {
		if (!DoFrequencyAttack(userLegend, timeLimit)) {
			keepGoing = NO;
		}
		// ...well... we certainly tried
		solutionAttempted = YES;
	}

	/*
	 *	Let's try a word-by-word attack on the solution.
	 *	Start with the first plaintext word of the first
	 *	cypherword and put all missing keys into the legend.
	 *	Then, move to the next cypherword and repeat. If
	 *	we do it right, blocks of the legend will be tried
	 *	at once and therefore make it a little more speedy.
	 */
	if (!error && keepGoing && tryingWordBlockAttack) {
		struct timespec	start, end;
		clock_gettime(CLOCK_MONOTONIC_RAW, &start);
		if (!DoWordBlockAttack(0, userLegend, timeLimit)) {
			keepGoing = NO;
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		runtime_us = (end.tv_sec - start.tv_sec) * 1000000
		             + (end.tv_nsec - start.tv_nsec) / 1000;
		// ...well... we certainly tried
		solutionAttempted = YES;
	}

	/*
	 *	Now that I think I'm done, let's print out the
	 *	answers that my code has generated for me. Make
	 *	sure to print out a message if none were found.
	 *	It can happen... and we need to be clear about
	 *	what we've done for the user.
	 */
	if (!error && solutionAttempted) {
		if (plainTextCnt == 0) {
			if (htmlOutput) {
				printf("*** No solutions to this could be found! ***<BR>\n");
			} else {
				printf("*** No solutions to this could be found! ***\n");
			}
		} else {
			int		i;

			for(i = 0; i < plainTextCnt; i++) {
				// see what kind of output the user wants
				if (htmlOutput) {
					printf("%s<BR>\n", plainText[i]);
				} else {
					printf("[%lu us] Solution: %s\n", runtime_us, plainText[i]);
				}
			}
		}
	}

	/*
	 *	Log the end of what we've done
	 */
	if (!error && keepGoing && LOG) {
		snprintf(logMsg, 2048, "terminating: quip='%s'", initialCyphertext);
		logIt(logMsg);
	}

	/*
	 *	When all is said and done, we need to release those
	 *	resources that we've used at some point in the code
	 */
	if (initialCyphertext != NULL) {
		free(initialCyphertext);
		initialCyphertext = NULL;
	}

	if (wordsFilename != NULL) {
		free(wordsFilename);
		wordsFilename = NULL;
	}

	if (userLegend != NULL) {
		userLegend = DestroyLegend(userLegend);
	}

	if (words != NULL) {
		int		i;

		for (i = 0; i < wordCount; i++) {
			words[i] = DestroyCypherword(words[i]);
		}
		free(words);

		words = NULL;
		wordCount = 0;
	}

	if (legends != NULL) {
		int		i;

		for (i = 0; i < legendCount; i++) {
			legends[i] = DestroyLegend(legends[i]);
		}
		free(legends);

		legends = NULL;
		legendCount = 0;
	}

	if (plainText != NULL) {
		int		i;

		for (i = 0; i < plainTextCnt; i++) {
			free(plainText[i]);
		}
		free(plainText);

		plainText = NULL;
		plainTextCnt = 0;
		plainTextMaxCnt = 0;
	}

	return 0;
}
