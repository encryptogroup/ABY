/**
 \file graycode.h
 \brief Gray code implementation.

 The Gray code is a binary numeral system where two successive
 values differ in only one digit.

 \author Gregory Bard <bard@fordham.edu>
 \author Martin Albrecht <M.R.Albrecht@rhul.ac.uk>
 */

#ifndef GRAYCODE_H_
#define GRAYCODE_H_

#include "typedefs.h"

/******************************************************************************
 *
 *                 M4RI: Linear Algebra over GF(2)
 *
 *    Copyright (C) 2007 Gregory Bard <gregory.bard@ieee.org>
 *    Copyright (C) 2007 Martin Albrecht <malb@informatik.uni-bremen.de>
 *
 *  Distributed under the terms of the GNU General Public License (GPL)
 *  version 2 or higher.
 *
 *    This code is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    General Public License for more details.
 *
 *  The full text of the GPL is available at:
 *
 *                  http://www.gnu.org/licenses/
 ******************************************************************************/

/**
 * \brief Gray codes.
 *
 * A codestruct represents one entry in the code book, i.e. it
 * represents a Gray code of a given length.
 *
 * For example the Gray code table of length \f$2^3\f$ is:
 *
 * \verbatim
 -------------------
 |  i  | ord | inc |
 -------------------
 |  0  |  0  |  0  |
 |  1  |  4  |  1  |
 |  2  |  6  |  0  |
 |  3  |  2  |  2  |
 |  4  |  3  |  0  |
 |  5  |  7  |  1  |
 |  6  |  5  |  0  |
 |  7  |  1  |  2  |
 -------------------
 * \endverbatim
 */

typedef struct {
	/**
	 * array of of Gray code entries
	 */
	int *ord;
	/**
	 * increment
	 */
	int *inc;
} code;

/**
 * Returns the i-th gray code entry for a gray code of length \f$2^l\f$.
 *
 * \param i The index in the Gray code table.
 * \param l Length of the Gray code.
 *
 * \return i-th Gray code entry.
 */

int gray_code(int i, int l);

/**
 * Fills var ord and var inc with Gray code data for a Gray code of
 * length \f$2^l\f$.
 *
 * \param ord Will hold gray code data, must be preallocated with correct size
 * \param inc Will hold some increment data, must be preallocated with correct size
 * \param l Logarithm of length of Gray code.
 *
 * \note Robert Miller had the idea for a non-recursive
 * implementation.
 */

code* build_code(int l);

/**
 * Frees memory from the global code book.
 *
 * This function is called automatically when the shared library is
 * unloaded.
 *
 * \warning Not thread safe!
 */

void destroy_code(code* codebook);

/**
 * floor(log_2(v))
 */

static inline int log2_floor(int v) {
	static unsigned const int b[] = { 0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000 };
	static unsigned const int S[] = { 1, 2, 4, 8, 16 };
	unsigned int r = 0;
	for (int i = 4; i >= 0; --i) {
		if ((v & b[i])) {
			v >>= S[i];
			r |= S[i];
		}
	}
	return r;
}

#endif /* GRAYCODE_H_ */
