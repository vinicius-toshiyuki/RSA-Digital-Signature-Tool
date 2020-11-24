#ifndef __BYTESTREAM_H__
#define __BYTESTREAM_H__

#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>

/*******************************************************************
 * 	Implementation of a variable length bytestream object and some *
 * 	functions to work with them                                    *
 *                                                                 *
 * 	All functions expect by-reference bytestreams.                 *
 * 	The leftmost argument in a function is used as the destination *
 * 	for the results, if any. Other arguments are used as operands. *
 * 	A bytestream can be both a function destination and operand at *
 * 	the same time.                                                 *
 *******************************************************************/

/**
 * 	Bytestream Constants
 *
 * 	_BS_INIT: Default initial size for bytestreams
 * 	_BS_UPDT_MUL: Growth rate for bytestreams
 */
#define _BS_INIT 64
#define _BS_UPDT_MUL 2

/* Byte type */
typedef uint8_t byte_t;

/**
 * 	Bytestream object
 *
 * 	Used in function arguments as by-reference value
 */
typedef struct _bytestream_t {
	byte_t *_data; /* Array of bytes of size `_avail` */
	size_t _len; /* Number of occupied bytes in `_data` */
	size_t _avail; /* Max size the bytestream can hold */
} * bytestream_t[1];

/**
 * 	Initialize a bytestream with default size
 * 	One bytestream should not be initialized more than once
 * 	All non-initialization funtions expect a bytestream to be initialized
 *
 * 	@param bs A bytestream
 */
void bs_init(bytestream_t bs);

/**
 * 	Initialize a bytestream with specified size
 * 	One bytestream should not be initialized more than once
 * 	All non-initialization funtions expect a bytestream to be initialized
 *
 * 	@param bs A bytestream
 * 	@param size Size to initialize the bytestream
 */
void bs_init_size(bytestream_t bs, size_t size);

/**
 * 	Set a bytestream with bytes from another bytestream
 *
 * 	@param bs Bytestream to have bytes copied into
 * 	@param op1 Bytestream to copy bytes from
 */
void bs_set(bytestream_t bs, bytestream_t const op1);

/**
 * 	Set a bytestream with bytes from a generic object
 * 	The source object must have enough bytes to copy
 *
 * 	@param bs Bytestream to have bytes copied into
 * 	@param bytes Object to copy bytes from
 * 	@param len Number of bytes to copy
 */
void bs_set_b(bytestream_t bs, void * const bytes, size_t len);

/**
 * 	Concatenate two bytestreams
 *
 * 	@param bs Bytestream to hold concatenated bytestreams
 * 	@param op1 First bytestream
 * 	@param op2 Second bytestream
 */
void bs_concat(bytestream_t bs, bytestream_t const op1, bytestream_t const op2);

/**
 * 	Concatenate a byte to a bytestream
 *
 * 	@param bs Bytestream to hold concatenated bytestream
 * 	@param op1 A Bytestream
 * 	@param op2 A Byte
 */
void bs_concat_b(bytestream_t bs, bytestream_t const op1, byte_t op2);

/**
 * 	Concatenate a number of zeros to a bytestream
 *
 * 	@param bs Bytestream to hold concatenated bytestream
 * 	@param op1 A Bytestream
 * 	@param len Number of zero-bytes to concatenate
 */
void bs_concat_zero(bytestream_t bs, bytestream_t const op1, size_t len);

/**
 * 	Trim a bytestream
 *
 * 	@param bs Bytestream to hold trimmed bytestream
 * 	@param op1 Bytestream to be trimmed
 * 	@param len Number of bytes to be trimmed. If `len` is negative, bytes
 * 	are trimmed from the begining of the stream, otherwise, from the end
 */
void bs_trim(bytestream_t bs, bytestream_t const op1, int len);

/**
 * 	Clear memory used by a bytestream
 * 	Should be called when a bytestream will no longer be used
 *
 * 	@param bs A bytestream
 */
void bs_clear(bytestream_t bs);

/**
 * 	Update a bytestream size
 * 	Internal function. A bytestream has it's space update automatically
 * 	when needed.
 *
 * 	@param bs A bytestream
 * 	@param size New size
 */
void _bs_update(bytestream_t bs, size_t size);

/**
 * 	Save bytestream bytes in a destination
 *
 * 	@param dest Pointer to destination
 * 	@param src Source bytestream
 * 	@param size Number of bytes to copy. Copies at most the number of bytes
 * 	in the source
 * 	@param start Index in source to start copying
 * 	@param endianess Endianess of the bytestream. `endianess` > 0 is 'big endian'
 * 	and 'little endian' otherwise
 */
void bs_save(void *dest, bytestream_t const src, size_t size, int start, int endianess);

/**
 * 	Load bytes into a bytestream from a source object
 *
 * 	@param dest Destination bytestream
 * 	@param src Source object
 * 	@param size Number of bytes to copy. `src` must have at least `size` bytes
 * 	@param start Index in source to start copying
 * 	@param endianess Endianess of the bytestream. `endianess` > 0 is 'big endian'
 * 	and 'little endian' otherwise
 */
void bs_load(bytestream_t dest, void * const src, size_t size, int start, int endianess);

/**
 *  Set a GMP integer from the bytes of a bytestream
 *
 *  @param rot Target GMP integer
 *  @param op Source bytestream
 */
void mpz_set_bs(mpz_t rot, bytestream_t const op);

/**
 * 	Set a bytestream from the bytes of a GMP integer
 *
 * 	@param bs Target bytestream
 * 	@param op Source GMP integer
 */
void bs_set_mpz(bytestream_t bs, mpz_t const op);

/**
 * 	Get length of a bytestream in bytes
 *
 * 	@param bs A bytestream
 */
#define bs_len(bs) (bs[0]->_len)

/**
 * 	Print a bytestream as a hexadecimal string with a new line
 *
 * 	@param bs A bytestream
 */
#define bs_print(bs) { \
	for (int i = 0; i < bs_len(bs); i++) \
		printf("%02x", bs[0]->_data[i]); \
	printf("\n"); \
} NULL

/* Word type */
typedef uint64_t word_t;

#endif
