#include "../include/bytestream.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

void bs_init(bytestream_t bs) {
	bs[0] = malloc(sizeof(bytestream_t));
	bs[0]->_len = 0;
	bs[0]->_avail = _BS_INIT;
	assert((bs[0]->_data = malloc(sizeof(byte_t) * bs[0]->_avail)));
}

void bs_init_size(bytestream_t bs, size_t size) {
	bs[0] = malloc(sizeof(bytestream_t));
	bs[0]->_len = 0;
	bs[0]->_avail = size;
	assert((bs[0]->_data = calloc(size, sizeof(byte_t))));
}

void bs_set(bytestream_t bs, bytestream_t const op1) {
	if (bs[0]->_avail < op1[0]->_len)
		_bs_update(bs, op1[0]->_len);
	memcpy(bs[0]->_data, op1[0]->_data, op1[0]->_len);
	bs[0]->_len = op1[0]->_len;
}

void bs_set_b(bytestream_t bs, void *bytes, size_t len) {
	if (bs[0]->_avail < len)
		_bs_update(bs, len);
	memcpy(bs[0]->_data, bytes, len);
	bs[0]->_len = len;
}

void bs_concat(bytestream_t bs, bytestream_t const op1, bytestream_t const op2) {
	size_t catlen = op1[0]->_len + op2[0]->_len, op1len = op1[0]->_len;
	if (catlen > bs[0]->_avail)
		_bs_update(bs, catlen);

	if (bs[0] == op1[0] || bs[0] == op2[0]) {
		if (bs[0] == op1[0])
			memcpy(bs[0]->_data + op1len, op2[0]->_data, catlen - op1len);
		if (bs[0] == op2[0]) {
			memmove(bs[0]->_data + op1len, op2[0]->_data, catlen - op1len);
			memcpy(bs[0]->_data, op1[0]->_data, op1len);
		}
	} else {
		memcpy(bs[0]->_data, op1[0]->_data, op1len);
		memcpy(bs[0]->_data + op1len, op2[0]->_data, catlen - op1len);
	}

	bs[0]->_len = catlen;
}

void bs_concat_b(bytestream_t bs, bytestream_t const op1, byte_t op2) {
	size_t op1len = bs_len(op1);
	if (bs[0]->_avail < op1len + 1)
		_bs_update(bs, op1len + 1);
	
	if (bs[0] != op1[0])
		memcpy(bs[0]->_data, op1[0]->_data, op1len);
	bs[0]->_data[op1len] = op2;
	bs[0]->_len = op1len + 1;
}

void bs_concat_zero(bytestream_t bs, bytestream_t const op1, size_t len) {
	size_t op1len = op1[0]->_len;
	if (bs[0]->_avail < op1len + len)
		_bs_update(bs, op1len + len);
	
	if (bs[0] != op1[0])
		memcpy(bs[0]->_data, op1[0]->_data, op1len);

	memset(bs[0]->_data + op1len, 0, len);
	bs[0]->_len = op1len + len;
}

void bs_trim(bytestream_t bs, bytestream_t const op1, int len) {
	void *(*move)(void *, const void *, size_t) =
		bs[0]->_data == op1[0]->_data ? memmove : memcpy;

	int reverse = len < 0;
	len = abs(len);
	if (len > bs_len(op1)) {
		len = bs_len(op1);
	}

	size_t new_len = 0;
	new_len += bs_len(op1) - len;

	if (reverse) {
		move(bs[0]->_data, op1[0]->_data + len, new_len);
	} else {
		move(bs[0]->_data, op1[0]->_data, new_len);
	}

	bs[0]->_len = new_len;
}

void _bs_update(bytestream_t bs, size_t size) {
	if (size == 0)
		bs[0]->_avail *= _BS_UPDT_MUL;
	else
		bs[0]->_avail = size;
	byte_t *new = malloc(sizeof(byte_t) * bs[0]->_avail);
	assert(new);
	memcpy(new, bs[0]->_data, bs[0]->_len);
	free(bs[0]->_data);
	bs[0]->_data = new;
}

void bs_clear(bytestream_t bs) {
	free(bs[0]->_data);
	free(bs[0]);
	bs[0] = NULL;
}

void bs_save(void *dest, bytestream_t const src, size_t size, int start, int endianess) {
	start = start < 0 ? start % bs_len(src) : start;
	int end = start + size;
	size = end > bs_len(src) ? bs_len(src) : size; 

	/* Big endian */
	if (endianess > 0)
		memcpy(dest, src[0]->_data + start, size);
	/* Little endian */
	else {
		for (int i = 0; i < size; i++) {
			memcpy(((byte_t *) dest) + i, src[0]->_data + start + size - i - 1, 1);
		}
	}
}

void bs_load(bytestream_t dest, void * const src, size_t size, int start, int endianess) {
	if (dest[0]->_avail < size)
		_bs_update(dest, size);

	/* Big endian */
	if (endianess > 0)
		memcpy(dest[0]->_data, ((byte_t *) src) + start, size);
	/* Little endian */
	else {
		for (int i = 0; i < size; i++) {
			memcpy(dest[0]->_data + i, ((byte_t *) src) + size - i - 1, 1);
		}
	}
}

void mpz_set_bs(mpz_t rot, bytestream_t const op) {
	mpz_import(rot, bs_len(op), 1, 1, 1, 0, op[0]->_data);
}

void bs_set_mpz(bytestream_t bs, mpz_t const op) {
	void *data;
	size_t op_len;
	/* Export msg byte data and set data to point to it */
	data = mpz_export(NULL, &op_len, 1, 1, 1, 0, op);
	bs_set_b(bs, data, op_len);
}
