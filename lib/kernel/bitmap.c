#include "bitmap.h"
#include <debug.h>
#include <limits.h>
#include <round.h>
#include <stdio.h>
#include "threads/malloc.h"
#ifdef FILESYS
#include "filesys/file.h"
#endif

/* Element type.

   This must be an unsigned integer type at least as wide as int.

   Each bit represents one bit in the bitmap.
   If bit 0 in an element represents bit K in the bitmap,
   then bit 1 in the element represents bit K+1 in the bitmap,
   and so on. */
typedef unsigned long elem_type;

/* Number of bits in an element. */
#define ELEM_BITS (sizeof (elem_type) * CHAR_BIT)

/* From the outside, a bitmap is an array of bits.  From the
   inside, it's an array of elem_type (defined above) that
   simulates an array of bits. */
struct bitmap {
	size_t bit_cnt;     /* Number of bits. */
	elem_type *bits;    /* Elements that represent bits. */
};

/* Returns the index of the element that contains the bit
   numbered BIT_IDX. */
static inline size_t
elem_idx (size_t bit_idx) {
	return bit_idx / ELEM_BITS;
}

/* Returns an elem_type where only the bit corresponding to
   BIT_IDX is turned on. */
static inline elem_type
bit_mask (size_t bit_idx) {
	return (elem_type) 1 << (bit_idx % ELEM_BITS);
}

/* Returns the number of elements required for BIT_CNT bits. */
static inline size_t
elem_cnt (size_t bit_cnt) {
	return DIV_ROUND_UP (bit_cnt, ELEM_BITS);
}

/* Returns the number of bytes required for BIT_CNT bits. */
static inline size_t
byte_cnt (size_t bit_cnt) {
	return sizeof (elem_type) * elem_cnt (bit_cnt);
}

/* Returns a bit mask in which the bits actually used in the last
   element of B's bits are set to 1 and the rest are set to 0. */
static inline elem_type
last_mask (const struct bitmap *b) {
	int last_bits = b->bit_cnt % ELEM_BITS;
	return last_bits ? ((elem_type) 1 << last_bits) - 1 : (elem_type) -1;
}

/* Creation and destruction. */

/* Initializes B to be a bitmap of BIT_CNT bits
   and sets all of its bits to false.
   Returns true if success, false if memory allocation
   failed. */
struct bitmap *
bitmap_create (size_t bit_cnt) {
	struct bitmap *b = malloc (sizeof *b);
	if (b != NULL) {
		b->bit_cnt = bit_cnt;
		b->bits = malloc (byte_cnt (bit_cnt));
		if (b->bits != NULL || bit_cnt == 0) {
			bitmap_set_all (b, false);
			return b;
		}
		free (b);
	}
	return NULL;
}

/* Creates and returns a bitmap with BIT_CNT bits in the
   BLOCK_SIZE bytes of storage preallocated at BLOCK.
   BLOCK_SIZE must be at least bitmap_needed_bytes(BIT_CNT). */
struct bitmap *
bitmap_create_in_buf (size_t bit_cnt, void *block, size_t block_size UNUSED) {
	struct bitmap *b = block;

	ASSERT (block_size >= bitmap_buf_size (bit_cnt));

	b->bit_cnt = bit_cnt;
	b->bits = (elem_type *) (b + 1);
	bitmap_set_all (b, false);
	return b;
}

/* Returns the number of bytes required to accomodate a bitmap
   with BIT_CNT bits (for use with bitmap_create_in_buf()). */
size_t
bitmap_buf_size (size_t bit_cnt) {
	return sizeof (struct bitmap) + byte_cnt (bit_cnt);
}

/* Destroys bitmap B, freeing its storage.
   Not for use on bitmaps created by
   bitmap_create_preallocated(). */
void
bitmap_destroy (struct bitmap *b) {
	if (b != NULL) {
		free (b->bits);
		free (b);
	}
}

/* Bitmap size. */

/* Returns the number of bits in B. */
size_t
bitmap_size (const struct bitmap *b) {
	return b->bit_cnt;
}

/* Setting and testing single bits. */

/* Atomically sets the bit numbered IDX in B to VALUE. */
void
bitmap_set (struct bitmap *b, size_t idx, bool value) {
	ASSERT (b != NULL);
	ASSERT (idx < b->bit_cnt);
	if (value)
		bitmap_mark (b, idx);
	else
		bitmap_reset (b, idx);
}

/* Atomically sets the bit numbered BIT_IDX in B to true. */
void
bitmap_mark (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* This is equivalent to `b->bits[idx] |= mask' except that it
	   is guaranteed to be atomic on a uniprocessor machine.  See
	   the description of the OR instruction in [IA32-v2b]. */
	asm ("lock orq %1, %0" : "=m" (b->bits[idx]) : "r" (mask) : "cc");
}

/* Atomically sets the bit numbered BIT_IDX in B to false. */
void
bitmap_reset (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* This is equivalent to `b->bits[idx] &= ~mask' except that it
	   is guaranteed to be atomic on a uniprocessor machine.  See
	   the description of the AND instruction in [IA32-v2a]. */
	asm ("lock andq %1, %0" : "=m" (b->bits[idx]) : "r" (~mask) : "cc");
}

/* Atomically toggles the bit numbered IDX in B;
   that is, if it is true, makes it false,
   and if it is false, makes it true. */
void
bitmap_flip (struct bitmap *b, size_t bit_idx) {
	size_t idx = elem_idx (bit_idx);
	elem_type mask = bit_mask (bit_idx);

	/* This is equivalent to `b->bits[idx] ^= mask' except that it
	   is guaranteed to be atomic on a uniprocessor machine.  See
	   the description of the XOR instruction in [IA32-v2b]. */
	asm ("lock xorq %1, %0" : "=m" (b->bits[idx]) : "r" (mask) : "cc");
}

/* Returns the value of the bit numbered IDX in B. */
bool
bitmap_test (const struct bitmap *b, size_t idx) {
	ASSERT (b != NULL);
	ASSERT (idx < b->bit_cnt);
	return (b->bits[elem_idx (idx)] & bit_mask (idx)) != 0;
}

/* Setting and testing multiple bits. */

/* Sets all bits in B to VALUE. */
void
bitmap_set_all (struct bitmap *b, bool value) {
	ASSERT (b != NULL);

	bitmap_set_multiple (b, 0, bitmap_size (b), value);
}

/* Sets the CNT bits starting at START in B to VALUE. */
void
bitmap_set_multiple (struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		bitmap_set (b, start + i, value);
}

/* Returns the number of bits in B between START and START + CNT,
   exclusive, that are set to VALUE. */
size_t
bitmap_count (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i, value_cnt;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	value_cnt = 0;
	for (i = 0; i < cnt; i++)
		if (bitmap_test (b, start + i) == value)
			value_cnt++;
	return value_cnt;
}

/* Returns true if any bits in B between START and START + CNT,
   exclusive, are set to VALUE, and false otherwise. */
/* START와 START + CNT 사이에 B의 비트가 하나라도 있으면 참을 반환합니다,
	 배타적인 비트가 VALUE로 설정되어 있으면 참을, 그렇지 않으면 거짓을 반환합니다.

	 bitmap_contains() 함수는 비트맵의 지정된 비트 범위에 특정 값이 포함되어 있는지 확인하는 데 사용됩니다.
*/

bool
bitmap_contains (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t i;

	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);
	ASSERT (start + cnt <= b->bit_cnt);

	for (i = 0; i < cnt; i++)
		if (bitmap_test(b, start + i) == value) // 루프 내에서 함수는 bitmap_test()를 호출하여 비트맵(b)의 현재 인덱스(start + i)에서 비트 값을 확인합니다. 결과는 등호 연산자(==)를 사용하여 원하는 값(value)과 비교됩니다.
			return true;													// 테스트된 비트가 원하는 값과 일치하여 범위에 지정된 값이 포함되어 있음을 나타내는 경우 함수는 'true'를 반환하여 비트맵에 값이 있음을 나타냅니다.
	return false;															// 범위에 지정된 값이 포함되어 있지 않음을 나타내는 일치 항목을 찾지 않고 루프가 완료되면 함수는 'false'를 반환합니다.
}

/* Returns true if any bits in B between START and START + CNT,
   exclusive, are set to true, and false otherwise.*/
bool
bitmap_any (const struct bitmap *b, size_t start, size_t cnt) {
	return bitmap_contains (b, start, cnt, true);
}

/* Returns true if no bits in B between START and START + CNT,
   exclusive, are set to true, and false otherwise.*/
bool
bitmap_none (const struct bitmap *b, size_t start, size_t cnt) {
	return !bitmap_contains (b, start, cnt, true);
}

/* Returns true if every bit in B between START and START + CNT,
   exclusive, is set to true, and false otherwise. */
bool
bitmap_all (const struct bitmap *b, size_t start, size_t cnt) {
	return !bitmap_contains (b, start, cnt, false);
}

/* Finding set or unset bits. */

/* Finds and returns the starting index of the first group of CNT
   consecutive bits in B at or after START that are all set to
   VALUE.
   If there is no such group, returns BITMAP_ERROR. */
size_t
bitmap_scan (const struct bitmap *b, size_t start, size_t cnt, bool value) {
	ASSERT (b != NULL);
	ASSERT (start <= b->bit_cnt);

	if (cnt <= b->bit_cnt) {
		size_t last = b->bit_cnt - cnt;
		size_t i;
		for (i = start; i <= last; i++)
			if (!bitmap_contains (b, i, cnt, !value))
				return i;
	}
	return BITMAP_ERROR;
}

/* Finds the first group of CNT consecutive bits in B at or after
   START that are all set to VALUE, flips them all to !VALUE,
   and returns the index of the first bit in the group.
   If there is no such group, returns BITMAP_ERROR.
   If CNT is zero, returns 0.
   Bits are set atomically, but testing bits is not atomic with
   setting them. */
/*
	bitmap_scan_and_flip() 함수는 비트맵에서 검색 작업을 수행하고 지정된 위치에서 시작하여 비트 범위를 뒤집습니다.
*/
size_t
bitmap_scan_and_flip (struct bitmap *b, size_t start, size_t cnt, bool value) {
	size_t idx = bitmap_scan(b, start, cnt, value); // 비트맵 b, 시작 위치 start, 카운트 cnt 및 원하는 값 value로 bitmap_scan()을 호출하여 시작합니다. 이 함수는 비트맵을 스캔하고 주어진 범위 내에서 '값'으로 지정된 조건과 일치하는 첫 번째 비트의 인덱스를 반환합니다. 결과는 idx 변수에 저장됩니다.
	if (idx != BITMAP_ERROR)												// idx가 BITMAP_ERROR와 같지 않은지 확인합니다. 'BITMAP_ERROR'는 일반적으로 오류 또는 일치하는 비트가 없음을 나타내는 특수 값(-1 또는 다른 고유 값)으로 정의됩니다.
		bitmap_set_multiple(b, idx, cnt, !value);			// 그런 다음 함수는 bitmap_set_multiple()을 호출하여 비트맵 b의 비트 범위를 뒤집습니다. 인덱스 idx에서 시작하는 cnt 비트를 value의 논리적 NOT(!) 값으로 설정합니다. 즉, 범위 내의 비트 상태를 뒤집습니다.
	return idx;
}

/* File input and output. */

#ifdef FILESYS
/* Returns the number of bytes needed to store B in a file. */
size_t
bitmap_file_size (const struct bitmap *b) {
	return byte_cnt (b->bit_cnt);
}

/* Reads B from FILE.  Returns true if successful, false
   otherwise. */
bool
bitmap_read (struct bitmap *b, struct file *file) {
	bool success = true;
	if (b->bit_cnt > 0) {
		off_t size = byte_cnt (b->bit_cnt);
		success = file_read_at (file, b->bits, size, 0) == size;
		b->bits[elem_cnt (b->bit_cnt) - 1] &= last_mask (b);
	}
	return success;
}

/* Writes B to FILE.  Return true if successful, false
   otherwise. */
bool
bitmap_write (const struct bitmap *b, struct file *file) {
	off_t size = byte_cnt (b->bit_cnt);
	return file_write_at (file, b->bits, size, 0) == size;
}
#endif /* FILESYS */

/* Debugging. */

/* Dumps the contents of B to the console as hexadecimal. */
void
bitmap_dump (const struct bitmap *b) {
	hex_dump (0, b->bits, byte_cnt (b->bit_cnt), false);
}

