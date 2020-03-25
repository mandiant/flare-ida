/**
 * @file Replacements for stdlib and other functions
 *
 * Copyright (C) 2019 FireEye, Inc. All Rights Reserved.
 *
 * x86: cl /W3 /WX /Zi function_replacements.c /link /INCREMENTAL:NO
 * x64: cl /W3 /WX /Zi function_replacements.c /Fefunction_replacements_x64.exe
 *      /link /INCREMENTAL:NO
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define VERBOSE                     1

#define PDEBUG_ERROR(__fmt, ...)    fprintf(stderr, __fmt, __VA_ARGS__)
#if VERBOSE
#  define PDEBUG_INFO(__fmt, ...)   printf(__fmt, __VA_ARGS__)
#  define HEXDUMP(__s, __l)         hexdump(__s, __l)
#else
#  define PDEBUG_INFO(__fmt, ...)
#  define HEXDUMP(__s, __l)
#endif

#define MALLOC_BASE(__size) \
    void *ret = (void *)&arena[next]; \
    next = ((next + __size - 1) | 0xfff) + 1; \
    return ret

typedef enum test_status {
    test_success = 0,
    test_fail = 1,
} test_status_t;

#if VERBOSE
void hexdump(unsigned char *s, unsigned int l);
#endif

void * __cdecl my_memcpy(void *dst, void *src, size_t len);
void * __cdecl my_memset(void *dst, int fill, size_t len);
char * __cdecl my_strcpy(char *dst, const char *src);
size_t __cdecl my_strlen(const char *s);
void * __cdecl my_malloc(size_t size);
void * __stdcall my_HeapAlloc(void *hHeap, int dwFlags, size_t size);
void * __stdcall my_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
   );

void terminate_tests_if_next_malloc_outside_arena(size_t size);
test_status_t test_memcpy(void);
test_status_t test_memset(void);
test_status_t test_strcpy(void);
test_status_t test_strlen(void);
test_status_t test_allocators(void);

volatile size_t next = 0;
char arena[10 * 0x1000];

int
main(void)
{
    test_status_t status = test_success;
    status |= test_memcpy();
    status |= test_memset();
    status |= test_strcpy();
    status |= test_strlen();
    status |= test_allocators();
    return status;
}

void *
test_retn0_qword(void)
{
    return NULL;
}

#if VERBOSE
void
hexdump(unsigned char *s, unsigned int l) {
    while (l--) {
        printf("%02x ", *(s++));
    }
    printf("\n");
}
#endif /* VERBOSE */

/**
 * @func Test my_strlen against the following criteria:
 *  1. Measures correct length for zero-length string
 *  2. Measures correct length for unity-length string
 *  3. Measures correct length for string of length greater than one
 */
test_status_t
test_strlen()
{
    test_status_t status = test_fail;

    char *s_zerolength = "\x00unwanted\x00";
    char *s_unitylength = "a\x00unwanted\x00";
    char *s_lengthfour = "abcd\x00unwanted\x00";

    if (my_strlen(s_zerolength) != strlen(s_zerolength)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1)\n");
    } else if (my_strlen(s_unitylength) != strlen(s_unitylength)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2)\n");
    } else if (my_strlen(s_lengthfour) != strlen(s_lengthfour)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3)\n");
    } else {
        PDEBUG_INFO(__FUNCTION__ ": succeeded\n");
        status = test_success;
    }

    return status;
}

/**
 * @func Test my_strcpy against the following criteria:
 *  1. Copies as much as requested including null
 *  2. Copies no more than requested
 *  3. Returns dst
 */
test_status_t
test_strcpy()
{
    char *src = "123\0unwanted";
    char dst[13];
    char *ret = NULL;
    /* Test constraints/parameters on dst vs src - both including NULL */
    const size_t len_same = 4;
    const size_t len_total = 13;
    test_status_t status = test_fail;

    memset(dst, 0xff, sizeof(dst));

    ret = my_strcpy(dst, src);

    if (memcmp(src, dst, len_same)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1)\n");
    } else if (!memcmp(src, dst, len_same + 1)) {
        /* Not even a single byte should match after the null */
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2)\n");
    } else if ((void *)ret != (void *)&dst) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3)\n");
    } else {
        PDEBUG_INFO(__FUNCTION__ ": succeeded\n");
        status = test_success;
    }

    return status;
}

/**
 * @func Guard against subsequent malloc test overflowing static arena (in case
 * more tests are added without being conscious of the arena size).
 */
void
terminate_tests_if_next_malloc_outside_arena(size_t size)
{
    
    if (next > sizeof(arena)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1), terminating\n");
        exit(1);
    } else if ((size <= 0xfff) && ((next + 0xfff) > sizeof(arena))) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2), terminating\n");
        exit(1);
    } else if ((size > 0xfff) && ((next + size) > sizeof(arena))) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3), terminating\n");
        exit(1);
    }
}

/**
 * @func Test my_memcpy against the following criteria:
 *  1. Copies as much as requested including null
 *  2. Copies no more than requested
 *  3. Returns dst
 */
test_status_t
test_memcpy()
{
    char *src = "123\0wanted\0unwanted";
    char dst[13];
    char *ret = NULL;
    /* Test constraints/parameters on dst vs src - including selected NULLs */
    const size_t len_to_copy = 10;
    const size_t len_total = 20;
    test_status_t status = test_fail;

    memset(dst, 0xff, sizeof(dst));

    ret = my_memcpy(dst, src, len_to_copy);

    if (memcmp(src, dst, len_to_copy)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1)\n");
    } else if (!memcmp(src, dst, len_to_copy + 1)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2)\n");
    } else if ((void *)ret != (void *)&dst) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3)\n");
    } else {
        PDEBUG_INFO(__FUNCTION__ ": succeeded\n");
        status = test_success;
    }

    return status;
}

/**
 * @func Test my_memset against the following criteria:
 *  1. Fills as much as requested and truncates fill like the real memset
 *  2. Fills no more than requested
 *  3. Returns dst
 */
test_status_t
test_memset()
{
    char dst[20];
    char reference[20];
    int fill = 0x123456aa;
    char *ret = NULL;
    /* Test constraints/parameters on dst vs src - including selected NULLs */
    const size_t len_to_set = 10;
    const size_t len_total = 20;
    test_status_t status = test_fail;

    memset(dst, 0xff, sizeof(dst));
    memset(reference, 0xff, sizeof(reference));

    memset(reference, fill, len_to_set);
    ret = my_memset(dst, fill, len_to_set);

    if (memcmp(dst, reference, len_to_set)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1)\n");
    } else if (memcmp(dst, reference, len_total)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2)\n");
    } else if ((void *)ret != (void *)&dst) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3)\n");
    } else {
        PDEBUG_INFO(__FUNCTION__ ": succeeded\n");
        status = test_success;
    }

    return status;
}

/**
 * @func Test my_malloc and my_HeapAlloc together against the following
 * criteria:
 *  1. Return non-null pointers
 *  2. Return distinct pointers
 *  3. Return non-overlapping allocations
 *  (4. Can commingle use of both in the same program)
 */
test_status_t
test_allocators(void)
{
    unsigned char *test1 = NULL;
    unsigned char *test2 = NULL;
    unsigned char *test3 = NULL;
    const size_t alloc_size = 10;
    test_status_t status = test_fail;

    terminate_tests_if_next_malloc_outside_arena(alloc_size);
    test1 = my_malloc(alloc_size);
    if (test1 == NULL) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1a)\n");
    } else {
        memset(test1, 0xaa, alloc_size);
    }

    terminate_tests_if_next_malloc_outside_arena(alloc_size);
    test2 = my_HeapAlloc(NULL, 0, alloc_size);
    if (test2 == NULL) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1b)\n");
    } else {
        memset(test2, 0xbb, alloc_size);
    }

    terminate_tests_if_next_malloc_outside_arena(alloc_size);
    test3 = my_VirtualAlloc(
        0,
        alloc_size,
        MEM_RESERVE|MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
       );
    if (test3 == NULL) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 1c)\n");
    } else {
        memset(test3, 0xcc, alloc_size);
    }

    if (test1 == test2) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2a)\n");
    } else if (test2 == test3) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2b)\n");
    } else if (test1 == test3) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 2c)\n");
    } else if (test1 && test2 && !memcmp(test1, test2, alloc_size)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3a)\n");
    } else if (test2 && test3 && !memcmp(test2, test3, alloc_size)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3b)\n");
    } else if (test1 && test3 && !memcmp(test1, test3, alloc_size)) {
        PDEBUG_ERROR(__FUNCTION__ ": FAILED (criterion 3c)\n");
    } else {
        PDEBUG_INFO(__FUNCTION__ ": succeeded\n");
        status = test_success;
    }

    return status;
}

void *
__cdecl
my_memcpy(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (len--) { *(d++) = *(s++); }
    return dst;
}

void *
__cdecl
my_memset(void *dst, int fill, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    while (len--) { *(d++) = (unsigned char)fill; }
    return dst;
}

char *
__cdecl
my_strcpy(char *dst, const char *src)
{
    char *d = dst;
    while (*d++ = *src++);
    return dst;
}

size_t
__cdecl
my_strlen(const char *s)
{
    size_t ret = 0;
    while (*s++) {
        ++ret;
    }
    return ret;
}

void *
__cdecl
my_malloc(size_t size) { MALLOC_BASE(size); }

void *
__stdcall
my_HeapAlloc(void *hHeap, int dwFlags, size_t size) { MALLOC_BASE(size); }

void *
__stdcall
my_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
   )
{
    MALLOC_BASE(dwSize);
}
