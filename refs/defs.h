// reference https://github.com/nihilus/hexrays_tools/blob/master/code/defs.h

#define HIDWORD(x) (*((unsigned int*)&(x)+1))
#define LODWORD(x) (*((unsigned int*)&(x)))
#define HIWORD(x) (*((unsigned short*)&(x)+1))
#define LOWORD(x) (*((unsigned short*)&(x)))
#define COERCE_UNSIGNED_INT64(x) (*((unsigned long*)(&x)))
#define HIBYTE(x) (*((unsigned char*)&(x)+1))
#define LOBYTE(x) (*((unsigned char*)&(x)))


#define _BoolDef (bool)
#define _TBYTE (long double)
#define _BYTE (uint8_t)
#define _WORD (uint16_t)
#define _DWORD (uint32_t)
#define _QWORD (uint64_t)
// from IDADOC support: _OWORD is an unknown type; the only known info is its size: 16 bytes
#define _OWORD (unsigned long long)

#define __short short

typedef char int8;
typedef short int16;
typedef int int32;

typedef int8 _BOOL1;
typedef int16 _BOOL2;
typedef int32 _BOOL4;

#if defined(__GNUC__)
#define __noreturn __attribute__((noreturn))
#define __cdecl  __attribute__((__cdecl__))
#define __stdcall  __attribute__((__stdcall__))
#else
#define __noreturn __declspec(noreturn)
#define __cdecl 
#define __stdcall
#endif


// workaround for dietlibc inclusion issue with including wchar.h
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

#define int32_t intptr_t
#define uint32_t intptr_t


#if defined(__WINT_TYPE__)
typedef __WINT_TYPE__ wint_t;
#else
typedef unsigned int wint_t;
#endif

typedef struct {
  int count;
  wchar_t sofar;
} mbstate_t;



//typedef FILE _IO_FILE;
// typedef long long int __int64;
#define _IO_FILE FILE
#define __int64 long long int
#define __int32 int
#define __int16 short int
#define __int8  char


#define __DEFAULT_FN_ATTRS __attribute__((__always_inline__, __nodebug__))


/*----------------------------------------------------------------------------*\
|* readfs, readgs
|* (Pointers in address space #256 and #257 are relative to the GS and FS
|* segment registers, respectively.)
\*----------------------------------------------------------------------------*/
static __inline__ __attribute__((always_inline)) unsigned char __readfsbyte(const unsigned long Offset)
{
	unsigned char value;
	__asm__("movb %%fs:%a[Offset], %b[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}
 
static __inline__ __attribute__((always_inline)) unsigned short __readfsword(const unsigned long Offset)
{
	unsigned short value;
	__asm__("movw %%fs:%a[Offset], %w[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}
 
static __inline__ __attribute__((always_inline)) unsigned long __readfsdword(const unsigned long Offset)
{
	unsigned long value;
	__asm__("movl %%fs:%a[Offset], %k[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}

static __inline__  __attribute__((__always_inline__)) unsigned long long int __readfsqword(unsigned long Offset) 
{
	unsigned long long int value;
	__asm__ ("mov %%fs:(%1), %0" : "=r" (value) : "r" (Offset));
	return value;
}

static __inline__ __attribute__((always_inline)) unsigned char __readgsbyte(const unsigned long Offset)
{
	unsigned char value;
	__asm__("movb %%gs:%a[Offset], %b[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}
 
static __inline__ __attribute__((always_inline)) unsigned short __readgsword(const unsigned long Offset)
{
	unsigned short value;
	__asm__("movw %%gs:%a[Offset], %w[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}
 
static __inline__ __attribute__((always_inline)) unsigned long __readgsdword(const unsigned long Offset)
{
	unsigned long value;
	__asm__("movl %%gs:%a[Offset], %k[value]" : [value] "=q" (value) : [Offset] "irm" (Offset));
	return value;
}

static __inline__  __attribute__((__always_inline__)) unsigned long long int __readgsqword(unsigned long Offset) 
{
	unsigned long long int value;
	__asm__ ("mov %%gs:(%1), %0" : "=r" (value) : "r" (Offset));
	return value;
}

