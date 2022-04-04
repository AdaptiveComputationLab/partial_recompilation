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

#define int32_t intptr_t
#define uint32_t intptr_t

typedef char int8;
typedef short int16;
typedef int int32;

typedef int8 _BOOL1;
typedef int16 _BOOL2;
typedef int32 _BOOL4;

#if defined(__GNUC__)
#define __noreturn __attribute__((noreturn))
#else
#define __noreturn __declspec(noreturn)
#endif
