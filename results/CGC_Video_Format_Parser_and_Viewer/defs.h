// reference https://github.com/nihilus/hexrays_tools/blob/master/code/defs.h

#define HIDWORD(x) (*((unsigned int*)&(x)+1))
#define LODWORD(x) (*((unsigned int*)&(x)))
#define HIWORD(x) (*((unsigned short*)&(x)+1))
#define LOWORD(x) (*((unsigned short*)&(x)))
#define COERCE_UNSIGNED_INT64(x) (*((unsigned long*)(&x)))