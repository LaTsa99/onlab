#ifndef VAPA_H
#define VAPA_H

#define INFO_PGD 0x01
#define INFO_P4D 0x02
#define INFO_PUD 0x04
#define INFO_PMD 0x08
#define INFO_PTE 0x10

struct translate_mem{
	unsigned long virtual;
	unsigned short flags;
};

#endif