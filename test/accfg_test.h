#ifndef _DSA_TEST_H_
#define _DSA_TEST_H_

static inline void movdir64b(volatile void *portal, void *desc)
{
	asm volatile("sfence\t\n"
			".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"  :
			: "a" (portal), "d" (desc));
}

static inline unsigned char enqcmd(volatile void *portal, void *desc)
{
	unsigned char retry;
	asm volatile("sfence\t\n"
			".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry): "a" (portal), "d" (desc));
	return retry;
}
#endif
