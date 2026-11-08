#ifndef CIPHERFIX_INTERFACE_H
#define CIPHERFIX_INTERFACE_H

#include <stdint.h>

void classify(void *ptr, int length);
void declassify(void *ptr, int length);

#endif
