/*
Utility functions for analysis with Cipherfix.
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Marks data at the given address and with the given length as secret.
void __attribute__((noinline, optimize("O0"))) classify(void *ptr, int length) { asm (""); }

// Marks data at the given address and with the given length as public.
void __attribute__((noinline, optimize("O0"))) declassify(void *ptr, int length) { asm (""); }
