/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

/* Output trace file pointer */
static FILE *fp;

/* Constructor and Destructor Prototypes */
void main_constructor(void)
__attribute__((no_instrument_function, constructor));
void main_destructor(void)
__attribute__((no_instrument_function, destructor));
void __cyg_profile_func_enter(void *func_address, void *call_site)
__attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *func_address, void *call_site)
__attribute__((no_instrument_function));

void main_deconstructor(void)
__attribute__((no_instrument_function, constructor));
void main_destructor(void)
__attribute__((no_instrument_function, destructor));

void main_constructor(void)
{
	fp = fopen("trace.txt", "w");
	if (fp == NULL)
		exit(-1);
}

void main_deconstructor(void)
{
	fclose(fp);
}

void __cyg_profile_func_enter(void *this, void *callsite)
{
	/* Function Entry Address */
	if (fp != NULL)
		fprintf(fp, "E %p %p %lu\n", (int *)this, callsite, time(NULL));
}

void __cyg_profile_func_exit(void *this, void *callsite)
{
	/* Function Exit Address */
	if (fp != NULL)
		fprintf(fp, "X %p %p %lu\n", (int *)this, callsite, time(NULL));
}
