/*
 * Copyright (C) 2015,2016 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
 * Implements some easy to use compiler macros
 */

#ifndef __COMPILER_H_
#define __COMPILER_H_

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * This attribute places the function in section named .l1.text
 * which can be optionally located in L1 instruction SRAM.
 */
#define __L1_TEXT		(__attribute__ ((l1_text)))

/**
 * This attribute specifies that some function parameters should be
 * non-null pointers.
 */
#define __NONNULL(arg, ...)	(__attribute__ ((nonnull(arg))))

/**
 * This attribute informs the compiler that a function is a hot
 * spot in the compiled program and needs to be optimized more aggressively
 * and can be placed into special subsection of the text section so as to
 * place all hot functions closely to improve locality of reference.
 */
#define __HOT		(__attribute__ ((hot)))

/**
 * This attribute informs the compiler that function is not likely be executed.
 * The function is optimized for size rather than for speed and may be placed
 * into special subsection of the text section so as to place all cold
 * functions closely improving code locality of non-cold parts of program.
 * The paths leading to call of cold functions are marked as unlikely by the
 * by the branch prediction mechanism.
 */
#define __COLD		(__attribute__ ((cold)))

/**
 * This function attribute prevents a function from being considered for
 * inlining.
 */
#define __NOINLINE      (__attribute__ ((noinline)))

/**
 * A "pure" function is one that has no effects except its return value is a
 * function of only the function's parameters or non-volatile
 * global variables. Any parameter or global variable access must be read-only.
 * Loop optimization and subexpression elimination can be applied to such
 * functions. A common example is strlen(): Given identical inputs, the
 * function's return value (its only effect) is invariant across multiple
 * invocations and thus can be pulled out of a loop and called but once.
 */
#define __PURE		(__attribute__ ((pure)))
/**
 * A "const" function is a stricter variant of a pure function: Such functions
 * cannot access global variables and no parameters may be pointers. Thus their
 * return value is a function of nothing but their passed-by-value parameters.
 * Additional optimizations are possible for such functions. Math functions,
 * such as abs(), are examples of const functions (presuming they don't save
 * state or otherwise pull tricks in the name of optimization). It makes no
 * sense for a const or pure function to return void.
 */
#define __CONST		(__attribute__ ((const)))
/**
 * If a function never returns (perhaps because it calls exit()), it can be
 * marked as such and GCC can optimize the call site without regard to the
 * potentiality of the function actually returning. It makes no sense for such a
 * function to have a return value other than void.
 */
#define __NORETURN	(__attribute__ ((noreturn)))
/**
 * If a function returns pointers that can never alias any other data (almost
 * assuredly because it just allocated memory), the function can be marked as
 * such and GCC can improve optimizations.
 */
#define __MALLOC	(__attribute__ ((malloc)))
/**
 * This attribute instructs GCC to generate a warning whenever the return value
 * from the function is not stored or used in an expression during invocation.
 * This allows functions whose return value is crucial to ensure that the value
 * is always used.
 */
#define __MUST_USE	(__attribute__ ((warn_unused_result)))
#ifndef __cplusplus
/**
 * This attribute instructs GCC to generate a warning whenever the return value
 * from the function is not stored or used in an expression during invocation.
 * This allows functions whose return value is crucial to ensure that the value
 * is always used.
 */
#define __DEPRECATED	(__attribute__ ((deprecated)))
#endif
/**
 * This attribute tells GCC that, despite apparent reality, a function really is
 * used and to always output the assembly for the function. This is useful if
 * the function is only invoked from assembly and GCC is unaware. It also
 * disables warnings due to lack of use.
 */
#define __USED		(__attribute__ ((used)))
/**
 * This attribute tells GCC that the programmer is aware that a given parameter
 * is unused and not to emit warnings to that end. This is useful if compiling
 * with -W or -Wunused but forced to have unused parameters, as is common in
 * event-driven GUI programming.
 */
#define __UNUSED	(__attribute__ ((unused)))
/**
 * This attribute tells GCC that a type or variable should be packed into
 * memory, using the minimum amount of space possible, potentially disregarding
 * alignment requirements. If specified on a struct or union, all variables
 * therein are so packed. If specified on just a specific variable, only that
 * type is packed. As an example, a structure with a char followed by an int
 * would most likely find the integer aligned to a memory address not
 * immediately following the char (say, three bytes later). The compiler does
 * this by inserting three bytes of unused packing between the two variables. A
 * packed structure lacks this packing, potentially consuming less memory but
 * failing to meet architecture alignment requirements.
 */
#define __PACKED	(__attribute__ ((packed)))
/**
 * The opposite of packed - this forces the specified alignment on the variable,
 * member of a struct, or whole struct, depending on its context.
 */
#define __ALIGNED(x)	_(_attribute__ ((aligned(x))))

#define __ASM		(__asm__ __volatile__)

#define __EXTENSION	__extension__

#ifdef __cplusplus
	}
#endif
#endif				/* __COMPILER_H_ */
