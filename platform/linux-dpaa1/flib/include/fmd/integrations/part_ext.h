/*
 * Copyright 2008-2012 Freescale Semiconductor, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Freescale Semiconductor nor the
 *        names of its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * This software is provided by Freescale Semiconductor "as is" and any
 * express or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose are
 * disclaimed. In no event shall Freescale Semiconductor be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential damages
 * (including, but not limited to, procurement of substitute goods or services;
 * loss of use, data, or profits; or business interruption) however caused and
 * on any theory of liability, whether in contract, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 */

/**************************************************************************//**
 @File          part_ext.h

 @Description   Definitions for the part (integration) module.
*//***************************************************************************/

#ifndef __PART_EXT_H
#define __PART_EXT_H

#include "std_ext.h"
#include "part_integration_ext.h"



/**************************************************************************//*
 @Description   Part data structure - must be contained in any integration
                data structure.
*//***************************************************************************/
typedef struct t_Part
{
    uintptr_t   (* f_GetModuleBase)(t_Handle h_Part, e_ModuleId moduleId);
                /**< Returns the address of the module's memory map base. */
    e_ModuleId  (* f_GetModuleIdByBase)(t_Handle h_Part, uintptr_t baseAddress);
                /**< Returns the module's ID according to its memory map base. */
} t_Part;

#ifdef P1023
#include "part_P1023.h"
#elif defined FMAN_V3H
#include "part_B4_T4.h"
#elif defined FMAN_V3L
#include "part_FMAN_V3L.h"
#else
#include "part_P3_P4_P5.h"
#endif

#endif /* __PART_EXT_H */
