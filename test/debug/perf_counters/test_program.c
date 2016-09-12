/* Copyright (c) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdio.h>
#include <stdint.h>
#include "counters.h"

int main()
{
  uint32_t read1=0, read2=0;
  uint64_t cyc_read1=0, cyc_read2=0;
  int i,x=0;
  /*selecting PM_COUNTER_1 to count "INST_EXEC" event*/
  arm_connect_counter_to_event(PM_COUNTER_1, INST_EXEC);

  /*enable PM_COUNTER_1  counter*/
  arm_enable_counter(PM_COUNTER_1);

  /*Enable the 64bit cycle counter*/
  arm_enable_cycle_counter();

  /*Get an initial reading of PM_COUNTER_1*/
  read1 = arm_read_counter(PM_COUNTER_1);

  /*Get an initial reading of 64 bit cycle counter*/
  cyc_read1 = arm_read_cycle_counter();

  for(i=0;i<1000;i++)
    x++;

  /*Get an final reading of 64 bit cycle counter*/
  cyc_read2 = arm_read_cycle_counter();

  /*Get an final reading of PM_COUNTER_1*/
  read2 = arm_read_counter(PM_COUNTER_1);

  /*disable counters*/
  arm_disable_counter(PM_COUNTER_1);
  arm_disable_cycle_counter();

  printf("x = %d, INST = %lu, CYC = %llu\n", x, read2-read1, cyc_read2-cyc_read1);
  return 0;
}
