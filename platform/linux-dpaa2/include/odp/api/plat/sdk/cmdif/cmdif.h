/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

#ifndef __CMDIF_H
#define __CMDIF_H

#include <errno.h>
#include <odp/api/std_types.h>
#include <string.h>
#include <stdlib.h>
#include <odp/api/byteorder.h>
#include <fsl_cmdif_flib_fd.h>

#define CPU_TO_SRV16(val) odpfsl_bswap16(val)
#define CPU_TO_SRV32(val) odpfsl_bswap32(val)
#define CPU_TO_BE64(val)  odpfsl_bswap64(val)
#define CPU_TO_BE16(val)  odpfsl_bswap16(val)

#define CMDIF_EPID         0
/*!< EPID to be used for setting by client */

#ifdef DPAA2_DEBUG
#ifndef DEBUG
#define DEBUG
#endif
#endif /* DPAA2_DEBUG */

#ifndef __HOT_CODE
#define __HOT_CODE
#endif

#ifndef __COLD_CODE
#define __COLD_CODE
#endif /* COLD_CODE*/

#ifndef CPU_TO_LE64
#define CPU_TO_LE64(val) (val)
#endif
#ifndef CPU_TO_LE32
#define CPU_TO_LE32(val) (val)
#endif

#define SHBP_BUF_TO_PTR(BUF) ((uint64_t *)(BUF))
#define SHBP_PTR_TO_BUF(BUF) ((uint64_t)(BUF))

int send_fd(struct cmdif_fd *cfd, int pr, void *dpaa2_dev);
int receive_fd(struct cmdif_fd *cfd, int pr, void *dpaa2_dev);

#endif /* __CMDIF_H */
