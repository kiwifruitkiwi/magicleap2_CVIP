/****************************************************************************\
*
*  Copyright (c) 2019 Advanced Micro Devices, Inc. (unpublished)
*
*  All rights reserved.  This notice is intended as a precaution against
*  inadvertent publication and does not imply publication or any waiver
*  of confidentiality.  The year included in the foregoing notice is the
*  year of creation of the work.
*  LOG OF CHANGES
*
*  Contains code specific to asics that use the interrupt vector (IV) ring
*  buffer.
*
\****************************************************************************/

#ifndef __IRQSRCS_SDMA2_5_0_H__
#define __IRQSRCS_SDMA2_5_0_H__


#define SDMA2_5_0__SRCID__SDMA_ATOMIC_RTN_DONE				217		// 0xD9 SDMA atomic*_rtn ops complete
#define SDMA2_5_0__SRCID__SDMA_ATOMIC_TIMEOUT				218		// 0xDA SDMA atomic CMPSWAP loop timeout
#define SDMA2_5_0__SRCID__SDMA_IB_PREEMPT					219		// 0xDB sdma mid-command buffer preempt interrupt
#define SDMA2_5_0__SRCID__SDMA_ECC					        220		// 0xDC ECC  Error
#define SDMA2_5_0__SRCID__SDMA_PAGE_FAULT					221		// 0xDD Page Fault Error from UTCL2 when nack=3
#define SDMA2_5_0__SRCID__SDMA_PAGE_NULL					222		// 0xDE Page Null from UTCL2 when nack=2
#define SDMA2_5_0__SRCID__SDMA_XNACK					    223		// 0xDF Page retry  timeout after UTCL2 return nack=1
#define SDMA2_5_0__SRCID__SDMA_TRAP					        224		// 0xE0 Trap
#define SDMA2_5_0__SRCID__SDMA_SEM_INCOMPLETE_TIMEOUT		225		// 0xE1 0xDAGPF (Sem incomplete timeout)
#define SDMA2_5_0__SRCID__SDMA_SEM_WAIT_FAIL_TIMEOUT		226		// 0xE2 Semaphore wait fail timeout
#define SDMA2_5_0__SRCID__SDMA_SRAM_ECC					    228		// 0xE4 SRAM ECC Error
#define SDMA2_5_0__SRCID__SDMA_PREEMPT					    240		// 0xF0 SDMA New Run List
#define SDMA2_5_0__SRCID__SDMA_VM_HOLE					    242		// 0xF2 MC or SEM address in VM hole
#define SDMA2_5_0__SRCID__SDMA_CTXEMPTY					    243		// 0xF3 Context Empty
#define SDMA2_5_0__SRCID__SDMA_DOORBELL_INVALID				244		// 0xF4 Doorbell BE invalid
#define SDMA2_5_0__SRCID__SDMA_FROZEN					    245		// 0xF5 SDMA Frozen
#define SDMA2_5_0__SRCID__SDMA_POLL_TIMEOUT					246		// 0xF6 SRBM read poll timeout
#define SDMA2_5_0__SRCID__SDMA_SRBMWRITE					247		// 0xF7 SRBM write Protection

#endif // __IRQSRCS_SDMA2_5_0_H__