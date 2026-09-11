/*
 * os_log from an injected kext.
 *
 * Needs KADDR__os_log_internal, KADDR_os_log_dso and KADDR_os_log_default in
 * the generated kaddrs.h; those come from the config's `symbols` map.
 *
 * CAUTION: os_log substitutes "<ptr>" for any argument whose value looks like
 * a kernel pointer, so a successful print of an address reads as a failure.
 * Report addresses with KLOG_ADDR_FMT / KLOG_ADDR.
 */
#ifndef KLOG_H
#define KLOG_H

#include "kpayload.h"
#include "kaddrs.h"

#define KLOG_TYPE_DEFAULT 0x00
#define KLOG_TYPE_INFO    0x01
#define KLOG_TYPE_DEBUG   0x02
#define KLOG_TYPE_ERROR   0x10
#define KLOG_TYPE_FAULT   0x11

#define klog(type, fmt, ...)                                                  \
	KP_CALL(void, KADDR__os_log_internal, void *, void *, uint32_t,       \
	    const char *, ...)(kp_addr(KADDR_os_log_dso),                     \
	    kp_addr(KADDR_os_log_default), (type), (fmt), ##__VA_ARGS__)

#define klog_err(fmt, ...)  klog(KLOG_TYPE_ERROR, fmt, ##__VA_ARGS__)
#define klog_info(fmt, ...) klog(KLOG_TYPE_DEFAULT, fmt, ##__VA_ARGS__)

/* Split an address so os_log will not redact it. */
#define KLOG_HI(v) ((uint32_t)((uint64_t)(v) >> 32))
#define KLOG_LO(v) ((uint32_t)((uint64_t)(v)))
#define KLOG_ADDR_FMT "%08x%08x"
#define KLOG_ADDR(v)  KLOG_HI(v), KLOG_LO(v)

#endif /* KLOG_H */
