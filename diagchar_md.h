/* SPDX-License-Identifier: Apache-2.0 */
#ifndef DIAGCHAR_MD_H
#define DIAGCHAR_MD_H
#include <stdint.h>
#include <sys/ioctl.h>

/* MSM diagchar UAPI (drivers/char/diag/diagchar.h). Stable across MSM/SDX.
 * VERIFY on-device in Task B1 (debugfs status must flip to MD mode). */
#define DIAG_IOCTL_SWITCH_LOGGING   7

/* Logging modes for the struct-based SWITCH_LOGGING (req_mode field). */
#define DIAG_USB_MODE              1
#define DIAG_MEMORY_DEVICE_MODE    2
#define DIAG_NO_LOGGING_MODE       3

/* Device/peripheral mask helpers. DIAG_CON_ALL covers all peripherals. */
#define DIAG_CON_APSS              0x0001
#define DIAG_CON_MPSS              0x0002
#define DIAG_CON_LPASS             0x0004
#define DIAG_CON_WCNSS             0x0008
#define DIAG_CON_SENSORS           0x0010
#define DIAG_CON_ALL               (DIAG_CON_APSS|DIAG_CON_MPSS|DIAG_CON_LPASS|\
                                    DIAG_CON_WCNSS|DIAG_CON_SENSORS|0x0020|0x0040)
#define DIAG_MD_LOCAL              0   /* local-processor MD routing */
#define DIAG_MD_LOCAL_LAST         0
#define DIAG_MD_PERIPHERAL         1

/* RE'd from diag_udp_bridge.c:31-40 (24 bytes). Used as the SWITCH_LOGGING arg. */
struct diag_logging_mode_param_t {
    uint32_t req_mode;
    uint32_t peripheral_mask;
    uint32_t pd_mask;
    uint16_t mode_param;
    uint8_t  diag_id;
    uint8_t  reserved;
    int      peripheral;
    int      device_mask;
};
#endif
