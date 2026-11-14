/*
 * Native Win32 linux-user prototype: stubs
 *
 * The user-mode gdbstub (gdbstub/user.c and friends) is not built for
 * Windows yet, but the CPU and target code still describe their registers
 * to it.  Without a gdb server nothing ever reads those descriptions, so
 * registering them does nothing.
 *
 * util/qemu-sockets.c is not linked either: the prototype opens no host
 * socket, so no descriptor is ever one.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/sockets.h"
#include "exec/gdbstub.h"
#include "gdbstub/commands.h"
#include "gdbstub/syscalls.h"
#include "gdbstub/user.h"

/* include/exec/gdbstub.h */

void gdb_init_cpu(CPUState *cpu)
{
}

void gdb_register_coprocessor(CPUState *cpu,
                              gdb_get_reg_cb get_reg, gdb_set_reg_cb set_reg,
                              const GDBFeature *feature)
{
}

void gdb_feature_builder_init(GDBFeatureBuilder *builder, GDBFeature *feature,
                              const char *name, const char *xmlname,
                              int base_reg)
{
}

void gdb_feature_builder_append_tag(const GDBFeatureBuilder *builder,
                                    const char *format, ...)
{
}

void gdb_feature_builder_append_reg(const GDBFeatureBuilder *builder,
                                    const char *name,
                                    int bitsize,
                                    int regnum,
                                    const char *type,
                                    const char *group)
{
}

void gdb_feature_builder_end(const GDBFeatureBuilder *builder)
{
}

const GDBFeature *gdb_find_static_feature(const char *xmlname)
{
    return NULL;
}

/* include/gdbstub/commands.h: only reached from gdb packet handlers */

int gdb_put_packet(const char *buf)
{
    g_assert_not_reached();
}

void gdb_hextomem(GByteArray *mem, const char *buf, int len)
{
    g_assert_not_reached();
}

void gdb_extend_query_table(GPtrArray *table)
{
}

void gdb_extend_set_table(GPtrArray *table)
{
}

void gdb_extend_qsupported_features(char *qsupported_features)
{
}

/* include/gdbstub/syscalls.h: semihosting calls are never forwarded */

int use_gdb_syscalls(void)
{
    return 0;
}

/*
 * include/gdbstub/user.h: no gdb server is ever requested, so translated
 * blocks may be chained across pages.
 */

bool gdb_may_set_breakpoints(void)
{
    return false;
}

/* include/qemu/sockets.h */

bool fd_is_socket(int fd)
{
    return false;
}

/* plugins/api.c: no gdbstub, no registers to list */
GArray *gdb_get_register_list(CPUState *cpu)
{
    return g_array_new(false, false, sizeof(GDBRegDesc));
}

int gdb_read_register(CPUState *cpu, GByteArray *buf, int reg)
{
    return 0;
}

int gdb_write_register(CPUState *cpu, uint8_t *mem_buf, int reg)
{
    return 0;
}
