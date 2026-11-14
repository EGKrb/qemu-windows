/*
 * Native Win32 linux-user prototype: entry point
 *
 * Same start-up sequence as linux-user/main.c, reduced to what the
 * prototype supports: no binfmt_misc, gdbstub or plugins, one guest
 * thread, static executables.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/help-texts.h"
#include "qemu/help_option.h"
#include "qemu/accel.h"
#include "qemu/version.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qom/object.h"
#include "accel/accel-ops.h"
#include "crypto/init.h"
#include "exec/cpu-common.h"
#include "exec/page-vary.h"
#include "tcg/startup.h"
#include "trace/control.h"
#include "user/cpu_loop.h"
#include "user/guest-base.h"
#include "user/page-protection.h"
#include "win32-user.h"

__thread CPUState *thread_cpu;
bool w32u_strace;

static const char *cpu_model;
static const char *argv0;
static const char *seed_optarg;
static const char *log_filename;
static int log_mask;
static bool one_insn_per_tb;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

static G_NORETURN void usage(int exitcode)
{
    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Native Windows Linux user-mode emulator (prototype: static "
           "executables, one thread)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n"
           "-h                              print this help\n"
           "-version                        display version information\n"
           "-cpu model       QEMU_CPU       select CPU (-cpu help for list)\n"
           "-E var=value                    set an environment variable "
           "for the guest\n"
           "-U var                          unset an environment variable "
           "for the guest\n"
           "-0 argv0                        force the guest argv[0]\n"
           "-d item[,...]    QEMU_LOG       enable logging of items "
           "(-d help for list)\n"
           "-D logfile       QEMU_LOG_FILENAME  write logs to 'logfile' "
           "(default stderr)\n"
           "-seed seed       QEMU_RAND_SEED seed the pseudo-random number "
           "generator\n"
           "-one-insn-per-tb                one guest instruction per "
           "translation block\n"
           "-strace          QEMU_STRACE    log system calls\n"
           "\n"
           "Guest paths: /c/... and /mnt/c/... are drive C:, /tmp is the "
           "Windows temporary\n"
           "directory, other paths are given to Windows as they are.\n"
           QEMU_HELP_BOTTOM "\n");
    exit(exitcode);
}

static void set_log(const char *items)
{
    log_mask = qemu_str_to_log_mask(items);
    if (!log_mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
}

static void set_cpu(const char *model)
{
    cpu_model = model;
    if (is_help_option(cpu_model)) {
        list_cpus();
        exit(EXIT_SUCCESS);
    }
}

static void parse_env(void)
{
    const char *s;

    if ((s = g_getenv("QEMU_CPU"))) {
        cpu_model = s;
    }
    if ((s = g_getenv("QEMU_LOG"))) {
        set_log(s);
    }
    if ((s = g_getenv("QEMU_LOG_FILENAME"))) {
        log_filename = s;
    }
    if ((s = g_getenv("QEMU_RAND_SEED"))) {
        seed_optarg = s;
    }
    if (g_getenv("QEMU_STRACE")) {
        w32u_strace = true;
    }
}

/* Returns the index of the guest program in argv */
static int parse_args(int argc, char **argv, char ***envp)
{
    int i;

    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        const char *opt = argv[i] + 1 + (argv[i][1] == '-');
        const char *arg = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        }
        if (!strcmp(opt, "h") || !strcmp(opt, "help")) {
            usage(EXIT_SUCCESS);
        } else if (!strcmp(opt, "version")) {
            printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
                   "\n" QEMU_COPYRIGHT "\n");
            exit(EXIT_SUCCESS);
        } else if (!strcmp(opt, "strace")) {
            w32u_strace = true;
        } else if (!strcmp(opt, "one-insn-per-tb")) {
            one_insn_per_tb = true;
        } else {
            if (!arg) {
                fprintf(stderr, "qemu: option '%s' needs an argument\n",
                        argv[i]);
                exit(EXIT_FAILURE);
            }
            if (!strcmp(opt, "cpu")) {
                set_cpu(arg);
            } else if (!strcmp(opt, "E")) {
                g_auto(GStrv) kv = g_strsplit(arg, "=", 2);

                if (!kv[1]) {
                    fprintf(stderr, "qemu: -E expects var=value\n");
                    exit(EXIT_FAILURE);
                }
                *envp = g_environ_setenv(*envp, kv[0], kv[1], true);
            } else if (!strcmp(opt, "U")) {
                *envp = g_environ_unsetenv(*envp, arg);
            } else if (!strcmp(opt, "0")) {
                argv0 = arg;
            } else if (!strcmp(opt, "d")) {
                set_log(arg);
            } else if (!strcmp(opt, "D")) {
                log_filename = arg;
            } else if (!strcmp(opt, "seed")) {
                seed_optarg = arg;
            } else {
                fprintf(stderr, "qemu: unknown option '%s'\n", argv[i]);
                exit(EXIT_FAILURE);
            }
            i++;
        }
    }
    if (i >= argc) {
        fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }
    return i;
}

static void init_accel(void)
{
    AccelState *accel = current_accel();
    AccelClass *ac = ACCEL_GET_CLASS(accel);

    accel_init_interfaces(ac);
    object_property_set_bool(OBJECT(accel), "one-insn-per-tb",
                             one_insn_per_tb, &error_abort);
    ac->init_machine(accel, NULL);
}

static void init_random(void)
{
    Error *err = NULL;

    if (seed_optarg) {
        qemu_guest_random_seed_main(seed_optarg, &err);
    } else {
        qcrypto_init(&err);
    }
    if (err) {
        error_reportf_err(err, "cannot initialize crypto: ");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    char **target_env, **target_argv;
    const char *exec_path;
    W32UImage image;
    CPUState *cpu;
    int optind, i, ret;

    /* UTF-8 arguments, whatever the ANSI code page */
    argv = g_win32_get_command_line();
    argc = g_strv_length(argv);

    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    target_env = g_get_environ();
    parse_env();
    optind = parse_args(argc, argv, &target_env);
    exec_path = argv[optind];

    qemu_set_log_filename_flags(log_filename,
                                log_mask | (w32u_strace ? LOG_STRACE : 0),
                                &error_fatal);
    if (!trace_init_backends()) {
        exit(EXIT_FAILURE);
    }

    /* init tcg before creating CPUs */
    init_accel();
    set_preferred_target_page_bits(ctz32(qemu_real_host_page_size()));
    finalize_target_page_bits();

    cpu = cpu_create(parse_cpu_option(cpu_model ? cpu_model : "max"));
    cpu_reset(cpu);
    thread_cpu = cpu;

    w32u_mem_init();
    w32u_fault_init();
    init_random();
    w32u_syscall_init(exec_path);

    target_argv = g_new0(char *, argc - optind + 1);
    for (i = 0; optind + i < argc; i++) {
        target_argv[i] = argv[optind + i];
    }
    if (argv0) {
        target_argv[0] = (char *)argv0;
    }

    ret = w32u_load_elf(exec_path, target_argv, target_env, &image);
    if (ret < 0) {
        fprintf(stderr, "qemu: error while loading %s\n", exec_path);
        exit(EXIT_FAILURE);
    }
    g_free(target_argv);
    g_strfreev(target_env);
    w32u_set_brk(image.brk);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        FILE *f = qemu_log_trylock();

        if (f) {
            fprintf(f, "guest_base  %p\n", (void *)guest_base);
            page_dump(f);
            fprintf(f, "entry       0x" TARGET_ABI_FMT_lx "\n", image.entry);
            fprintf(f, "brk         0x" TARGET_ABI_FMT_lx "\n", image.brk);
            fprintf(f, "start_stack 0x" TARGET_ABI_FMT_lx "\n",
                    image.start_stack);
            qemu_log_unlock(f);
        }
    }

    /*
     * guest_base is fixed now: generate the prologue so that it can take
     * its value into account.
     */
    tcg_prologue_init();
    w32u_init_main_thread(cpu, &image);
    cpu_loop(cpu_env(cpu));
    /* never exits */
    return 0;
}
