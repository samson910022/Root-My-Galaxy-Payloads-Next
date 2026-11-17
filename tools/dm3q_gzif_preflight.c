/* dm3q_gzif_preflight — read-only precondition probe for the S9180ZHU8GZIF
 * (Android 17 / One UI 9) CVE-2026-43284 ("Dirty Frag") feasibility study.
 *
 * This program performs NO privilege escalation. It opens exactly one
 * NETLINK_XFRM socket and immediately closes it, and it reads procfs/sysfs.
 * Its purpose is to tell you, BEFORE any porting begins, whether the GZIF
 * unit you run it on matches the analyzed kernel and what the local policy
 * allows. It never installs SAs, sends packets, or writes anything.
 *
 * What this probe can and cannot tell you:
 *   - `uts.release` is a string the vendor chose. It is NOT binary
 *     attestation: it cannot distinguish an original GZIF kernel from a
 *     patched or swapped one that carries the same string, and it says
 *     nothing about which .config was built in. Treat a "KERNEL-RELEASE
 *     STRING MATCHES" line as "the unit reports the expected release
 *     string", never as "this is the analyzed Image". Binary identity is
 *     only established by a hash- or evidence-backed check outside this
 *     tool (see docs/SM-S9180-S9180ZHU8GZIF.md).
 *   - `/proc/config.gz` is gzip-compressed (CONFIG_IKCONFIG_PROC). This
 *     tool does not decompress it: it only reports whether the file
 *     exists and is readable. To inspect the config, use e.g.
 *       zcat /proc/config.gz | grep -E 'CONFIG_(USER_NS|XFRM_USER|INET_ESP)(=|_)'
 *     on a unit where it is present, or pull the config from the vendor
 *     firmware package.
 *   - The tracefs `sched_blocked_reason` event id is printed when the file
 *     is readable so it can be compared against the value statically
 *     derived for this build (108). A mismatch means the tracefs path of the
 *     payload must not be used on this unit.
 *
 * Exit status:
 *   0  the reported kernel release matches the analyzed build
 *   1  anything else (mismatch, probe error in strict mode)
 *   2  unknown argument (usage printed to stderr)
 *   `--strict` additionally requires the tracefs event id to be readable
 *   and equal to 108; otherwise exits 1 even on a release-string match.
 * A policy-denied NETLINK_XFRM socket is printed as an observation and is
 * NOT a failure condition of the probe.
 *
 * Run from `adb shell` (or any app context you wish to test):
 *   adb push dm3q_gzif_preflight /data/local/tmp/
 *   adb shell /data/local/tmp/dm3q_gzif_preflight [--strict]
 *
 * Reproduce the device binary (verified on the author's host, 2026-11-17):
 *   aarch64-linux-android35-clang -static -Wall -Wextra -Werror -O2 \
 *     -o dm3q_gzif_preflight tools/dm3q_gzif_preflight.c
 * (Android NDK r28c, android-35, fully static; no recipe ships in this
 * repository — the binary is gitignored; tools/dm3q_gzif_preflight.c is the
 * source of truth. pr-checks.yml compiles it as a bit-rot guard.)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <unistd.h>

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 14
#endif

/* Read a whole file into buf (NUL-terminated); returns bytes read, or -1. */
static ssize_t read_whole(const char *path, char *buf, size_t size) {
    if (size < 2) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    for (;;) {
        ssize_t n = read(fd, buf + off, size - 1 - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        if (n == 0) break;
        off += (size_t)n;
        if (off == size - 1) break; /* keep the trailing NUL */
    }
    close(fd);
    buf[off] = '\0';
    return (ssize_t)off;
}

/* Print the first line of file whose text starts with key (by field name). */
static void print_field(const char *path, const char *key) {
    char buf[16384];
    int off = read_whole(path, buf, sizeof(buf));
    if (off < 0) {
        printf("%-44s %s: errno=%d (%s)\n", key, path, errno, strerror(errno));
        return;
    }
    if ((size_t)off == sizeof(buf) - 1)
        printf("%-44s note: %s truncated to %zu bytes\n", key, path, sizeof(buf) - 1);
    size_t klen = strlen(key);
    for (char *p = buf; *p;) {
        char *eol = strpbrk(p, "\n\r");
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if ((len > klen) && strncmp(p, key, klen) == 0) {
            printf("%-44s %.*s\n", key, (int)len, p);
            return;
        }
        if (!eol) break;
        p = eol + 1;
    }
    printf("%-44s not present in %s\n", key, path);
}

static void print_file(const char *path) {
    char buf[512];
    ssize_t off = read_whole(path, buf, sizeof(buf));
    if (off < 0) {
        printf("%-44s errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    if ((size_t)off == sizeof(buf) - 1)
        printf("%-44s note: %s truncated to %zu bytes\n", path, path, sizeof(buf) - 1);
    /* small single-line files: trim trailing newline for tidy output */
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    printf("%-44s %s\n", path, buf);
}

/* The gzip config blob: report existence/readability only. */
static void report_config_gz(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        printf("%-44s errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("%-44s errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    close(fd);
    printf("%-44s present, st_size=%ld (procfs often reports 0), gzip — NOT decompressed here; "
           "inspect with: zcat %s | grep -E 'CONFIG_(USER_NS|XFRM_USER|INET_ESP)(=|_)'\n",
           path, (long)st.st_size, path);
}

/* The one number the SLIDE tracefs path depends on; 108 for this build. */
static int report_tracefs_event_id(void) {
    const char *path = "/sys/kernel/tracing/events/sched/sched_blocked_reason/id";
    char buf[64];
    char *end = NULL;
    if (read_whole(path, buf, sizeof(buf)) < 0) {
        printf("%-44s errno=%d (%s)\n", path, errno, strerror(errno));
        return -1;
    }
    errno = 0;
    unsigned long id = strtoul(buf, &end, 10);
    if (errno || end == buf) {
        printf("%-44s unparsable id in %s\n", path, path);
        return -1;
    }
    while (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t') end++;
    if (*end != '\0') {
        printf("%-44s unparsable id in %s\n", path, path);
        return -1;
    }
    printf("%-44s %lu (static derivation for this build: 108)\n", path, id);
    return (id == 108UL) ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        fprintf(stderr, "unknown extra argument: %s\n", argv[2]);
        fprintf(stderr, "usage: dm3q_gzif_preflight [--strict]\n");
        return 2;
    }
    int strict = (argc == 2 && strcmp(argv[1], "--strict") == 0);
    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("usage: dm3q_gzif_preflight [--strict]\n");
            printf("  default: exit 0 iff `uts.release` matches the analyzed build\n");
            printf("  --strict: also require the tracefs sched_blocked_reason id == 108\n");
            printf("  exit 2: unknown argument\n");
            return 0;
        }
        if (!strict) {
            fprintf(stderr, "unknown argument: %s\n", argv[1]);
            fprintf(stderr, "usage: dm3q_gzif_preflight [--strict]\n");
            return 2;
        }
    }

    struct utsname uts;
    if (uname(&uts) != 0) {
        printf("uname failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("== dm3q GZIF preflight ==\n");
    printf("kernel release: %s\n", uts.release);
    const char *want = "5.15.197-android13-8-34343818-abS9180ZHU8GZIF";
    int release_match = strcmp(uts.release, want) == 0;
    if (release_match) {
        printf("KERNEL-RELEASE STRING MATCHES: %s\n", want);
        printf("  note: the release string is not binary attestation; see docs/SM-S9180-S9180ZHU8GZIF.md\n");
    } else {
        printf("KERNEL-RELEASE MISMATCH: expected %s — the GZIF binary analysis does NOT apply to this unit\n", want);
    }
    printf("uid=%u gid=%u\n", (unsigned)getuid(), (unsigned)getgid());
    print_file("/proc/self/attr/current");
    print_file("/sys/fs/selinux/enforce");
    print_file("/proc/sys/user/max_user_namespaces");
    print_file("/proc/sys/user/max_pid_namespaces");
    print_file("/proc/sys/kernel/unprivileged_userns_clone");
    print_file("/proc/sys/kernel/unprivileged_bpf_disabled");
    /* The full /proc/self/status, read to EOF in a loop: the fields below sit
     * past byte 511 on common Android builds. */
    print_field("/proc/self/status", "NoNewPrivs:");
    print_field("/proc/self/status", "CapEff:");
    print_field("/proc/self/status", "CapBnd:");
    print_field("/proc/self/status", "Seccomp:");
    print_field("/proc/self/status", "Seccomp_filters:");
    printf("prctl(PR_GET_SECCOMP)=%d (mode only; filter count is Seccomp_filters above)\n",
           prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    report_config_gz("/proc/config.gz");
    int tracefs = report_tracefs_event_id();

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
    if (fd >= 0) {
        printf("socket(AF_NETLINK, NETLINK_XFRM): OK (fd=%d) — policy permitted creation\n", fd);
        close(fd);
    } else {
        /* An XFRM policy denial is an expected observation on locked-down
         * units and is deliberately not a probe failure. */
        printf("socket(AF_NETLINK, NETLINK_XFRM): errno=%d (%s)\n", errno, strerror(errno));
    }

    if (!release_match) return 1;
    if (strict && tracefs != 1) return 1;
    return 0;
}
