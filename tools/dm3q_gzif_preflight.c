/* dm3q_gzif_preflight — read-only precondition probe for the S9180ZHU8GZIF
 * (Android 17 / One UI 9) CVE-2026-43284 ("Dirty Frag") feasibility study.
 *
 * This program performs NO privilege escalation. It opens exactly one
 * NETLINK_XFRM socket and immediately closes it, and it reads procfs/sysfs.
 * Its purpose is to tell you, BEFORE any porting begins, whether the GZIF
 * unit you run it on matches the analyzed kernel and what the local policy
 * allows. It never installs SAs, sends packets, or writes anything.
 *
 * Run from `adb shell` (or any app context you wish to test):
 *   adb push dm3q_gzif_preflight /data/local/tmp/
 *   adb shell /data/local/tmp/dm3q_gzif_preflight
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
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

static void print_file(const char *path) {
    char buf[512];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("%-44s errno=%d (%s)\n", path, errno, strerror(errno));
        return;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        printf("%-44s read errno=%d\n", path, errno);
        return;
    }
    buf[n] = '\0';
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\0')) buf[--n] = '\0';
    printf("%-44s %s\n", path, buf);
}

static void print_int_str(const char *label, const char *fmt) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", fmt);
    printf("%s\n", buf);
}

int main(void) {
    struct utsname uts;
    uname(&uts);
    printf("== dm3q GZIF preflight ==\n");
    printf("kernel release: %s\n", uts.release);
    const char *want = "5.15.197-android13-8-34343818-abS9180ZHU8GZIF";
    if (strcmp(uts.release, want) == 0) {
        printf("KERNEL MATCH: analyzed Image (5.15.197, SPL 2026-10-05) applies\n");
    } else {
        printf("KERNEL MISMATCH: expected %s — the GZIF binary analysis does NOT apply to this unit\n", want);
    }
    printf("uid=%d gid=%d\n", getuid(), getgid());
    print_file("/proc/self/attr/current");
    print_file("/sys/fs/selinux/enforce");
    print_file("/proc/sys/user/max_user_namespaces");
    print_file("/proc/sys/user/max_pid_namespaces");
    print_file("/proc/sys/kernel/unprivileged_userns_clone");
    print_file("/proc/sys/kernel/unprivileged_bpf_disabled");
    print_file("/proc/self/status");   /* Seccomp: field lives here */
    printf("prctl(PR_GET_SECCOMP)=%d\n", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    print_file("/proc/config.gz");

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
    if (fd >= 0) {
        printf("socket(AF_NETLINK, NETLINK_XFRM): OK (fd=%d) — policy permitted creation\n", fd);
        close(fd);
    } else {
        printf("socket(AF_NETLINK, NETLINK_XFRM): errno=%d (%s)\n", errno, strerror(errno));
    }
    return 0;
}
