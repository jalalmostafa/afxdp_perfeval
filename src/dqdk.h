#ifndef DQDK_TYPES_H
#define DQDK_TYPES_H

#include <linux/mman.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <math.h>
#include <ctype.h>
#include <numa.h>
#include <errno.h>
#include <unistd.h>

#include "dlog.h"

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define always_inline inline __attribute__((always_inline))

#define HUGEPAGE_2MB_SIZE 2097152
#define HUGETLB_PATH "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
#define HUGETLB_CALC(size) ((u32)ceil(size / HUGEPAGE_2MB_SIZE))
#define INT_BUFFER 100
#define STRING_BUFFER 1024

char* sys_read_string(const char* path)
{
    char* buffer = calloc(1, STRING_BUFFER);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
    }

    int ret = read(fd, buffer, STRING_BUFFER);
    if (ret < 0) {
        dlog_error2("read", ret);
    }

    close(fd);
    return buffer;
}

int sys_read_uint(const char* path)
{
    char buffer[INT_BUFFER] = { 0 };
    int ret = -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        puts(path);
        dlog_error2("open", fd);
        return ret;
    }

    ret = read(fd, &buffer, INT_BUFFER);
    if (ret < 0) {
        dlog_error2("read", ret);
        goto exit;
    }

    ret = atoi(buffer);

exit:
    close(fd);
    return ret;
}

int sys_write_int(const char* path, int value)
{
    char buffer[INT_BUFFER] = { 0 };
    int ret = -1;
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        puts(path);
        dlog_error2("open", fd);
        return ret;
    }

    sprintf(buffer, "%d\n", value);
    ret = write(fd, &buffer, strlen(buffer));
    if (ret < 0) {
        dlog_error2("write", ret);
        goto exit;
    }

exit:
    close(fd);
    return ret;
}

int nic_numa_node(const char* ifname)
{
    char ifnuma[PATH_MAX] = { 0 };
    snprintf(ifnuma, PATH_MAX, "/sys/class/net/%s/device/numa_node", ifname);
    return sys_read_uint(ifnuma);
}

// get NUMA node huge pages
char* get_numa_hugepages_path(int numanode)
{
    char* path = calloc(1, PATH_MAX);
    sprintf(path, "/sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages", numanode);
    return path;
}

int reserve_hugepages(const char* path, int nb_hugepages)
{
    return sys_write_int(path, nb_hugepages);
}

int set_hugepages(int device_numanode, int howmany)
{
    char* path;
    int ret;

    if (device_numanode == -1) {
        return reserve_hugepages(HUGETLB_PATH, howmany);
    }

    path = get_numa_hugepages_path(device_numanode);
    ret = reserve_hugepages(path, howmany);
    free(path);
    return ret;
}

int get_hugepages(int device_numanode)
{
    int ret;
    char* path;

    if (device_numanode == -1) {
        return sys_read_uint(HUGETLB_PATH);
    }

    path = get_numa_hugepages_path(device_numanode);
    ret = sys_read_uint(path);
    free(path);
    return ret;
}

u8* huge_malloc(int devicenode, u64 size)
{
    int needed_hgpg = get_hugepages(devicenode) + HUGETLB_CALC(size);
    set_hugepages(devicenode, needed_hgpg);

    void* map = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);

    if (map == MAP_FAILED) {
        dlog_error2("huge_malloc", (int)(u64)map);
        return NULL;
    }

    return (u8*)map;
}

u64 clock_nsecs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

void nic_set_irq_affinity(int irq, int cpu)
{
    char irq_file[PATH_MAX] = { 0 };
    snprintf(irq_file, PATH_MAX, "/proc/irq/%d/smp_affinity_list", irq);
    sys_write_int(irq_file, cpu);
}

typedef struct {
    u32 irq;
    u32 interrupts;
} irq_interrupts_t;

typedef struct {
    u32 nbirqs;
    irq_interrupts_t* interrupts;
} interrupts_t;

interrupts_t* nic_get_interrupts(char* irqstr, u32 nprocs)
{
    char cmd[4096] = { 0 };
    char *line = NULL, *cursor = NULL;
    FILE* fp = NULL;
    u32 idx = 0, current_irq, current_interrupts = 0, procs = 0;
    size_t linesz = 0;
    interrupts_t* intrpts = (interrupts_t*)calloc(1, sizeof(interrupts_t));
    intrpts->nbirqs = nprocs;
    intrpts->interrupts = (irq_interrupts_t*)calloc(nprocs, sizeof(irq_interrupts_t));

    snprintf(cmd, 4096, "grep -P \"%s\" /proc/interrupts", irqstr);
    fp = popen(cmd, "r");

    while (getline(&line, &linesz, fp) != -1 && idx != nprocs) {
        current_irq = strtol(line, &cursor, 10);
        while (procs != nprocs) {
            while (!isdigit(cursor[0]))
                ++cursor;

            current_interrupts += strtol(cursor, &cursor, 10);
            ++procs;
        }

        intrpts->interrupts[idx].irq = current_irq;
        intrpts->interrupts[idx].interrupts = current_interrupts;

        current_interrupts = 0;
        procs = 0;
        idx++;
    }

    if (line != NULL) {
        free(line);
    }

    if (fp != NULL) {
        pclose(fp);
    }

    return intrpts;
}

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define DQDK_RCV_POLL (1 << 0)
#define DQDK_RCV_RTC (1 << 1)
#define IS_THREADED(x, nbqs) (x == DQDK_RCV_RTC && nbqs != 1)
#define DQDK_DURATION 3

#define is_power_of_2(x) ((x != 0) && ((x & (x - 1)) == 0))
#define popcountl(x) __builtin_popcountl(x)

int is_smt()
{
    return sys_read_uint("/sys/devices/system/cpu/smt/active");
}

int cpu_smt_sibling(int cpu)
{
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    char* siblings = sys_read_string(path);
    char* sibling;
    int isibling = -1;

    while ((sibling = strtok(siblings, ",")) != NULL) {
        if (atoi(sibling) != cpu) {
            isibling = atoi(sibling);
            goto exit;
        }
        siblings = NULL;
    }

exit:
    free(siblings);
    return isibling;
}

#endif
