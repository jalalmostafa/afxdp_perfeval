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

#include "dlog.h"

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define always_inline // inline __attribute__((always_inline))

#define HUGEPAGE_2MB_SIZE 2097152
#define HUGETLB_PATH "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
#define HUGETLB_CALC(size) ((u32)ceil(size / HUGEPAGE_2MB_SIZE))
#define HUGETLB_DIGITS 10

always_inline int get_hugepages()
{
    char buffer[HUGETLB_DIGITS] = { 0 };

    int fd = open(HUGETLB_PATH, O_RDONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
        return -1;
    }

    int ret = read(fd, &buffer, HUGETLB_DIGITS);
    if (ret < 0) {
        dlog_error2("read", ret);
        return -1;
    }

    int nb_hugepages = atoi(buffer);
    close(fd);
    return nb_hugepages;
}

void set_hugepages(int nb_hugepages)
{
    char buffer[HUGETLB_DIGITS] = { 0 };

    int fd = open(HUGETLB_PATH, O_WRONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
        return;
    }

    sprintf(buffer, "%d\n", nb_hugepages);

    int ret = write(fd, &buffer, 10);
    if (ret < 0) {
        dlog_error2("write", ret);
        return;
    }
    close(fd);
}

u8* huge_malloc(u64 size)
{
    int needed_hgpg = HUGETLB_CALC(size);
    int current_hgpg = get_hugepages();
    set_hugepages(current_hgpg + needed_hgpg);

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
    char mask[10] = { 0 };
    char irq_file[PATH_MAX] = { 0 };
    snprintf(irq_file, 30, "/proc/irq/%d/smp_affinity", irq);
    snprintf(mask, 10, "%d", 1 << cpu);
    int fd = open(irq_file, O_RDWR);
    write(fd, mask, strlen(mask));
    close(fd);
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

#endif
