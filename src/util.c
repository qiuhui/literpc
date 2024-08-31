#include <sys/time.h>
#include "util.h"
#include <stdio.h>
uint64_t get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
