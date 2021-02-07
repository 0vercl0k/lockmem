// Axel '0vercl0k' Souchet - February 6 2020
#pragma once
#ifdef _KERNEL_MODE
#    include <ntifs.h>
#else
#    include <windows.h>
#endif

#define LCK_DEVICE_NAME "Lockmem"