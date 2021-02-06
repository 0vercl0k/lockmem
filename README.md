# lockmem
![Builds](https://github.com/0vercl0k/lockmem/workflows/Builds/badge.svg)

This utility allows you to lock every available memory regions of an arbitrary process into its working set.
It uses `ntdll!NtLockVirtualMemory` (syscall used internally by [VirtualLock](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)) to lock memory ranges as well as [GetProcessWorkingSetSizeEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getprocessworkingsetsizeex) and [SetProcessWorkingSetSizeEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex) to increase the size of the process' working set.

The Windows kernel guarantees that those pages will stay resident in memory, not written to the [pagefile](https://docs.microsoft.com/en-us/windows/client-management/introduction-page-file) and not incur a page fault on access.

![lockmem](pics/lockmem.gif)

## Build

You can build the project using [Visual Studio 2019]() or `msbuild` using the solution file: `src/lockmem.sln`

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet