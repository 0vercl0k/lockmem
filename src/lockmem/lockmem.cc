// Axel '0vercl0k' Souchet - March 8 2020
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

const uint64_t _1MB = 1024 * 1024;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_WORKING_SET_QUOTA 0xc00000a1

#define MAP_PROCESS 1
#define MAP_SYSTEM 2

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtLockVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                    _Inout_ PSIZE_T RegionSize, _In_ ULONG MapType);

bool ForceLockInWorkingSet(HANDLE Process, PVOID BaseAddress,
                           SIZE_T RegionSize) {
  for (size_t Tries = 0; Tries < 10; Tries++) {
    const NTSTATUS Status =
        NtLockVirtualMemory(Process, &BaseAddress, &RegionSize, MAP_PROCESS);

    if (NT_SUCCESS(Status)) {
      return true;
    }

    if (Status == STATUS_WORKING_SET_QUOTA) {
      SIZE_T MinimumWorkingSetSize = 0;
      SIZE_T MaximumWorkingSetSize = 0;
      DWORD Flags;

      if (!GetProcessWorkingSetSizeEx(Process, &MinimumWorkingSetSize,
                                      &MaximumWorkingSetSize, &Flags)) {
        printf("GetProcessWorkingSetSizeEx failed, GLE=%lu.\n", GetLastError());
        return false;
      }

      MaximumWorkingSetSize *= 2;
      MinimumWorkingSetSize *= 2;

      printf("Growing working set to %lld MB..\r",
             MinimumWorkingSetSize / _1MB);

      Flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;

      if (!SetProcessWorkingSetSizeEx(Process, MinimumWorkingSetSize,
                                      MaximumWorkingSetSize, Flags)) {
        printf("SetProcessWorkingSetSizeEx failed, GLE=%lu.\n", GetLastError());
        return false;
      }
    }
  }

  printf("Ran out of tries to grow the working set.\n");

  return false;
}

bool Pid2Name(const char *ProcessName, uint32_t &Pid) {
  PROCESSENTRY32 Pe32;
  HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snap == INVALID_HANDLE_VALUE) {
    return false;
  }

  Pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(Snap, &Pe32)) {
    CloseHandle(Snap);
    return false;
  }

  bool FoundPid = false;
  do {
    const bool Match = _stricmp(Pe32.szExeFile, ProcessName) == 0;
    if (Match) {
      if (FoundPid) {
        printf("There are several instances of %s, pid %d will be used.\n",
               Pe32.szExeFile, Pid);
      } else {
        FoundPid = true;
        Pid = Pe32.th32ProcessID;
      }
    }
  } while (Process32Next(Snap, &Pe32));

  CloseHandle(Snap);
  return FoundPid;
}

int main(int Argc, const char *Argv[]) {
  if (Argc != 2) {
    printf("./lockme <process name | pid>\n");
    return EXIT_FAILURE;
  }

  uint32_t ProcessId = strtol(Argv[1], nullptr, 0);
  if (ProcessId == 0) {
    const bool Success = Pid2Name(Argv[1], ProcessId);
    if (!Success) {
      printf("Pid2Name failed, exiting.\n");
      return EXIT_FAILURE;
    }
  }

  const HANDLE Process =
      OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_READ,
                  false, ProcessId);

  if (Process == nullptr) {
    return EXIT_FAILURE;
  }

  printf("Got a handle to PID %d\n", ProcessId);
  MEMORY_BASIC_INFORMATION MemoryInfo;
  uint64_t NumberBytes = 0;
  uint64_t AmountMb = 0;
  for (uint8_t *Address = 0;
       VirtualQueryEx(Process, Address, &MemoryInfo, sizeof(MemoryInfo));
       Address = (uint8_t *)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) {
    PVOID BaseAddress = MemoryInfo.BaseAddress;
    SIZE_T RegionSize = MemoryInfo.RegionSize;
    const uint32_t BadProtectBits = PAGE_GUARD | PAGE_NOACCESS;
    if (MemoryInfo.Protect & BadProtectBits) {
      // printf("Skipping %p - %llx because of protect bad bits..\n",
      //         BaseAddress, RegionSize);
      continue;
    }

    const uint32_t BadStatetBits = MEM_FREE | MEM_RESERVE;
    if (MemoryInfo.State & BadStatetBits) {
      // printf("Skipping %p - %llx because of state bad bits..\n",
      //         BaseAddress, RegionSize);
      continue;
    }

    if (!ForceLockInWorkingSet(Process, BaseAddress, RegionSize)) {
      printf("ForceLockInWorkingSet failed, exiting.\n");
      return EXIT_FAILURE;
    }

    // printf("Locked %p (%lld MB) in memory..\r", BaseAddress, RegionSize /
    // _1MB);

    auto Buffer = std::make_unique<uint8_t[]>(RegionSize);
    SIZE_T NumberBytesRead = 0;
    const bool Ret = ReadProcessMemory(Process, BaseAddress, Buffer.get(),
                                       RegionSize, &NumberBytesRead);
    if (!Ret || NumberBytesRead != RegionSize) {
      printf("Failed to ReadProcessMemory the region, exiting.\n");
      return EXIT_FAILURE;
    }

    // printf("Read region %p..\r", BaseAddress);
    NumberBytes += RegionSize;
    AmountMb = NumberBytes / _1MB;
    printf("Locked %llu MBs..\r", AmountMb);
  }

  printf("Done, locked %llu MBs!\n", AmountMb);
  return EXIT_SUCCESS;
}