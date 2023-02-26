// Axel '0vercl0k' Souchet - March 8 2020
#include <windows.h>

#include <assert.h>
#include <boost/icl/interval_set.hpp>
#include <cstdint>
#include <cstdio>
#include <inttypes.h>
#include <memory>
#include <optional>
#include <string.h>
#include <string>
#include <tlhelp32.h>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ntdll.lib")

#ifdef NDEBUG
#define dbgprintf(...) /**/
#else
#define dbgprintf(...) printf(__VA_ARGS__)
#endif

enum class THREADINFOCLASS : uint32_t { ThreadBasicInformation };

extern "C" uint32_t NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtLockVirtualMemory(HANDLE ProcessHandle,
                                                           PVOID *BaseAddress,
                                                           PSIZE_T RegionSize,
                                                           ULONG MapType);

using Interval_t = boost::icl::interval<uint64_t>;
using Ranges_t = boost::icl::interval_set<uint64_t>;

const uint64_t _1MB = 1'024 * 1'024;
const NTSTATUS STATUS_WORKING_SET_QUOTA = 0xc000'00a1;
const ULONG MAP_PROCESS = 1;
const ULONG MAP_SYSTEM = 2;

template <typename F_t> [[nodiscard]] auto finally(F_t &&f) noexcept {
  struct Finally_t {
    F_t f_;
    bool Canceled = false;
    Finally_t(F_t &&f) noexcept : f_(f) {}
    ~Finally_t() noexcept {
      if (!Canceled) {
        f_();
      }
    }
  };

  return Finally_t(std::move(f));
}

[[nodiscard]] bool NT_SUCCESS(const NTSTATUS Status) { return Status >= 0; }

std::optional<Ranges_t> ParseRanges(std::string String) {
  Ranges_t Ranges;

  //
  // Strip backticks if there's any... (WinDbg uses them to separate the lower
  // 4 bytes from the higher 4 bytes of an address)
  //

  if (String.find('`') != String.npos) {
    const auto &NewEnd = std::remove(String.begin(), String.end(), '`');
    String.erase(NewEnd, String.end());
  }

  char *Str = String.data();
  char *Context = nullptr;
  for (const char *Token = strtok_s(Str, ",", &Context); Token != nullptr;
       Token = strtok_s(nullptr, ",", &Context)) {

    //
    // Parse a range off the current token.
    //

    uint64_t Start = 0, End = 0;
    char Mode = 0;
    const int HowMany =
        sscanf_s(Token, "%" PRIx64 "%c%" PRIx64, &Start, &Mode, 1, &End);
    if (HowMany != 3) {
      printf("The range %s is malformed, exiting\n", Token);
      return {};
    }

    const auto CorrectMode = Mode == '-' || Mode == '+';
    if (!CorrectMode) {
      printf("The range %s uses an unknown mode, exiting\n", Token);
      return {};
    }

    //
    // If + is used, End is actually a size, not an address; so calculate it.
    //

    if (Mode == '+') {
      End += Start + ((End > 1) ? -1 : 0);
      printf("%" PRIx64 ", %" PRIx64 "\n", Start, End);
    }

    //
    // Verify that the range is sane.
    //

    if (Start >= End) {
      printf("The range %s is malformed, exiting\n", Token);
      return {};
    }

    //
    // Check if the start is page aligned.
    //

    if ((Start & 0xf'ff) != 0) {
      printf("The range start %" PRIx64 " is not page aligned, exiting\n",
             Start);
      return {};
    }

    //
    // Check that the range is page aligned.
    //

    const uint64_t Size = End - Start + 1;
    if ((Size & 0xf'ff) != 0) {
      printf("The range size %" PRIx64 " is not page aligned, exiting\n", Size);
      return {};
    }

    //
    // All right, we have a range!
    //

    Ranges.insert(Interval_t::closed(Start, End));
  }

  return Ranges;
}

[[nodiscard]] bool GrownAndLockInWorkingSet(const HANDLE Process,
                                            const auto &Range) {
  auto BaseAddress = PVOID(Range.lower());
  auto RegionSize = boost::icl::size(Range);
  for (size_t Tries = 0; Tries < 10; Tries++) {
    const NTSTATUS Status =
        NtLockVirtualMemory(Process, &BaseAddress, &RegionSize, MAP_PROCESS);

    if (NT_SUCCESS(Status)) {
      return true;
    }

    if (Status != STATUS_WORKING_SET_QUOTA) {
      printf("NtLockVirtualMemory failed w/ %x for %p\n", Status, BaseAddress);
      return false;
    }

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

    printf("Growing working set to %lld MB..\r", MinimumWorkingSetSize / _1MB);

    Flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;

    if (!SetProcessWorkingSetSizeEx(Process, MinimumWorkingSetSize,
                                    MaximumWorkingSetSize, Flags)) {
      printf("SetProcessWorkingSetSizeEx failed, GLE=%lu.\n", GetLastError());
      return false;
    }
  }

  printf("Ran out of tries to grow the working set.\n");
  return false;
}

[[nodiscard]] std::optional<uint32_t> Name2Pid(const std::string &ProcessName) {
  PROCESSENTRY32 Pe32;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE) {
    return {};
  }

  const auto &CloseSnapshot = finally([&] { CloseHandle(Snapshot); });

  Pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(Snapshot, &Pe32)) {
    return {};
  }

  std::optional<uint32_t> Pid;
  do {
    const bool Match = _stricmp(Pe32.szExeFile, ProcessName.c_str()) == 0;
    if (!Match) {
      continue;
    }

    if (Pid) {
      printf("There are several instances of %s, pid %d will be used.\n",
             Pe32.szExeFile, *Pid);
    } else {
      Pid = Pe32.th32ProcessID;
    }
  } while (Process32Next(Snapshot, &Pe32));
  return Pid;
}

[[nodiscard]] bool VirtRead(const uintptr_t RemoteAddress, void *Buffer,
                            const size_t BufferLength,
                            const HANDLE Process = GetCurrentProcess()) {
  SIZE_T AmountRead = 0;
  if (!ReadProcessMemory(Process, (void *)RemoteAddress, Buffer, BufferLength,
                         &AmountRead)) {
    return false;
  }

  return AmountRead == BufferLength;
}

template <typename Struct_t>
[[nodiscard]] bool VirtRead(const uintptr_t RemoteAddress, Struct_t &Struct,
                            const HANDLE Process = GetCurrentProcess()) {
  return VirtRead(RemoteAddress, &Struct, sizeof(Struct), Process);
}

[[nodiscard]] std::optional<Ranges_t> GetStackRange(const HANDLE Process,
                                                    const uint32_t Tid) {

  //
  // Open the thread.
  //

  const HANDLE Thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, Tid);
  if (Thread == nullptr) {
    printf("OpenThread failed w/ GLE=%d\n", GetLastError());
    return {};
  }

  const auto &CloseThread = finally([&] { CloseHandle(Thread); });

  //
  // Get the TEB.
  //

  struct {
    uint32_t ExitStatus;
    uintptr_t TebBaseAddress;
    struct {
      HANDLE UniqueProcess;
      HANDLE UniqueThread;
    } ClientId;
    uintptr_t AffinityMask;
    uint32_t Priority;
    uint32_t BasePriority;
  } ThreadInformation = {};

  ULONG Length = 0;
  const uint32_t Status = NtQueryInformationThread(
      Thread, THREADINFOCLASS::ThreadBasicInformation, &ThreadInformation,
      sizeof(ThreadInformation), &Length);
  if (Status != 0 || Length != sizeof(ThreadInformation)) {
    printf("NtQueryInformationThread failed w/ %x\n", Status);
    return {};
  }

  //
  // Grab the TEB.
  //

  union {
    struct {
      uint64_t ExceptionList;
      uint64_t StackBase;
      uint64_t StackLimit;
    } _64;
    struct {
      uint32_t ExceptionList;
      uint32_t StackBase;
      uint32_t StackLimit;
    } _32;
  } Tib = {};

  if (!VirtRead(ThreadInformation.TebBaseAddress, Tib, Process)) {
    printf("VirtRead failed, bailing\n");
    return {};
  }

  Ranges_t StackRanges;
#ifdef _WIN64
  assert(Tib._64.StackLimit < Tib._64.StackBase && Tib._64.StackBase > 0);
  StackRanges.insert(
      Interval_t::right_open(Tib._64.StackLimit, Tib._64.StackBase));
#else
  assert(Tib._32.StackLimit < Tib._32.StackBase && Tib._32.StackBase > 0);
  StackRanges.insert(
      Interval_t::right_open(Tib._32.StackLimit, Tib._32.StackBase));
#endif

#ifdef _WIN64
  uint16_t ProcessMachine = 0, NativeMachine = 0;
  if (!IsWow64Process2(Process, &ProcessMachine, &NativeMachine)) {
    printf("IsWow64Process2 failed w/ GLE=%d, bailing\n", GetLastError());
    return {};
  }

  if (NativeMachine != IMAGE_FILE_MACHINE_AMD64) {
    printf("NativeMachine has an unexpected value (%x), bailing\n",
           NativeMachine);
    return {};
  }

  if (ProcessMachine != IMAGE_FILE_MACHINE_I386) {
    return StackRanges;
  }

  if (!VirtRead(Tib._64.ExceptionList, Tib, Process)) {
    printf("VirtRead2 failed, bailing\n");
    return {};
  }

  assert(Tib._32.StackLimit < Tib._32.StackBase && Tib._32.StackBase);
  StackRanges.insert(
      Interval_t::right_open(Tib._32.StackLimit, Tib._32.StackBase));
#endif

  return StackRanges;
}

[[nodiscard]] std::optional<Ranges_t> GetStackRanges(const HANDLE Process,
                                                     const uint32_t Pid) {
  Ranges_t Stacks;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (Snapshot == INVALID_HANDLE_VALUE) {
    printf("CreateToolhelp32Snapshot failed w/ GLE=%d\n", GetLastError());
    return {};
  }

  const auto &CloseSnapshot = finally([&] { CloseHandle(Snapshot); });

  THREADENTRY32 Entry = {};
  Entry.dwSize = sizeof(Entry);
  if (!Thread32First(Snapshot, &Entry)) {
    printf("Thread32First failed w/ GLE=%d\n", GetLastError());
    return {};
  }

  do {

    //
    // If it's not a thread owned by the process we want, continue.
    //

    if (Entry.th32OwnerProcessID != Pid) {
      continue;
    }

    //
    // Retrieve the stack ranges.
    //

    const auto &Ranges = GetStackRange(Process, Entry.th32ThreadID);
    if (!Ranges) {
      printf("GetStackRange failed for TID=%x, bailing\n", Entry.th32ThreadID);
      return {};
    }

    for (const auto &Range : *Ranges) {
      printf("TID %lu Stack Range: %" PRIx64 "-%" PRIx64 "\n",
             Entry.th32ThreadID, Range.lower(), Range.upper());
      Stacks.insert(Range);
    }
  } while (Thread32Next(Snapshot, &Entry));

  return Stacks;
}

struct Opts_t {
  std::optional<std::string> NameOrPid;
  std::optional<Ranges_t> Ranges;
  bool Stacks = false;
};

int main(int Argc, const char *Argv[]) {

  //
  // Parse arguments received.
  //

  Opts_t Opts;
  for (int Idx = 1; Idx < Argc; Idx++) {
    const std::string Arg = Argv[Idx];
    const char *Next = (Idx + 1) < Argc ? Argv[Idx + 1] : nullptr;
    if (Arg == "--ranges") {
      if (!Next) {
        printf("--ranges expect to be followed by an argument.\n");
        return EXIT_FAILURE;
      }

      Opts.Ranges = ParseRanges(Next);
      if (!Opts.Ranges) {
        printf("ParseRanges failed, exiting.\n");
        return EXIT_FAILURE;
      }
      Idx++;
    } else if (Arg == "--stacks") {
      Opts.Stacks = true;
    } else {
      Opts.NameOrPid = Arg;
    }
  }

  //
  // If we don't have a name or pid, we have no job to do!
  //

  if (!Opts.NameOrPid) {
    printf("./lockmem [--ranges 0-0x1000,0x2000+0x1000,..] [--stacks] <process "
           "name | pid>\n");
    return EXIT_FAILURE;
  }

  //
  // Figure out if we received a PID or a process name.
  //

  char *EndPtr = nullptr;
  errno = 0;
  uint32_t ProcessId = strtol(Opts.NameOrPid->c_str(), &EndPtr, 0);
  const bool Valid = errno == 0 && *EndPtr == 0;
  if (!Valid) {
    const auto &Pid = Name2Pid(*Opts.NameOrPid);
    if (!Pid) {
      printf("Name2Pid failed, exiting.\n");
      return EXIT_FAILURE;
    }
    ProcessId = *Pid;
  }

  //
  // Open the target process.
  //

  const HANDLE Process =
      OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_READ,
                  false, ProcessId);

  if (!Process) {
    printf("OpenProcess(%s) failed w/ GLE=%d, exiting.\n", Argv[1],
           GetLastError());
    return EXIT_FAILURE;
  }

  const auto &CloseProcess = finally([&] { CloseHandle(Process); });

  //
  // Get threads stacks.
  //

  std::optional<Ranges_t> AllowRanges;
  if (Opts.Stacks) {
    AllowRanges = GetStackRanges(Process, ProcessId);
    if (!AllowRanges) {
      printf("GetStacks failed, exiting\n");
      return EXIT_FAILURE;
    }
  }

  //
  // Get the user ranges in there as well.
  //

  if (Opts.Ranges) {
    if (AllowRanges) {
      *AllowRanges += *Opts.Ranges;
    } else {
      AllowRanges = *Opts.Ranges;
    }
  }

  //
  // Iterate through memory ranges of the process.
  //

  printf("Got a handle to PID %d\n", ProcessId);
  MEMORY_BASIC_INFORMATION MemoryInfo;
  uint64_t NumberBytes = 0;
  uint64_t AmountMb = 0;
  for (uint8_t *Address = nullptr;
       VirtualQueryEx(Process, Address, &MemoryInfo, sizeof(MemoryInfo));
       Address = (uint8_t *)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) {

    //
    // If this is a page guard, or a no access page; let's ignore it.
    //

    const auto BaseAddress = MemoryInfo.BaseAddress;
    const auto RegionSize = MemoryInfo.RegionSize;
    const uint32_t BadProtectBits = PAGE_GUARD | PAGE_NOACCESS;
    if (MemoryInfo.Protect & BadProtectBits) {
      dbgprintf("Skipping %p - %zx because of protect bad bits..\n",
                BaseAddress, RegionSize);
      continue;
    }

    //
    // If the page is reserved or freed, let's ignore it.
    //

    const uint32_t BadStatetBits = MEM_FREE | MEM_RESERVE;
    if (MemoryInfo.State & BadStatetBits) {
      dbgprintf("Skipping %p - %zx because of state bad bits..\n", BaseAddress,
                RegionSize);
      continue;
    }

    //
    // Check if the region overlaps with a filter.
    //

    const auto &RegionRange = Interval_t::right_open(
        uint64_t(BaseAddress), uint64_t(BaseAddress) + RegionSize);
    Ranges_t OverlappingRanges;
    OverlappingRanges.insert(RegionRange);
    if (AllowRanges) {
      OverlappingRanges = *AllowRanges & RegionRange;
    }

    for (const auto &OverlappingRange : OverlappingRanges) {

      //
      // Extend the WS if needed, and lock the region in.
      //

      if (!GrownAndLockInWorkingSet(Process, OverlappingRange)) {
        printf("GrownAndLockInWorkingSet failed, exiting.\n");
        return EXIT_FAILURE;
      }

      const auto OverlappingStart = PVOID(OverlappingRange.lower());
      const auto OverlappingSize = boost::icl::size(OverlappingRange);
      dbgprintf("Locked %p (%lld MB) in memory..\r", OverlappingStart,
                OverlappingSize / _1MB);
#if 0
      auto Buffer = std::make_unique<uint8_t[]>(OverlappingSize);
      SIZE_T NumberBytesRead = 0;
      const bool Ret =
          ReadProcessMemory(Process, OverlappingStart, Buffer.get(),
                            OverlappingSize, &NumberBytesRead);
      if (!Ret || NumberBytesRead != OverlappingSize) {
        printf("ReadProcessMemory failed w/ GLE=%d, exiting.\n",
               GetLastError());
        return EXIT_FAILURE;
      }
#endif

      //
      // OK we're done.
      //

      dbgprintf("Read region %p..\r", OverlappingStart);
      NumberBytes += OverlappingSize;
      AmountMb = NumberBytes / _1MB;
    }

    printf("Locked %llu MBs..\r", AmountMb);
  }

  printf("Done, locked %llu MBs!\n", AmountMb);
  return EXIT_SUCCESS;
}