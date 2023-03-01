// Axel '0vercl0k' Souchet - March 8 2020
#include <windows.h>

#include <assert.h>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <fmt/core.h>
#include <memory>
#include <optional>
#include <string>
#include <tlhelp32.h>
#include <unordered_map>

#pragma comment(lib, "ntdll.lib")

#ifdef NDEBUG
#define dbgprint(...) /**/
#else
#define dbgprint(...) fmt::print(__VA_ARGS__)
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

enum class OverlapKind_t {
  BeforeStart,
  AfterStartBeforeEnd,
  AfterEnd,
  BeforeStartAfterEnd,
  No
};

struct Range_t {
  uint64_t Start = 0;
  uint64_t End = 0;

  [[nodiscard]] uint64_t Size() const { return End - Start; }

  [[nodiscard]] std::pair<OverlapKind_t, Range_t>
  Overlaps(const Range_t &O) const {

    //
    // <> is the |O| range, [] is the |this| range.
    //

    //
    // <-------[--->--------]
    //

    if (O.Start < Start && O.End >= Start && O.End <= End) {
      return {OverlapKind_t::BeforeStart, {Start, O.End}};
    }

    //
    // [-<-->--------]
    //

    if (O.Start >= Start && O.End <= End) {
      return {OverlapKind_t::AfterStartBeforeEnd, {O.Start, O.End}};
    }

    //
    // [-------<---]-------->
    //

    if (O.Start >= Start && O.Start <= End && O.End > End) {
      return {OverlapKind_t::AfterEnd, {O.Start, End}};
    }

    //
    // <---[----------]--->
    //

    if (O.Start <= Start && O.End >= End) {
      return {OverlapKind_t::BeforeStartAfterEnd, {Start, End}};
    }

    return {OverlapKind_t::No, {}};
  }
};

//
// Ghetto interval tree.
//

class Ranges_t {
private:
  std::vector<Range_t> Ranges_;

public:
  auto begin() const { return Ranges_.begin(); }
  auto end() const { return Ranges_.end(); }

  Ranges_t Overlaps(const Ranges_t &Others) const {
    Ranges_t OverlappingRanges;
    for (const auto &Range : Ranges_) {
      for (const auto &Other : Others) {
        const auto &[Kind, OverlappingRange] = Range.Overlaps(Other);
        if (Kind != OverlapKind_t::No) {
          OverlappingRanges.Add(OverlappingRange);
        }
      }
    }

    return OverlappingRanges;
  }

  Ranges_t Overlaps(const Range_t &Other) const {
    Ranges_t OverlappingRanges;
    for (const auto &Range : Ranges_) {
      const auto &[Kind, OverlappingRange] = Range.Overlaps(Other);
      if (Kind != OverlapKind_t::No) {
        OverlappingRanges.Ranges_.push_back(OverlappingRange);
      }
    }

    return OverlappingRanges;
  }

  void Add(const Ranges_t &Ranges) {
    for (const auto &Range : Ranges) {
      Add(Range.Start, Range.End);
    }
  }

  void Add(const Range_t &O) { Add(O.Start, O.End); }

  void Add(const uint64_t Start, const uint64_t End) {
    assert(End > Start);
    Range_t New(Start, End);
    std::vector<Range_t> NewRanges;
    bool Inserted = false;
    for (const auto &Range : Ranges_) {
      if (New.Start > Range.End) {

        //
        // If the current interval is bigger than the candidate, we still need
        // to figure out where to add it.
        //

        NewRanges.push_back(Range);
      } else if (New.End < Range.Start) {

        //
        // The intervals are ordered from low to high; if the end of the new
        // interval is before the candidate, we found a spot where to insert it
        // (unless we already did that).
        //

        if (!Inserted) {

          //
          // Let's insert the interval.
          //

          NewRanges.push_back(New);
          Inserted = true;
        }

        //
        // Don't forget to insert the current candidate as well (we know they
        // don't overlap)
        //

        NewRanges.push_back(Range);
      } else {

        //
        // If the current interval overlaps with the candidate, merge them in.
        //

        New.Start = std::min(New.Start, Range.Start);
        New.End = std::max(New.End, Range.End);
      }
    }

    //
    // If we got here before inserting the candidate, do it now.
    //

    if (!Inserted) {
      NewRanges.push_back(New);
    }

    //
    // Update our internal set.
    //

    Ranges_ = std::move(NewRanges);
  }
};

struct BytesHuman_t {
  double Value;
  const char *Unit;
};

template <> struct fmt::formatter<BytesHuman_t> : fmt::formatter<std::string> {
  template <typename FormatContext>
  auto format(const BytesHuman_t &Bytes, FormatContext &Ctx) const {
    return fmt::format_to(Ctx.out(), "{:.1f}{}", Bytes.Value, Bytes.Unit);
  }
};

template <> struct fmt::formatter<Range_t> : fmt::formatter<std::string> {
  template <typename FormatContext>
  auto format(const Range_t &R, FormatContext &Ctx) const {
    return fmt::format_to(Ctx.out(), "[{:x}, {:x}(", R.Start, R.End);
  }
};

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

//
// Utility that is used to print bytes for human.
//

[[nodiscard]] BytesHuman_t BytesToHuman(const uint64_t Bytes_) {
  const char *Unit = "b";
  double Bytes = double(Bytes_);
  const uint64_t K = 1'024;
  const uint64_t M = K * K;
  const uint64_t G = M * K;
  if (Bytes >= G) {
    Unit = "gb";
    Bytes /= G;
  } else if (Bytes >= M) {
    Unit = "mb";
    Bytes /= M;
  } else if (Bytes >= K) {
    Unit = "kb";
    Bytes /= K;
  }

  return {Bytes, Unit};
}

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
      fmt::print("The range %s is malformed, bailing\n", Token);
      return {};
    }

    const auto CorrectMode = Mode == '-' || Mode == '+';
    if (!CorrectMode) {
      fmt::print("The range %s uses an unknown mode, bailing\n", Token);
      return {};
    }

    //
    // If + is used, End is actually a size, not an address; so calculate it.
    //

    if (Mode == '+') {
      End += Start;
    }

    //
    // Verify that the range is sane.
    //

    if (Start >= End) {
      fmt::print("The range {} is malformed, bailing\n", Token);
      return {};
    }

    //
    // Check if the start is page aligned.
    //

    if ((Start & 0xf'ff) != 0) {
      fmt::print("The range start {:x} is not page aligned, bailing\n", Start);
      return {};
    }

    //
    // Check that the range is page aligned.
    //

    const uint64_t Size = End - Start;
    if ((Size & 0xf'ff) != 0) {
      fmt::print("The range size {:x} is not page aligned, bailing\n", Size);
      return {};
    }

    //
    // All right, we have a range!
    //

    Ranges.Add(Start, End);
  }

  return Ranges;
}

[[nodiscard]] bool GrownAndLockInWorkingSet(const HANDLE Process,
                                            const auto &Range) {
  const NTSTATUS STATUS_WORKING_SET_QUOTA = 0xc000'00a1;
  const uint32_t MAP_PROCESS = 1;
  auto BaseAddress = PVOID(Range.Start);
  SIZE_T RegionSize = Range.Size();
  for (size_t Tries = 0; Tries < 10; Tries++) {
    const NTSTATUS Status =
        NtLockVirtualMemory(Process, &BaseAddress, &RegionSize, MAP_PROCESS);

    if (NT_SUCCESS(Status)) {
      return true;
    }

    if (Status != STATUS_WORKING_SET_QUOTA) {
      fmt::print("NtLockVirtualMemory failed w/ {} for {}, bailing\n", Status,
                 BaseAddress);
      return false;
    }

    SIZE_T MinimumWorkingSetSize = 0;
    SIZE_T MaximumWorkingSetSize = 0;
    DWORD Flags;

    if (!GetProcessWorkingSetSizeEx(Process, &MinimumWorkingSetSize,
                                    &MaximumWorkingSetSize, &Flags)) {
      fmt::print("GetProcessWorkingSetSizeEx failed w/ GLE={}, bailing\n",
                 GetLastError());
      return false;
    }

    MaximumWorkingSetSize *= 2;
    MinimumWorkingSetSize *= 2;

    dbgprint("Growing working set to {}..\n",
             BytesToHuman(MinimumWorkingSetSize));

    Flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;

    if (!SetProcessWorkingSetSizeEx(Process, MinimumWorkingSetSize,
                                    MaximumWorkingSetSize, Flags)) {
      fmt::print("SetProcessWorkingSetSizeEx failed w/ GLE={}, bailing\n",
                 GetLastError());
      return false;
    }
  }

  fmt::print("Ran out of tries to grow the working set\n");
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
      fmt::print("There are several instances of {}, pid {} will be used\n",
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
    fmt::print("ReadProcessMemory failed w/ GLE={}, bailing\n", GetLastError());
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
    fmt::print("OpenThread failed w/ GLE={}, bailing\n", GetLastError());
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
    fmt::print("NtQueryInformationThread failed w/ {}, bailing\n", Status);
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
    fmt::print("VirtRead failed, bailing\n");
    return {};
  }

  Ranges_t StackRanges;
#ifdef _WIN64
  assert(Tib._64.StackLimit < Tib._64.StackBase && Tib._64.StackBase > 0);
  if ((Tib._64.StackLimit & 0xf'ff) != 0 || (Tib._64.StackBase & 0xf'ff) != 0) {
    fmt::print("TIB64 is not page aligned, bailing\n");
    return {};
  }

  StackRanges.Add(Tib._64.StackLimit, Tib._64.StackBase);
#else
  assert(Tib._32.StackLimit < Tib._32.StackBase && Tib._32.StackBase > 0);
  if ((Tib._32.StackLimit & 0xf'ff) != 0 || (Tib._32.StackBase & 0xf'ff) != 0) {
    fmt::print("TIB32 is not page aligned, bailing\n");
    return {};
  }

  StackRanges.Add(Tib._32.StackLimit, Tib._32.StackBase);
#endif

#ifdef _WIN64
  uint16_t ProcessMachine = 0, NativeMachine = 0;
  if (!IsWow64Process2(Process, &ProcessMachine, &NativeMachine)) {
    fmt::print("IsWow64Process2 failed w/ GLE={}, bailing\n", GetLastError());
    return {};
  }

  if (NativeMachine != IMAGE_FILE_MACHINE_AMD64) {
    fmt::print("NativeMachine has an unexpected value {:x}, bailing\n",
               NativeMachine);
    return {};
  }

  if (ProcessMachine != IMAGE_FILE_MACHINE_I386) {
    return StackRanges;
  }

  if (!VirtRead(Tib._64.ExceptionList, Tib, Process)) {
    fmt::print("VirtRead failed, bailing\n");
    return {};
  }

  assert(Tib._32.StackLimit < Tib._32.StackBase && Tib._32.StackBase);
  if ((Tib._32.StackLimit & 0xf'ff) != 0 || (Tib._32.StackBase & 0xf'ff) != 0) {
    fmt::print("TIBWOW6432 is not page aligned, bailing\n");
    return {};
  }

  StackRanges.Add(Tib._32.StackLimit, Tib._32.StackBase);
#endif

  return StackRanges;
}

[[nodiscard]] std::optional<Ranges_t> GetStackRanges(const HANDLE Process,
                                                     const uint32_t Pid) {
  Ranges_t Stacks;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (Snapshot == INVALID_HANDLE_VALUE) {
    fmt::print("CreateToolhelp32Snapshot failed w/ GLE={}, bailing\n",
               GetLastError());
    return {};
  }

  const auto &CloseSnapshot = finally([&] { CloseHandle(Snapshot); });

  THREADENTRY32 Entry = {};
  Entry.dwSize = sizeof(Entry);
  if (!Thread32First(Snapshot, &Entry)) {
    fmt::print("Thread32First failed w/ GLE={}, bailing\n", GetLastError());
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
      fmt::print("GetStackRange failed for TID {}, bailing\n",
                 Entry.th32ThreadID);
      return {};
    }

    for (const auto &Range : *Ranges) {
      dbgprint("TID {} Stack Range: {}\n", Entry.th32ThreadID, Range);
      Stacks.Add(Range);
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
        fmt::print("--ranges expect to be followed by an argument\n");
        return EXIT_FAILURE;
      }

      Opts.Ranges = ParseRanges(Next);
      if (!Opts.Ranges) {
        fmt::print("ParseRanges failed, exiting\n");
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
    fmt::print(
        "./lockmem [--ranges 0-0x1000,0x2000+0x1000,..] [--stacks] <process "
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
      fmt::print("Name2Pid failed, exiting\n");
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
    fmt::print("OpenProcess {} failed w/ GLE={}, exiting\n", Argv[1],
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
      fmt::print("GetStacks failed, exiting\n");
      return EXIT_FAILURE;
    }
  }

  //
  // If we have a range filter, bring it in as well.
  //

  if (Opts.Ranges) {

    //
    // If we already have ranges defined in it, then we need to find the
    // overlapping ranges.
    //

    if (AllowRanges) {
      auto OverlappingRanges = AllowRanges->Overlaps(*Opts.Ranges);
      AllowRanges = std::move(OverlappingRanges);
      AllowRanges->Add(*Opts.Ranges);
    } else {
      AllowRanges = *Opts.Ranges;
    }
  }

  //
  // Iterate through memory ranges of the process.
  //

  fmt::print("Got a handle on PID {}\n", ProcessId);
  MEMORY_BASIC_INFORMATION MemoryInfo;
  uint64_t LockedAmount = 0;
  for (uint8_t *Address = nullptr;
       VirtualQueryEx(Process, Address, &MemoryInfo, sizeof(MemoryInfo));
       Address = (uint8_t *)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) {

    //
    // If this is a page guard, or a no access page; let's ignore it.
    //

    const auto BaseAddress = MemoryInfo.BaseAddress;
    const auto RegionSize = MemoryInfo.RegionSize;
    const Range_t RegionRange(uint64_t(BaseAddress),
                              uint64_t(BaseAddress) + RegionSize);
    const uint32_t BadProtectBits = PAGE_GUARD | PAGE_NOACCESS;
    if (MemoryInfo.Protect & BadProtectBits) {
      dbgprint("Skipping {} because of protect bad bits..\n", RegionRange);
      continue;
    }

    //
    // If the page is reserved or freed, let's ignore it.
    //

    const uint32_t BadStatetBits = MEM_FREE | MEM_RESERVE;
    if (MemoryInfo.State & BadStatetBits) {
      dbgprint("Skipping {} because of state bad bits..\n", RegionRange);
      continue;
    }

    //
    // Check if the region overlaps with a filter.
    //

    Ranges_t OverlappingRanges;
    if (AllowRanges) {

      //
      // If we have range filters, calculate the overlapping ranges.
      //

      OverlappingRanges = AllowRanges->Overlaps(RegionRange);
    } else {

      //
      // If we don't, oh well, let's use the entire region as is!
      //

      OverlappingRanges.Add(RegionRange);
    }

    //
    // Walk the overlapping ranges to lock them in.
    //

    for (const auto &OverlappingRange : OverlappingRanges) {

      //
      // Extend the WS if needed, and lock the region in.
      //

      if (!GrownAndLockInWorkingSet(Process, OverlappingRange)) {
        fmt::print("GrownAndLockInWorkingSet failed, bailing\n");
        return EXIT_FAILURE;
      }

      LockedAmount += OverlappingRange.Size();

      //
      // Do our best to overwrite the previous line we displayed..
      //

      fmt::print("\33[2K\rLocked {}: {}..", BytesToHuman(LockedAmount),
                 OverlappingRange);
    }
  }

  //
  // OK we're done.
  //

  fmt::print("\nDone, locked {}!\n", BytesToHuman(LockedAmount));
  return EXIT_SUCCESS;
}