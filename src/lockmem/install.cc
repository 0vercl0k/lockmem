// Axel '0vercl0k' Souchet - February 22 2020
#include "install.h"
#include <filesystem>

namespace fs = std::filesystem;

//
// Ghetto version of base::win::ScopedHandle:
// https://cs.chromium.org/chromium/buildtools/gn/src/base/win/scoped_handle.h
//

template <typename HandleTy, typename DeleterTy> class Scoped_t {
private:
  HandleTy Handle_;

public:
  Scoped_t(const HandleTy Handle) : Handle_(Handle) {}

  //
  // Rule of three.
  //

  ~Scoped_t() { Close(); }
  Scoped_t(const Scoped_t &) = delete;
  Scoped_t &operator=(const Scoped_t &) = delete;

  bool IsHandleValid(const HandleTy Handle) const {
    return Handle != HandleTy(-1) && Handle != nullptr;
  }

  void Close() {
    if (IsHandleValid(Handle_)) {
      DeleterTy::Close(Handle_);
      Handle_ = nullptr;
    }
  }

  bool Valid() const { return IsHandleValid(Handle_); }

  operator HandleTy() const { return Handle_; }
};

struct HandleDeleter_t {
  static void Close(const HANDLE Handle) { CloseHandle(Handle); }
};

struct ServiceHandleDeleter_t {
  static void Close(const SC_HANDLE &Handle) { CloseServiceHandle(Handle); };
};

//
// Handy types for cleaning up the code.
//

using ScopedHandle_t = Scoped_t<HANDLE, HandleDeleter_t>;
using ScopedServiceHandle_t = Scoped_t<SC_HANDLE, ServiceHandleDeleter_t>;

bool InstallDriver(const char *ServiceName, const char *ServiceDisplayName,
                   const char *ServiceFilename) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (Scm == nullptr) {
    return false;
  }

  const fs::path Path = fs::current_path() / ServiceFilename;
  if (!fs::exists(Path)) {
    printf("%s does not exist, exiting\n", Path.string().c_str());
    return false;
  }

  const ScopedServiceHandle_t Service = CreateServiceA(
      Scm, ServiceName, ServiceDisplayName, 0, SERVICE_KERNEL_DRIVER,
      SERVICE_DEMAND_START, SERVICE_ERROR_SEVERE, Path.string().c_str(),
      nullptr, nullptr, nullptr, nullptr, nullptr);

  if (Service != nullptr) {
    return true;
  }

  const bool AlreadyExists = GetLastError() == ERROR_SERVICE_EXISTS;
  return AlreadyExists;
}

bool StartDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service =
      OpenService(Scm, ServiceName, SERVICE_START);

  if (Service == nullptr) {
    return false;
  }

  const BOOL Success = StartService(Service, 0, nullptr);
  return Success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service =
      OpenService(Scm, ServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);

  if (Service == nullptr) {
    return false;
  }

  SERVICE_STATUS_PROCESS Status;
  static_assert(sizeof(Status) > sizeof(SERVICE_STATUS));
  static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwCurrentState) ==
                FIELD_OFFSET(SERVICE_STATUS, dwCurrentState));
  static_assert(FIELD_OFFSET(SERVICE_STATUS_PROCESS, dwWaitHint) ==
                FIELD_OFFSET(SERVICE_STATUS, dwWaitHint));

  BOOL Success =
      ControlService(Service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&Status);
  while (Success && Status.dwCurrentState != SERVICE_STOPPED) {
    printf("Waiting for %u..\n", Status.dwWaitHint);
    Sleep(Status.dwWaitHint);
    DWORD BytesNeeded;
    Success =
        QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&Status,
                             sizeof(Status), &BytesNeeded);
    printf("Success: %d, dwCurrentState: %u..\n", Success, Status.dwCurrentState);
  }

  return Success && Status.dwCurrentState == SERVICE_STOPPED;
}

bool RemoveDriver(const char *ServiceName) {
  const ScopedServiceHandle_t Scm =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

  if (Scm == nullptr) {
    return false;
  }

  const ScopedServiceHandle_t Service = OpenService(Scm, ServiceName, DELETE);

  if (Service == nullptr) {
    return false;
  }

  const bool Success = DeleteService(Service);
  return Success;
}
