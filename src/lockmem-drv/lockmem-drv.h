// Axel '0vercl0k' Souchet - February 6 2021
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <ntifs.h>
#include <ntintsafe.h>
#include "..\common\common.h"

#if defined(_M_ARM) || defined(_M_ARM64)
#    error "ARM platforms are not supported."
#endif

//
// Undocumented?
//

extern NTSTATUS
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_opt_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

extern NTSTATUS
ObOpenObjectByName(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PHANDLE Handle);

extern POBJECT_TYPE *IoDriverObjectType;

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_SECTION_HEADER
{
    BYTE Name[8];
    union
    {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

#ifdef _WIN64
typedef struct _IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
#else
typedef struct _IMAGE_NT_HEADERS IMAGE_NT_HEADERS;
#endif

//
// Declare functions.
//

_Function_class_(DRIVER_INITIALIZE) _IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING);

_Function_class_(DRIVER_UNLOAD) _IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_ VOID
LckDriverUnload(_In_ PDRIVER_OBJECT);

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_ NTSTATUS
LckCreateClose(_In_ PDEVICE_OBJECT, _Inout_ PIRP);

_Function_class_(DRIVER_DISPATCH) _IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_ NTSTATUS
LckDispatchDeviceControl(_In_ PDEVICE_OBJECT, _Inout_ PIRP);

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckForcePagingInDrivers();

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckForcePagingIn(_In_ PVOID, _In_ ULONG, _Inout_opt_ PVOID);

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckHandleEntry(_In_ HANDLE, _In_ POBJECT_DIRECTORY_INFORMATION, _Inout_opt_ PVOID);

typedef NTSTATUS (*DIRECTORY_CALLBACK)(_In_ HANDLE, _In_ POBJECT_DIRECTORY_INFORMATION, _Inout_opt_ PVOID);

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckWalkDirectoryEntries(_In_ HANDLE, _In_ DIRECTORY_CALLBACK, _Inout_opt_ PVOID);

//
// Our code doesn't need to be allocated in non-paged memory.
// There is no functions running above APC_LEVEL as a result page faults
// are allowed.
// DriverEntry is in the INIT segment which gets discarded once the driver
// as been initialized.
//

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DriverEntry)
#    pragma alloc_text(PAGE, LckDriverUnload)
#    pragma alloc_text(PAGE, LckCreateClose)
#    pragma alloc_text(PAGE, LckDispatchDeviceControl)
#    pragma alloc_text(PAGE, LckForcePagingInDrivers)
#    pragma alloc_text(PAGE, LckForcePagingIn)
#    pragma alloc_text(PAGE, LckHandleEntry)
#    pragma alloc_text(PAGE, LckWalkDirectoryEntries)
#endif

//
// LCK pool tags.
//

#define LCK_TAG ' Lck'
#define LCK_TAG_NODE 'NkcL'
#define LCK_TAG_ODI 'OkcL'

//
// Device and symbolic link name.
//

#define LCK_NT_DEVICE_NAME L"\\Device\\" LCK_DEVICE_NAME
#define LCK_DOS_DEVICE_NAME L"\\DosDevices\\" LCK_DEVICE_NAME

#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000