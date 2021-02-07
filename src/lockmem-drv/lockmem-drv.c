// Axel '0vercl0k' Souchet - February 6 2021
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <ntifs.h>
#include <ntintsafe.h>

//
// Turn on debug outputs:
// ed nt!Kd_DEFAULT_MASK ffffffff
//

//
// Endless source of inspiration:
//   - ProcessHacker's source code.
//

#if defined(_M_ARM) || defined(_M_ARM64)
#    error "ARM platforms are not supported."
#endif

extern NTSTATUS
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_opt_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

//
// Declare functions.
//

_Function_class_(DRIVER_INITIALIZE) _IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING);

_Function_class_(DRIVER_UNLOAD) _IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_ VOID
LckDriverUnload(_In_ PDRIVER_OBJECT);

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckDoWork();

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckHandleEntry(_In_ POBJECT_DIRECTORY_INFORMATION, _Maybenull_ _Inout_ PVOID);

typedef NTSTATUS (*DIRECTORY_CALLBACK)(_In_ POBJECT_DIRECTORY_INFORMATION, _Maybenull_ _Inout_ PVOID);

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckWalkDirectoryEntries(_In_ HANDLE, _In_ DIRECTORY_CALLBACK, _Maybenull_ _Inout_ PVOID);

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
#    pragma alloc_text(PAGE, LckDoWork)
#    pragma alloc_text(PAGE, LckHandleEntry)
#    pragma alloc_text(PAGE, LckWalkDirectoryEntries)
#endif

#define LCK_TAG ' kcL'

_Function_class_(DRIVER_UNLOAD) _IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_ VOID
LckDriverUnload(_In_ PDRIVER_OBJECT DriverObject)

/*++

Routine Description:

    Unloads the driver. Pretty much empty for now.

Arguments:

    DriverObject - The driver object getting unloaded.

Return Value:

    None.

--*/

{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();
}

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckWalkDirectoryEntries(
    _In_ HANDLE DirectoryHandle,
    _In_ DIRECTORY_CALLBACK Callback,
    _Maybenull_ _Inout_ PVOID Context)

/*++

Routine Description:

    Query a directory and walk through every entries.
    Invoke a user-provided callback on each of those entries.

Arguments:

    DirectoryHande - Handle to the directory that needs to be walked.

    Callback - User provided callback that gets invoked on every entry.

    Context - User provided pointer that gets passed to the Callback.

Return Value:

    Status.

--*/

{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Length = sizeof(OBJECT_DIRECTORY_INFORMATION);
    ULONG ReturnedLength = 0;
    ULONG EnumerationContext = 0;
    POBJECT_DIRECTORY_INFORMATION ObjectDirectoryInformation = NULL;
    BOOLEAN FirstTime = TRUE;

    PAGED_CODE();

    NT_ASSERT(DirectoryHandle != NULL);
    NT_ASSERT(Callback != NULL);

    //
    // Let's get to work.
    //

    while (TRUE)
    {
        //
        // Query the directory.
        //

        Status = ZwQueryDirectoryObject(
            DirectoryHandle,
            ObjectDirectoryInformation,
            Length,
            FALSE,
            FirstTime,
            &EnumerationContext,
            &ReturnedLength);

        //
        // If the call fail we bail.
        //

        if (!NT_SUCCESS(Status))
        {
            KdPrint(("ZwQueryDirectoryObject failed with %08x\n", Status));
            break;
        }

        //
        // If the call is not STATUS_MORE_ENTRIES, it means we are done.
        //

        if (Status != STATUS_MORE_ENTRIES)
        {
            KdPrint(("Done enumerating\n"));
            break;
        }

        //
        // Keep iterating, don't restart the scanning.
        //

        FirstTime = FALSE;

        //
        // Check if we managed to get at least one entry.
        // Either, we haven't allocated ObjectDirectoryInformation yet, or we have
        //
        //

        const BOOLEAN EmptyBuffer =
            ObjectDirectoryInformation == NULL ||
            (ObjectDirectoryInformation->Name.Buffer == NULL && ObjectDirectoryInformation->Name.Length == 0);

        //
        // If we have an empty buffer it is because the buffer is not big enough to back the request, so double its
        // size.
        //

        if (EmptyBuffer)
        {
            //
            // Free the buffer if we have allocated one yet.
            //

            if (ObjectDirectoryInformation != NULL)
            {
                ExFreePoolWithTag(ObjectDirectoryInformation, LCK_TAG);
            }

            //
            // Double the size of the buffer, and allocate memory.
            //

            Length *= 2;
            ObjectDirectoryInformation = ExAllocatePoolWithTag(PagedPool, Length, LCK_TAG);
            if (ObjectDirectoryInformation == NULL)
            {
                KdPrint(("ExAllocatePoolWithTag failed for enumeration\n"));
                break;
            }

            //
            // Initialize memory.
            //

            memset(ObjectDirectoryInformation, 0, Length);
        }

        //
        // Invoke the user provided callback.
        //

        POBJECT_DIRECTORY_INFORMATION Entry = ObjectDirectoryInformation;
        while (Entry->Name.Length > 0)
        {
            Status = Callback(Entry, Context);
            if (!NT_SUCCESS(Status))
            {
                KdPrint(("Callback failed with %08x\n", Status));
                break;
            }

            //
            // Go to the next entry.
            //

            Entry++;
        }
    }

    //
    // Clean up after ourselves.
    //

    if (ObjectDirectoryInformation != NULL)
    {
        ExFreePoolWithTag(ObjectDirectoryInformation, LCK_TAG);
        ObjectDirectoryInformation = NULL;
    }

    return Status;
}

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckHandleEntry(_In_ POBJECT_DIRECTORY_INFORMATION ObjectDirectoryInfo, _Maybenull_ _Inout_ PVOID Context)

/*++

Routine Description:

    Handle an entry.

Arguments:

    Entry - Pointer to the current entry.

    Context - Context pointer.

Return Value:

    Status.

--*/

{
    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    KdPrint(("Received %wZ\n", ObjectDirectoryInfo->Name));
    return STATUS_SUCCESS;
}

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckDoWork()

/*++

Routine Description:

    Do the work.

Arguments:

    None.

Return Value:

    Status.

--*/

{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE DirectoryHandle = NULL;
    const UNICODE_STRING DirectoryName = RTL_CONSTANT_STRING(L"\\Driver");
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DirectoryName, OBJ_KERNEL_HANDLE);

    PAGED_CODE();

    //
    // Open a handle to the \Driver directory.
    //

    Status = ZwOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        KdPrint(("ZwOpenDirectoryObject failed with %08x\n", Status));
        goto clean;
    }

    Status = LckWalkDirectoryEntries(DirectoryHandle, LckHandleEntry, NULL);

clean:
    if (DirectoryHandle != NULL)
    {
        ZwClose(DirectoryHandle);
        DirectoryHandle = NULL;
    }

    return Status;
}

_Function_class_(DRIVER_INITIALIZE) _IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)

/*++

Routine Description:

    This is the main of the driver.

Arguments:

    DriverObject - Pointer to the driver object.

    RegistryPath - According to MSDN:
    """
    A pointer to a UNICODE_STRING structure that
    specifies the path to the driver's Parameters
    key in the registry.
    """

Return Value:

    STATUS_SUCCESS if successful or STATUS_* otherwise.

--*/

{
    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    //
    // Get support for both pool zeroing and default nx pool.
    //

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Fill in the callbacks.
    //

    DriverObject->DriverUnload = LckDriverUnload;

    LckDoWork();
    return STATUS_FAILED_DRIVER_ENTRY;
}
