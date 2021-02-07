// Axel '0vercl0k' Souchet - February 6 2021
#include "lockmem-drv.h"

//
// Turn on debug outputs:
// ed nt!Kd_DEFAULT_MASK ffffffff
//

//
// Endless source of inspiration:
//   - ProcessHacker's source code.
//

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
LckWalkDirectoryEntries(_In_ HANDLE DirectoryHandle, _In_ DIRECTORY_CALLBACK Callback, _Inout_opt_ PVOID Context)

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
            Status = Callback(DirectoryHandle, Entry, Context);
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
LckForcePagingIn(_In_ PVOID ImageBase, _In_ ULONG ImageSize)

/*++

Routine Description:

    Force paging in of a driver.

Arguments:

    ImageBase - Base address of the driver.

    ImageSize - Size of the driver.

Return Value:

    Status.

--*/

{
    UNREFERENCED_PARAMETER(ImageSize);
    NTSTATUS Status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_SECTION_HEADER SectionHeaders = NULL;

    PAGED_CODE();

    //
    // Do the PE dance.
    //

    DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + DosHeader->e_lfanew);
    SectionHeaders = (PIMAGE_SECTION_HEADER)(
        (PUCHAR)NtHeaders + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Walk through the sections.
    //

    for (ULONG Idx = 0; Idx < NtHeaders->FileHeader.NumberOfSections; Idx++)
    {
        KdPrint(("  Section %x - %x\n", Idx, SectionHeaders[Idx].VirtualAddress));
    }

    return Status;
}

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
LckHandleEntry(
    _In_ HANDLE DirectoryHandle,
    _In_ POBJECT_DIRECTORY_INFORMATION ObjectDirectoryInfo,
    _Inout_opt_ PVOID Context)

/*++

Routine Description:

    Handle an entry.

Arguments:

    DirectoryHandle - Handle to the directory the entries are in.

    ObjectDirectoryInfo - Information related to an entry in \Driver.

    Context - Context pointer.

Return Value:

    Status.

--*/

{
    UNREFERENCED_PARAMETER(Context);
    const UNICODE_STRING Driver = RTL_CONSTANT_STRING(L"Driver");
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE DriverHandle = NULL;
    PDRIVER_OBJECT DriverObject = NULL;

    PAGED_CODE();

    InitializeObjectAttributes(
        &ObjectAttributes, &ObjectDirectoryInfo->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, DirectoryHandle, NULL);

    //
    // If the TypeName doesn't say it is a 'Driver' we skip it because it is unexpected.
    //

    if (RtlCompareUnicodeString(&Driver, &ObjectDirectoryInfo->TypeName, FALSE) != 0)
    {
        KdPrint(("Skipping %wZ because it is not a Driver", ObjectDirectoryInfo->Name));
        goto clean;
    }

    //
    // Open the driver by name to get a handle.
    //

    KdPrint(("Received %wZ\n", ObjectDirectoryInfo->Name));
    Status = ObOpenObjectByName(&ObjectAttributes, *IoDriverObjectType, KernelMode, NULL, 0, NULL, &DriverHandle);

    if (!NT_SUCCESS(Status))
    {
        KdPrint(("ObOpenObjectByName failed with %08x\n", Status));
        goto clean;
    }

    //
    // Get a pointer off the handle.
    //

    Status = ObReferenceObjectByHandleWithTag(
        DriverHandle, 0, *IoDriverObjectType, KernelMode, LCK_TAG, &DriverObject, NULL);

    if (!NT_SUCCESS(Status))
    {
        KdPrint(("ObReferenceObjectByHandleWithTag failed with %08x\n", Status));
        goto clean;
    }

    //
    // Force page-in the driver.
    //

    KdPrint(("%wZ starts @ %p\n", ObjectDirectoryInfo->Name, DriverObject->DriverStart));
    Status = LckForcePagingIn(DriverObject->DriverStart, DriverObject->DriverSize);

    if (!NT_SUCCESS(Status))
    {
        KdPrint(("LckForcePagingIn failed with %08x\n", Status));
        goto clean;
    }

clean:
    if (DriverObject != NULL)
    {
        ObDereferenceObjectWithTag(DriverObject, LCK_TAG);
        DriverObject = NULL;
    }

    if (DriverHandle != NULL)
    {
        ZwClose(DriverHandle);
        DriverHandle = NULL;
    }

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
    OBJECT_ATTRIBUTES ObjectAttributes =
        RTL_CONSTANT_OBJECT_ATTRIBUTES(&DirectoryName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

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

    //
    // Walk the directory and handle every entries in a custom callback.
    //

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
