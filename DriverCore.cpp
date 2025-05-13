#include "DriverCore.h"


//auto DriverUnload(PDRIVER_OBJECT DriverObject) -> void
//{
//    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Driver unloading\n");
//}

auto DriverEntry(PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath) -> NTSTATUS
{
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    //pDriverObject->DriverUnload = DriverUnload;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DriverEntry called\n");
    return STATUS_SUCCESS;
}