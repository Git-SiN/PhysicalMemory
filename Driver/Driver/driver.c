#include "../../Headers/driver.h"


VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(101, 0, "Driver Unloaded...\n");
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
		
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING regPath) {
	ULONG i = 0;
	
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DispatchRoutine;

	pDriverObject->DriverUnload = DriverUnload;

	DbgPrintEx(101, 0, "Driver loaded...\n");
	return STATUS_SUCCESS;
}