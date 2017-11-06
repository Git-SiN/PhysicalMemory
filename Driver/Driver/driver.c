#include "../../Headers/driver.h"

//////////////////////////////////////////////////////////////////////////////////
//////////////////////		HARDCODING for test		//////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
#define MEMORY_SIZE						4							// GB
#define TARGET_EPROCESS					0x85a60030              		// for test
//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////

typedef struct _BACKUP_INFORMATION {
	ULONG BackedEprocess;
	ULONG BackedCR3;
	ULONG BackedEthread;
} BACKUP_INFORMATION, *PBACKUP_INFORMATION;

PBACKUP_INFORMATION pBackup = NULL;

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

NTSTATUS ManipulateForSniffing(ULONG targetEprocess) {
	ULONG targetPDT = 0;
	ULONG backedEprocess = 0;
	ULONG backedCR3 = 0;
	ULONG backedEthread = 0;

	if ((pBackup == NULL) && (targetEprocess >= 0x80000000) && (*(PUCHAR)(targetEprocess - 0xC) == 0x7)) {		
		__try {
			targetPDT = *(PULONG)(targetEprocess + KPROC_OFFSET_DirectoryTableBase);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Can't find the PDT...\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		DbgPrintEx(101, 0, "[ERROR] Invalid EPROCESS...\n");
		return STATUS_UNSUCCESSFUL;
	}
		
	pBackup = ExAllocatePool(NonPagedPool, sizeof(BACKUP_INFORMATION));
	if (pBackup == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to AllocatePool...\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(pBackup, sizeof(BACKUP_INFORMATION));

	// Backup & Manipulation 
	__try {
		__asm {
			push eax;
			push ebx;

			/////////////////////		Backup		/////////////////////
			mov eax, cr3;
			mov backedCR3, eax;					// current Thread's PDT

			mov eax, fs:0x124;					// current Thread's ETHREAD
			mov backedEthread, eax;

			add eax, KTHREAD_OFFSET_KPROCESS;
			mov ebx, [eax];						// current Thread's EPROCESS
			mov backedEprocess, ebx;


			/////////////////////		Manipulation		/////////////////////
			mov dword ptr ds:[eax], TARGET_EPROCESS;

			mov ebx, targetPDT;
			mov cr3, ebx;

			pop ebx;
			pop eax;

		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to manipulate...\n");
		ExFreePool(pBackup);
		pBackup = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	pBackup->BackedEprocess = backedEprocess;
	pBackup->BackedCR3 = backedCR3;
	pBackup->BackedEthread = backedEthread;
	
	DbgPrintEx(101, 0, "Succeeded to manipulate...\n");
	return STATUS_SUCCESS;
}


VOID RestoreManipulation()
{
	ULONG backedCR3 = 0;
	ULONG backedEthread = 0;

	if (pBackup == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Not Manipulated...\n");
		return;
	}

	backedCR3 = pBackup->BackedCR3;
	backedEthread = pBackup->BackedEthread;
	
	// RESTORE CR3...
	__try {
		__asm {
			push eax;
			push ebx;

			// Restore the CR3 when the backup thread is running.
			mov eax, fs:0x124;
			mov ebx, backedEthread;

			cmp eax, ebx;
			jne NORESTORE;

			mov ebx, backedCR3;
			mov cr3, ebx;

		NORESTORE:
			pop ebx;
			pop eax;

		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to restore CR3...\n");
	}

	// RESTORE EPROCESS in ETHREAD
	*(PULONG)(backedEthread + KTHREAD_OFFSET_KPROCESS) = pBackup->BackedEprocess;

	ExFreePool(pBackup);
	pBackup = NULL;

	DbgPrintEx(101, 0, "Succeeded to restore...\n");
	return;
}

VOID DumpPhysicalMemory(ULONG targetEprocess, ULONG CountOfPageFrame) {
	PHYSICAL_ADDRESS pa;
	ULONG i = 0;
	ULONG virtualAddress = 0;
	PULONG myAddress = NULL;
	PULONG targetAddress = NULL;


	myAddress = ExAllocatePool(NonPagedPool, CountOfPageFrame * 4);
	if (myAddress == NULL)
		return;

	targetAddress = ExAllocatePool(NonPagedPool, CountOfPageFrame * 4);
	if (targetAddress == NULL) {
		ExFreePool(myAddress);
		return;
	}

	RtlZeroMemory(myAddress, CountOfPageFrame * 4);
	RtlZeroMemory(targetAddress, CountOfPageFrame * 4);
	////////////////////////////////////////////////////////////////////////////////////////

	for (i = 0; i < CountOfPageFrame; i++) {
		pa.QuadPart = (i << 12);
		__try {
			virtualAddress = (ULONG)MmGetVirtualForPhysical(pa);
			//	DbgPrintEx(101, 0, "PA : [%06X000]     at 0x%08X\n", i, virtualAddress);
			myAddress[i] = virtualAddress;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "PA : [%06X000]       Exception occured...\n", i);
		}
	}

	// Examine at the target side...
	if (!NT_SUCCESS(ManipulateForSniffing(targetEprocess))) {
		ExFreePool(myAddress);
		ExFreePool(targetAddress);
		return;
	}
	
	for (i = 0; i < CountOfPageFrame; i++) {
		pa.QuadPart = (i << 12);
		__try {
			virtualAddress = (ULONG)MmGetVirtualForPhysical(pa);
			//	DbgPrintEx(101, 0, "PA : [%06X000]     at 0x%08X\n", i, virtualAddress);
			targetAddress[i] = virtualAddress;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "PA : [%06X000]       Exception occured...\n", i);
		}
	}

	RestoreManipulation();
	
	// Output...
	for (i = 0; i < CountOfPageFrame; i++) {
		DbgPrintEx(101, 0, "PA : [%06X000]     %08X     %08X\n", i, myAddress[i], targetAddress[i]);
	}


	ExFreePool(myAddress);
	ExFreePool(targetAddress);
	return;
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING regPath) {
	ULONG i = 0;
	ULONG j = 0;
	
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DispatchRoutine;

	pDriverObject->DriverUnload = DriverUnload;
	
	DumpPhysicalMemory(TARGET_EPROCESS, MEMORY_SIZE * 256);	// GB to Pages
	
	DbgPrintEx(101, 0, "Driver loaded...\n");
	return STATUS_SUCCESS;
}