#include "../../Headers/driver.h"

//////////////////////////////////////////////////////////////////////////////////
//////////////////////		HARDCODING for test		//////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
#define MEMORY_SIZE					4				// GB
#define TARGET_EPROCESS					0x8682cd28        		// for test
//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////


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


VOID DumpPhysicalMemory(ULONG CountOfPageFrame) {
	PHYSICAL_ADDRESS pa;
	ULONG i = 0;
	ULONG virtualAddress = 0;
	PULONG myAddress = NULL;
	PULONG targetAddress = NULL;
	ULONG backedEprocess = 0;
	ULONG backedCR3 = 0;
	ULONG backedEthread = 0;
	ULONG targetPDT = 0;


	if (TARGET_EPROCESS >= 0x80000000) {
		__try {
			targetPDT = *(PULONG)(TARGET_EPROCESS + KPROC_OFFSET_DirectoryTableBase);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] TARGET_ERPOCESS is Invalid address...\n");
			return;
		}
	}
	else
		return;
	
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


	// Backup & Switching 
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


			/////////////////////		Switching		/////////////////////
			mov dword ptr [eax], TARGET_EPROCESS;
			
			mov ebx, targetPDT;
			mov cr3, ebx;

			pop ebx;
			pop eax;

		}
		//*(PULONG)(backedEthread + KTHREAD_OFFSET_KPROCESS) = TARGET_EPROCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to switch...\n");
		goto PRINT;
	}

//	DbgPrintEx(101, 0, "EPROCESS : %s[0x%08X]    CR3 : 0x%08X\n", (PUCHAR)(backedEprocess + EPROC_OFFSET_ImageFileName), backedEprocess, backedCR3);

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

	// RESTORE...
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
		DbgPrintEx(101, 0, "[ERROR] in RESTORE CR3...\n");
	}

	*(PULONG)(backedEthread + KTHREAD_OFFSET_KPROCESS) = backedEprocess;

PRINT:
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
	
	DumpPhysicalMemory(MEMORY_SIZE * 256);	// GB to Pages
	
	DbgPrintEx(101, 0, "Driver loaded...\n");
	return STATUS_SUCCESS;
}