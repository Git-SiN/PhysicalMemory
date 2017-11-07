#pragma once
#include "ntddk.h"

#define EPROC_OFFSET_ImageFileName					0x16c //  [15] EPROC_OFFSET_UChar
#define KTHREAD_OFFSET_KPROCESS						0x150		//  Ptr32 _KPROCESS
#define KPROC_OFFSET_DirectoryTableBase				0x018		//  Uint4B
#define EPROC_OFFSET_VadRoot						0x278		//  _MM_AVL_TABLE

#define EPROC_OFFSET_Vm								0x1f0 //  _MMSUPPOR

#pragma pack(1)
/////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////			MMWSL			/////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _MMWSLE {
	union {
		PVOID VirtualAddress;   // PVoid
		LONG Long;
		struct _MMWSLENTRY {
			ULONG Valid : 1;
			ULONG Spare : 1;
			ULONG Hashed : 1;
			ULONG Direct : 1;
			ULONG Protection : 5;
			ULONG Age : 3;
			ULONG VirtualPageNumber : 20;
		}e1;
		struct _MMWSLE_FREE_ENTRY {
			ULONG MustBeZero : 1;
			ULONG PreviousFree : 11;
			ULONG NextFree : 20;
		}e2;
	}u1;
} MMWSLE, *PMMWSLE;

typedef struct _MMWSLE_NONDIRECT_HASH {
	PVOID Key;             // Ptr32 Void
	ULONG Index;            //  Uint4B
} MMWSLE_NONDIRECT_HASH, *PMMWSLE_NONDIRECT_HASH;

typedef struct _MMWSLE_HASH {
	ULONG Index; //Uint4B
}MMWSLE_HASH, *PMMWSLE_HASH;

typedef struct _MMWSL {
	ULONG FirstFree;  //Uint4B
	ULONG  FirstDynamic;  //Uint4B
	ULONG LastEntry;  //Uint4B
	ULONG  NextSlot;  //Uint4B
	PMMWSLE	Wsle;  //Ptr32 _MMWSLE
	PVOID LowestPagableAddress;  //Ptr32 Void
	ULONG  LastInitializedWsle;  //Uint4B
	ULONG  NextAgingSlot;  //Uint4B
	ULONG  NumberOfCommittedPageTables;  //Uint4B
	ULONG VadBitMapHint;  //Uint4B
	ULONG  NonDirectCount;  //Uint4B
	ULONG  LastVadBit;  //Uint4B
	ULONG  MaximumLastVadBit;  //Uint4B
	ULONG  LastAllocationSizeHint;  //Uint4B
	ULONG LastAllocationSize;  //Uint4B
	PMMWSLE_NONDIRECT_HASH NonDirectHash;  //Ptr32 _MMWSLE_NONDIRECT_HASH
	PMMWSLE_HASH HashTableStart;  //Ptr32 _MMWSLE_HASH
	PMMWSLE_HASH HighestPermittedHashAddress;  //Ptr32 _MMWSLE_HASH
	USHORT UsedPageTableEntries[1536];  //[1536] Uint2B
	ULONG CommittedPageTables[48];  //[48] Uint4B
} MMWSL, *PMMWSL;

typedef struct _MMSUPPORT {
	ULONG WorkingSetMutex; // _EX_PUSH_LOCK
	PVOID ExitGate; // Ptr32 _KGATE
	PVOID AccessLog; // Ptr32 Void
	LIST_ENTRY WorkingSetExpansionLinks; // _LIST_ENTRY
	ULONG AgeDistribution[7]; // [7] Uint4B
	ULONG MinimumWorkingSetSize; // Uint4B
	ULONG WorkingSetSize; // Uint4B
	ULONG  WorkingSetPrivateSize; // Uint4B
	ULONG  MaximumWorkingSetSize; // Uint4B
	ULONG  ChargedWslePages; // Uint4B
	ULONG  ActualWslePages; // Uint4B
	ULONG  WorkingSetSizeOverhead; // Uint4B
	ULONG  PeakWorkingSetSize; // Uint4B
	ULONG  HardFaultCount; // Uint4B
	PMMWSL VmWorkingSetList; // Ptr32 _MMWSL
	USHORT NextPageColor; // Uint2B
	USHORT LastTrimStamp; // Uint2B
	ULONG  PageFaultCount; // Uint4B
	ULONG  RepurposeCount; // Uint4B
	ULONG Spare[1]; // [1] Uint4B
	struct _MMSUPPORT_FLAGS {
		ULONG WorkingSetType : 3;
		ULONG ModwriterAttached : 1;
		ULONG TrimHard : 1;
		ULONG MaximumWorkingSetHard5 : 1;
		ULONG ForceTrim : 1;
		ULONG MinimumWorkingSetHard7 : 1;
		ULONG SessionMaster : 1;
		ULONG TrimmerState : 2;
		ULONG Reserved : 1;
		ULONG PageStealers : 4;
		ULONG MemoryPriority : 8;
		ULONG WsleDeleted : 1;
		ULONG VmExiting : 1;
		ULONG ExpansionFailed : 1;
		ULONG Available : 5;
	} Flags;
}MMSUPPORT, *PMMSUPPORT;
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////


#pragma pack()