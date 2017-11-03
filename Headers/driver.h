#pragma once
#include "ntddk.h"

#define KTHREAD_OFFSET_KPROCESS						0x150		//  Ptr32 _KPROCESS
#define KPROC_OFFSET_DirectoryTableBase				0x018		//  Uint4B
#define EPROC_OFFSET_VadRoot						0x278		//  _MM_AVL_TABLE
