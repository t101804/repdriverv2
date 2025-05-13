#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <intrin.h>
#include <bcrypt.h>
#include <windef.h>
#include <ntimage.h>
#include <strsafe.h>
#include <classpnp.h>
#include <netioddk.h>
#include <ntstrsafe.h>

// Native Kernel & Windows
#include "Native/Enums.h"
#include "Native/Structs.h"
#include "Native/Kernel.h"

// Native Driver DbgPrint
//#define DebugPrint(x) DbgPrintEx(DPFLTR_IHVDRIVER_ID, ULONG_MAX, x);

// Our Funcstions
#include "Callback.h" // for comms communications

extern "C" VOID DriverEntry();