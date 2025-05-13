#include "DriverCore.h"

PHOOK_NOTIFY_BUFFER pRegisterCallbackHookBuffer = NULL;


auto RegisterCallbackSet(BOOLEAN Set) -> NTSTATUS {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if (pRegisterCallbackHookBuffer->Enable != Set) {

	}
}