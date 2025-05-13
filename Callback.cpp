#include "DriverCore.h"

PHOOK_NOTIFY_BUFFER pRegisterCallbackHookBuffer = NULL;


//auto CallBack(LPVOID, REG_NOTIFY_CLASS OperationType, PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo) -> NTSTATUS {}

auto RegisterCallbackSet(BOOLEAN Set) -> NTSTATUS {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if (pRegisterCallbackHookBuffer->Enable != Set) {
		if (pRegisterCallbackHookBuffer->HookPoint != NULL) {
			if (Set == TRUE) {
				/*Status = CmRegisterCallback((PEX_CALLBACK_FUNCTION)(pRegisterCallbackHookBuffer->HookPoint), Callback, &pRegisterCallbackHookBuffer->Cookie);
				if (NT_SUCCESS(Status)) {
					pRegisterCallbackHookBuffer->Enable = TRUE;
				}*/
			}
			else {
				if (pRegisterCallbackHookBuffer->HookPoint != NULL) {
					Status = CmUnRegisterCallback(pRegisterCallbackHookBuffer->Cookie);
					if (NT_SUCCESS(Status)) {
						pRegisterCallbackHookBuffer->Enable = FALSE;
					}

				}
			}
		}
		else {
			// // Use Global Hooks
			//pRegisterCallbackHookBuffer->HookPoint = SearchSignForImage();
			// // "\xFF\xE1", "xx", 2);
		}
	}
	else {
		Status = STATUS_SUCCESS;
	}
	return Status;
}