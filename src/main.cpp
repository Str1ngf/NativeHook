#include <intrin.h>
#include <Windows.h>
#include <winternl.h>
#include <detours.h>
#include <stdio.h>
#pragma comment(lib, "psapi")
#pragma comment(lib,"C:\\Detours-4.0.1\\lib.X86\\detours.lib")

#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_SUCCESS 0x00000000

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CLIENT_ID* PCLIENT_ID;



typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef NTSTATUS(__stdcall* _NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID clientId);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);

bool Detour(void** function, void* redirection)
{
	if (DetourTransactionBegin() != NO_ERROR)
	{
		return false;
	}

	if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
	{
		return false;
	}


	if ((true ? DetourAttach : DetourDetach)(function, redirection) != NO_ERROR)
	{
		return false;
	}

	if (DetourTransactionCommit() == NO_ERROR)
	{
		return true;
	}

	DetourTransactionAbort();
	return false;
}

bool Hook_NtOpenProcess()
{
	typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	static NtOpenProcess_t _NtOpenProcess = reinterpret_cast<NtOpenProcess_t>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"));

	NtOpenProcess_t NtOpenProcess_hook = [](PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) -> NTSTATUS
	{
		if (ClientId->UniqueProcess != (HANDLE)GetCurrentProcessId()) {
			printf("ACCESS_DENIED NtOpenProcess process ID :  0x%X\n", ClientId->UniqueProcess);
			return STATUS_ACCESS_DENIED;
		}

		printf("STATUS_SUCCESS NtOpenProcess process ID : 0x%X\n", ClientId->UniqueProcess);
		return _NtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
	};
	return Detour(reinterpret_cast<void**>(&_NtOpenProcess), NtOpenProcess_hook);
}

BOOL APIENTRY DllMain(HMODULE module, unsigned long reason, void* reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		SetConsoleTitle(L"Native Hook");

		FILE* pFile = nullptr;
		freopen_s(&pFile, "CON", "r", stdin);
		freopen_s(&pFile, "CON", "w", stdout);
		freopen_s(&pFile, "CON", "w", stderr);
		pNtCreateThreadEx ntCTEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
		HANDLE hThread = nullptr;

		ntCTEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)Hook_NtOpenProcess, nullptr, FALSE, NULL, NULL, NULL, NULL);
		if (hThread == NULL) {
			CloseHandle(GetCurrentProcess());
			printf("ThreadHandle failed..\n");
			return 0;
		}
		else {
			printf("Successfully CreateThread..\n");
		}
		DisableThreadLibraryCalls(module);

	}
	else if (reason == DLL_PROCESS_DETACH)
	{

	}

	return TRUE;
}