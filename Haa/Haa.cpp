// Haa.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


DWORD GetProcessIDByName(wchar_t* ProcessName);
void InjectProcess(wchar_t* AppName);
DWORD GetLowestProcessIDByName(wchar_t* ProcessName);

void OnGetDocInterface(HWND hWnd);

int _tmain(int argc, _TCHAR* argv[])
{
	wchar_t* appName = L"IEXPLORE.EXE";

	//InjectProcess(appName);
	Sleep(2000);
	HWND foreground = GetForegroundWindow();
	//HWND IEDoc = FindWindowEx(foreground, NULL, L"Shell DocObject View", NULL);
	//HWND IESvr = FindWindowEx(IEDoc, NULL, L"Internet Explorer_Server", NULL);

	OnGetDocInterface(foreground);

	getchar();

	return 0;
}

void InjectProcess(wchar_t* AppName)
{
	char* buffer = "C:\\Source\\GitHub\\Haa\\Debug\\HaaDLL32.dll";

	DWORD procID = 0;
	procID = GetLowestProcessIDByName(AppName);
	printf("Found Process ID: %d \n", procID);
	/*
	* Get process handle passing in the process ID.
	*/

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (process == NULL) {
		printf("Error: the specified process couldn't be found.\n");
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
		printf("Error: the memory could not be allocated inside the chosen process.\n");
	}

	/*
	* Write the argument to LoadLibraryA to the process's newly allocated memory region.
	*/
	int n = WriteProcessMemory(process, arg, buffer, strlen(buffer), NULL);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space.\n");
	}

	/*
	* Inject our DLL into the process's address space.
	*/
	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created.\n");
	}
	else {
		printf("Success: the remote thread was successfully created.\n");
	}

	/*
	* Close the handle to the process, because we've already injected the DLL.
	*/
	CloseHandle(process);
}

DWORD GetProcessIDByName(wchar_t* ProcessName){

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp(entry.szExeFile, ProcessName) == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

DWORD GetLowestProcessIDByName(wchar_t* ProcessName)
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
		if (aProcesses[i] != 0 && aProcesses[i] < CurrentPID)
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

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam)
{
	TCHAR	buf[100];

	::GetClassName(hwnd, (LPTSTR)&buf, 100);
	if (_tcscmp(buf, _T("Internet Explorer_Server")) == 0)
	{
		*(HWND*)lParam = hwnd;
		return FALSE;
	}
	else
		return TRUE;
};

void OnGetDocInterface(HWND hWnd)
{
	CoInitialize(NULL);

	// Explicitly load MSAA so we know if it's installed
	HINSTANCE hInst = ::LoadLibrary(_T("OLEACC.DLL"));
	if (hInst != NULL)
	{
		if (hWnd != NULL)
		{
			HWND hWndChild = NULL;
			// Get 1st document window
			::EnumChildWindows(hWnd, EnumChildProc, (LPARAM)&hWndChild);
			if (hWndChild)
			{
				CComPtr<IHTMLDocument2> spDoc;
				LRESULT lRes;

				UINT nMsg = ::RegisterWindowMessage(_T("WM_HTML_GETOBJECT"));
				::SendMessageTimeout(hWndChild, nMsg, 0L, 0L, SMTO_ABORTIFHUNG, 1000, (DWORD*)&lRes);

				LPFNOBJECTFROMLRESULT pfObjectFromLresult = (LPFNOBJECTFROMLRESULT)::GetProcAddress(hInst, "ObjectFromLresult");
				if (pfObjectFromLresult != NULL)
				{
					HRESULT hr;
					hr = (*pfObjectFromLresult)(lRes, IID_IHTMLDocument, 0, (void**)&spDoc);
					if (SUCCEEDED(hr))
					{
						// Change background color to red
						spDoc->put_bgColor(CComVariant("red"));
					}
				}
			} // else document not ready
		} // else Internet Explorer is not running
		::FreeLibrary(hInst);
	} // else Active Accessibility is not installed
	CoUninitialize();
}