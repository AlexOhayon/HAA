// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

void OnGetDocInterface(HWND hWnd);

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	HWND foreground = GetActiveWindow();
	HWND IEDoc = FindWindowEx(foreground, NULL, L"Shell DocObject View", NULL);
	HWND IESvr = FindWindowEx(IEDoc, NULL, L"Internet Explorer_Server", NULL);

	OnGetDocInterface(IEDoc);

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		


		wchar_t window_title[256];
		GetWindowText(IESvr, window_title, 256);
		MessageBox(NULL, (LPCWSTR)&window_title, L"Injected!", MB_OK);

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
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
