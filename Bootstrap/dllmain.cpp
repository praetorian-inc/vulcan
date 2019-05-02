#include <metahost.h>
#include <string>

#pragma comment(lib, "mscoree.lib")

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")

using namespace mscorlib;
using namespace std;

//
// Parses arguments used to invoke a managed assembly
//
struct ClrArgs
{
	static const LPCWSTR DELIM;

	ClrArgs(LPCWSTR command)
	{
		int i = 0;
		wstring s(command);
		wstring* ptrs[] = { &pwzAssemblyPath, &pwzTypeName, &pwzMethodName };

		while (s.find(DELIM) != wstring::npos && i < 3)
		{
			*ptrs[i++] = s.substr(0, s.find(DELIM));
			s.erase(0, s.find(DELIM) + 1);
		}

		if (s.length() > 0)
			pwzArgument = s;
	}

	wstring pwzAssemblyPath;
	wstring pwzTypeName;
	wstring pwzMethodName;
	wstring pwzArgument;
};

const LPCWSTR ClrArgs::DELIM = L"\t"; // delimiter

//
// Function to start the DotNet runtime and invoke a managed assembly
//
__declspec(dllexport) HRESULT ImplantDotNetAssembly(_In_ LPCTSTR lpCommand)
{
    HRESULT hr;
    ICLRMetaHost *pMetaHost = NULL;
    ICLRRuntimeInfo *pRuntimeInfo = NULL;
	ICLRRuntimeHost *pClrRuntimeHost = NULL;

	// build runtime
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
    hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_PPV_ARGS(&pClrRuntimeHost));

	// start runtime
	hr = pClrRuntimeHost->Start();	

	// parse the arguments
	ClrArgs args(lpCommand);

	// execute managed assembly
	DWORD pReturnValue;
	hr = pClrRuntimeHost->ExecuteInDefaultAppDomain(
		args.pwzAssemblyPath.c_str(), 
		args.pwzTypeName.c_str(), 
		args.pwzMethodName.c_str(), 
		args.pwzArgument.c_str(), 
		&pReturnValue);

	// (optional) unload the .net runtime; note it cannot be restarted if stopped without restarting the process
	//hr = pClrRuntimeHost->Stop();

	// free resources
    pMetaHost->Release();
    pRuntimeInfo->Release();
    pClrRuntimeHost->Release();

    return hr;
}

//
// Dll entry point
//
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	// attempting to load .NET Framework inside of DllMain ATTACH will result in loader lock
	// more info: http://msdn.microsoft.com/en-us/library/ms172219.aspx

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
