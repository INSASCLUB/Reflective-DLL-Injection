// Took me like a month to figure out this technique manually
// but worth it , i know lethal aka vineet is great coder ( not so good bruhh , am still learning )

#include <string>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <SDKDDKVer.h>

#define PROCESS_NAME L"PROCESS_NAME.exe"  //Your process name goes here

uint8_t binary[] = {0x00}; // DLL data goes here, i post insas raw bytes here

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);

typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD32, LPVOID);

typedef struct 
{
	PBYTE imageBase;
	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
	VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

struct loaderdata 
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDir;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
};

DWORD __stdcall LibraryLoader(LPVOID Memory)
{
	loaderdata* LoaderParams = (loaderdata*)Memory;
	PIMAGE_BASE_RELOCATION ImageRelocation = LoaderParams->BaseReloc;
	DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase);

	while (ImageRelocation->VirtualAddress) 
	{
		if (ImageRelocation->SizeOfBlock >= sizeof(PIMAGE_BASE_RELOCATION))
		{
			int count = (ImageRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(ImageRelocation + 1);
			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (ImageRelocation->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
			ImageRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageRelocation + ImageRelocation->SizeOfBlock);
		}
	}

	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = LoaderParams->ImportDir;
	while (ImportDesc->Characteristics) 
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->FirstThunk);
		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + ImportDesc->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		ImportDesc++;
	}
	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point 
	}
	return true;
}

DWORD WINAPI stub()
{
	return 0;
}

DWORD FindProcessId(std::wstring processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processSnapshot);
	return 0;
}

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
	while (relocation->VirtualAddress) 
	{
		PWORD relocationInfo = (PWORD)(relocation + 1);
		for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
			if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				*(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;
		relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (importDirectory->Characteristics) 
	{
		PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);
		HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

		if (!module)
			return FALSE;

		while (originalFirstThunk->u1.AddressOfData) 
		{
			DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

			if (!Function)
				return FALSE;

			firstThunk->u1.Function = Function;
			originalFirstThunk++;
			firstThunk++;
		}
		importDirectory++;
	}

	if (ntHeaders->OptionalHeader.AddressOfEntryPoint) 
	{
		DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
			(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
			((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
		loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
		loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
#endif
		return result;
	}
	return TRUE;
}

int main() 
{

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 1;

	HANDLE process = NULL;
	PROCESSENTRY32W processInfo;
	processInfo.dwSize = sizeof(processInfo);

	if (Process32FirstW(processSnapshot, &processInfo)) 
	{
		do {
			if (!lstrcmpW(processInfo.szExeFile, PROCESS_NAME)) 
			{
				process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processInfo.th32ProcessID);
				break;
			}
		} while (Process32NextW(processSnapshot, &processInfo));
	}
	CloseHandle(processSnapshot);

	if (!process)
		return 1;
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)binary;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);
	LPVOID executableImage = VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, executableImage, binary,ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		WriteProcessMemory(process,(PVOID)((LPBYTE)executableImage + sectionHeaders[i].VirtualAddress),(PVOID)((LPBYTE)binary + sectionHeaders[i].PointerToRawData),sectionHeaders[i].SizeOfRawData,NULL);

	loaderdata LoaderParams;
	LoaderParams.ImageBase = executableImage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)executableImage + DosHeader->e_lfanew);

	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)executableImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)executableImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LoaderParams.fnLoadLibraryA = LoadLibraryA;
	LoaderParams.fnGetProcAddress = GetProcAddress;

	DWORD LoaderCodeSize = (DWORD)stub - (DWORD)LibraryLoader;
	DWORD LoaderTotalSize = LoaderCodeSize + sizeof(loaderdata);
	LPVOID LoaderMemory = VirtualAllocEx(process, NULL, LoaderTotalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(process, LoaderMemory, &LoaderParams, sizeof(loaderdata), 0);
	WriteProcessMemory(process, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader, LoaderCodeSize, NULL);

	HANDLE hThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);
	return 0;
}
