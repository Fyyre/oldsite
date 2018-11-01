#include <windows.h>

/* by fyyre & rndbit - 2013 */
/* how to... we were lazy, and not
 * make dll proxy, as was test of 
 * my idea how to break this 15k
 * skiddie tool...
 *
 * dll compile.. CFF Explorer used
 * attach of dll to IAT of MSF
 * rubyw.exe process.
 * work like charm, in 2013 at least =)
 *
 * I release this now for all, but I also
 * say.. if require MSF for hacking?
 * stop use it, use brain - simple
 * always best...
*/

void Write(void* pAddress, void* JumpTo, BYTE opcode, DWORD nops = 0)
{
	DWORD dwOldProtect = 0;
	VirtualProtect(pAddress, 5 + nops, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if(nops)
		memset((PBYTE)pAddress + 5, 0x90, nops);

	BYTE *pCur = (BYTE *) pAddress;
	*pCur = opcode;  // call rel
	*(DWORD*)(++pCur) = (DWORD) ((size_t)JumpTo - (size_t)pAddress) - 5;
	VirtualProtect(pAddress, 5 + nops, dwOldProtect, &dwOldProtect);
}

void* Hotpatch( void* OriginalFunction, void* NewFunction )
{
	Write((PBYTE)OriginalFunction - 5, NewFunction, 0xE9);
	DWORD oldProtect = 0;
	VirtualProtect(OriginalFunction, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(WORD*)OriginalFunction = 0xF9EB;	// jmp back
	VirtualProtect(OriginalFunction, 2, oldProtect, &oldProtect);
	return (PBYTE)OriginalFunction + 2;
}

decltype(GetSystemTimeAsFileTime)* _GetSystemTimeAsFileTime;
void WINAPI GetSystemTimeAsFileTimeFake(PFILETIME fileTime)
{
	_GetSystemTimeAsFileTime(fileTime);
	SYSTEMTIME st = { 0 };
	if(FileTimeToSystemTime(fileTime, &st))
	{
		st.wYear = 2000;
		memset(fileTime, 0, sizeof(FILETIME));
		SystemTimeToFileTime(&st, fileTime);
	}
}

extern "C" __declspec(dllexport) int lame_iat_add_me = 1;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			DisableThreadLibraryCalls(hModule);
			HANDLE kernel32 = GetModuleHandle(L"kernel32.dll");
			_GetSystemTimeAsFileTime = (decltype(_GetSystemTimeAsFileTime))Hotpatch(GetProcAddress((HMODULE)kernel32, "GetSystemTimeAsFileTime"), &GetSystemTimeAsFileTimeFake);

			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

