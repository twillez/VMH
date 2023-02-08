#include "VirtMemoryHelper.h"
#include <vector>
#include <iostream>

using namespace VirtualHelper;

typedef NTSTATUS(NTAPI* tNtReadVirtualMemory)(
    IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID buffer,
    IN ULONG NumberOfBytesRead, OUT PULONG NumberOfBytesReaded OPTIONAL);

typedef NTSTATUS(NTAPI* tNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID buffer,
    IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(NTAPI* tNtAllocateVirtualMemory)(
    IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

typedef NTSTATUS(NTAPI* tNtFreeVirtualMemory)(IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType);

typedef NTSTATUS(NTAPI* tNtProtectVirtualMemory)(
    IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection);

static tNtReadVirtualMemory NtReadVirtualMemory =
(tNtReadVirtualMemory)(void*)GetProcAddress(LoadLibrary(L"ntdll.dll"),
    "NtReadVirtualMemory");

static tNtWriteVirtualMemory NtWriteVirtualMemory =
(tNtWriteVirtualMemory)(void*)GetProcAddress(LoadLibrary(L"ntdll.dll"),
    "NtWriteVirtualMemory");

static tNtAllocateVirtualMemory NtAllocateVirtualMemory =
(tNtAllocateVirtualMemory)(void*)GetProcAddress(LoadLibrary(L"ntdll.dll"),
    "NtAllocateVirtualMemory");

static tNtFreeVirtualMemory NtFreeVirtualMemory =
(tNtFreeVirtualMemory)(void*)GetProcAddress(LoadLibrary(L"ntdll.dll"),
    "NtFreeVirtualMemory");

static tNtProtectVirtualMemory NtProtectVirtualMemory =
(tNtProtectVirtualMemory)(void*)GetProcAddress(LoadLibrary(L"ntdll.dll"),
    "NtProtectVirtualMemory");

void ERRMSG(std::string msg)
{
    printf("\nERROR: %s\n",msg);
}

uint32_t VMH::GetPidByName(const wchar_t* process_name)
{
    uint32_t result = 0;
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot_handle != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(process_entry);
        if (Process32First(snapshot_handle, &process_entry))
        {
            do
            {
                if (!_wcsicmp(process_entry.szExeFile, process_name))
                {
                    result = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot_handle, &process_entry));
        }
    }
    else { ERRMSG("Get Process Id"); return 0; }
    CloseHandle(snapshot_handle);
    return result;
}

HMODULE VMH::GetHModule(const wchar_t* module_name, int pid)
{
    uint32_t result = 0;
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot_handle == INVALID_HANDLE_VALUE) { ERRMSG(" Snapshot Module Handle"); return 0; }
    if (snapshot_handle != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 module_entry;
        module_entry.dwSize = sizeof(module_entry);
        if (Module32First(snapshot_handle, &module_entry))
        {
            do
            {
                if (!_wcsicmp(module_entry.szModule, module_name))
                {
                    return HMODULE(module_entry.hModule);
                }
            } while (Module32Next(snapshot_handle, &module_entry));
        }
    }
    CloseHandle(snapshot_handle);
    return 0;
}

HANDLE VMH::GetProcessHandle(int pid)
{
    HANDLE ha = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!ha) { ERRMSG("Get Process Handle");; return 0; }
    return ha;
}

void VMH::ReadMemoryBuffer(HANDLE handle, uint32_t address, uint32_t size, void* out_result)
{
    //ReadProcessMemory(static_cast<HANDLE>(handle), reinterpret_cast<LPCVOID>(address), out_result, size, 0);
    NtReadVirtualMemory(static_cast<HANDLE>(handle), reinterpret_cast<PVOID>(address), out_result, size, 0);
}

void VMH::WriteMemoryBuffer(HANDLE handle, uint32_t address, uint32_t size, const void* data)
{
    // WriteProcessMemory(static_cast<HANDLE>(_handle), reinterpret_cast<LPVOID>(address), data, size, 0);
    NtWriteVirtualMemory(static_cast<HANDLE>(handle), reinterpret_cast<PVOID>(address), const_cast<PVOID>(data), size, 0);
}

uint32_t VMH::alloc(HANDLE handle, const uint32_t size)
{
    //VirtualAllocEx(static_cast<HANDLE>(_handle), NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    void* address = NULL;
    SIZE_T sz = size;
    NtAllocateVirtualMemory(static_cast<HANDLE>(handle), &address, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (address != NULL)
    {
        _allocated_memory[reinterpret_cast<uint32_t>(address)] = size;
    }
    return reinterpret_cast<uint32_t>(address);
}

void VMH::Free(HANDLE handle, uint32_t address)
{
    auto result = _allocated_memory.find(address);
    if (result != _allocated_memory.end())
    {
        // VirtualFreeEx((HANDLE)_handle, reinterpret_cast<void *>(address), result->second, MEM_RELEASE);
        PVOID addr = reinterpret_cast<PVOID>(address);
        SIZE_T sz = 0;
        NtFreeVirtualMemory(static_cast<HANDLE>(handle), &addr, &sz,
            MEM_RELEASE);
        _allocated_memory.erase(address);
        _virtual_protect.erase(address);
    }
}

void VMH::SetVirtualProtect(HANDLE handle,uint32_t address, uint32_t size, enVirtualProtect type)
{
    ULONG old_protect = 0;
    PVOID addr = reinterpret_cast<PVOID>(address);
    ULONG sz = size;
    ULONG protect = 0;
    if (type == (enVirtualProtect::READ | enVirtualProtect::WRITE |
        enVirtualProtect::EXECUTE))
    {
        protect = PAGE_READWRITE;
    }
    else if (type == (enVirtualProtect::READ & enVirtualProtect::WRITE))
    {
        protect = PAGE_READWRITE;
    }
    else if (type == (enVirtualProtect::READ & enVirtualProtect::EXECUTE))
    {
        protect = PAGE_EXECUTE_READ;
    }
    else if (type == enVirtualProtect::READ)
    {
        protect = PAGE_READONLY;
    }
    else if (type == enVirtualProtect::NOACCESS)
    {
        protect = PAGE_NOACCESS;
    }

    NtProtectVirtualMemory(static_cast<HANDLE>(handle), &addr, &sz, protect,
        &old_protect);

    auto original_vp = _virtual_protect.find(address);
    if (original_vp == _virtual_protect.end())
    {
        _virtual_protect[address] = { size, old_protect };
    }
    else if (original_vp->second.size < size)
    {
        original_vp->second.size = size;
    }
}

void VMH::RestoreVirtualProtect(uint32_t address, HANDLE handle )
{
    auto vp = _virtual_protect.find(address);
    if (vp != _virtual_protect.end())
    {
        ULONG old_protect;
        PVOID addr = reinterpret_cast<PVOID>(address);
        ULONG sz;
        NtProtectVirtualMemory(static_cast<HANDLE>(handle), &addr, &sz,
            vp->second.original_protect, &old_protect);
        _virtual_protect.erase(address);
    }
}

uint32_t VMH::GetModuleAddress(const wchar_t* module_name, int pid)
{
    uint32_t result = 0;
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot_handle != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 module_entry;
        module_entry.dwSize = sizeof(module_entry);
        if (Module32First(snapshot_handle, &module_entry))
        {
            do
            {
                if (!_wcsicmp(module_entry.szModule, module_name))
                {
                    result =
                        reinterpret_cast<uint32_t>(module_entry.modBaseAddr);
                    break;
                }
            } while (Module32Next(snapshot_handle, &module_entry));
        }
    }
    CloseHandle(snapshot_handle);
    return result;
}

uint32_t VMH::FindSignature(
    HANDLE handle,
    uint32_t address, /*The address from which to start the search*/
    uint32_t size, /*The size of the memory area in which to search for the signature*/
    const uint8_t* signature, /*The byte sequence to be found.*/
    const char* mask) /* "xxx???xx?xxxx" */
{
    if (!signature)
    {
        return 0;
    }
    if (!mask)
    {
        return 0;
    }
    if (strlen(mask) > size)
    {
        return 0;
    }
    uint8_t* buffer = new uint8_t[size];
    ReadMemoryBuffer(handle,address, size, buffer);
    uint32_t result = 0;
    for (uint32_t i = 0; i <= size - strlen(mask); i++)
    {
        uint32_t mask_offset = 0;
        while (mask[mask_offset])
        {
            if (mask[mask_offset] == 'x' &&
                buffer[i + mask_offset] != signature[mask_offset])
            {
                mask_offset = 0;
                break;
            }
            ++mask_offset;
        }
        if (mask_offset != 0)
        {
            result = address + i;
            break;
        }
    }
    delete[] buffer;
    return result;
}

bool VMH::is_valid_ptr(PVOID ptr)
{
    return (ptr >= (PVOID)0x10000) && (ptr < PTRMAXVAL) && ptr != nullptr && !IsBadReadPtr(ptr, sizeof(ptr));
}

uint32_t VMH::OffsetsCalculator(HANDLE handle,uint32_t offset, std::vector<unsigned int> pointers)
{
    uint32_t address = offset;
    for (unsigned int i(0); i < pointers.size(); ++i)
    {
        ReadProcessMemory(static_cast<HANDLE>(handle), (BYTE*)address, &address, sizeof(address), 0);
        address += pointers[i];
    }
    return address;
}

BOOLEAN VMH::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{

    for (; *szMask; ++szMask, ++pData, ++bMask)
        if ((*szMask == 1 || *szMask == 'x') && *pData != *bMask)
            return 0;

    return (*szMask) == 0;
}

DWORD VMH::FindPatternEx(UINT64 dwAddress, DWORD dwLen, BYTE* bMask, char* szMask)
{

    if (dwLen <= 0)
        return 0;
    for (DWORD i = 0; i < dwLen; i++)
        if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
            return (DWORD)(dwAddress + i);
    
    return 0;
}

DWORD VMH::FindPattern(DWORD module, BYTE* bMask, CHAR* szMask, DWORD len)
{

    ULONG_PTR ret = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE*)pinh + sizeof(IMAGE_NT_HEADERS64));
    for (USHORT sec = 0; sec < pinh->FileHeader.NumberOfSections; sec++)
    {

        if ((pish[sec].Characteristics & 0x00000020))
        {
            DWORD address = FindPatternEx(pish[sec].VirtualAddress + (ULONG_PTR)(module), pish[sec].Misc.VirtualSize - len, bMask, szMask);

            if (address) {
                ret = address;
                break;
            }
        }

    }
    return ret;

}