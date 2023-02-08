#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

#define DWORD_OF_BITNESS DWORD64
#define PTRMAXVAL ((PVOID)0x000F000000000000)

namespace VirtualHelper
{
	enum class enCallConvention
	{
		ECC_CDECL = 1,
		ECC_STDCALL,
		ECC_THISCALL
	};

	struct VirtualProtect
	{
		uint32_t size;
		uint32_t original_protect;
	};

	enum class enInjectionType
	{
		EIT_JMP = 1,
		EIT_PUSHRET,
	};

	enum enVirtualProtect
	{
		NOACCESS = 0b0001,
		READ = 0b0010,
		WRITE = 0b0100,
		EXECUTE = 0b1000,
		READ_EXECUTE = READ | EXECUTE,
		READ_WRITE = READ | WRITE,
		READ_WRITE_EXECUTE = READ | WRITE | EXECUTE
	};

	class VMH
	{
	public:
		uint32_t GetPidByName(const wchar_t* process_name);
		void ReadMemoryBuffer(HANDLE handle, uint32_t address, uint32_t size, void* out_result);
		void WriteMemoryBuffer(HANDLE handle, uint32_t address, uint32_t size, const void* data);
		uint32_t alloc(HANDLE handle, const uint32_t size);
		HANDLE GetProcessHandle(int pid);
		void Free(HANDLE handle, uint32_t address);
		HMODULE GetHModule(const wchar_t* module_name, int pid);
		void SetVirtualProtect(HANDLE handle, uint32_t address, uint32_t size, enVirtualProtect type);
		void RestoreVirtualProtect(uint32_t address, HANDLE handle);
		uint32_t GetModuleAddress(const wchar_t* module_name, int pid);
		uint32_t FindSignature(HANDLE handle, uint32_t address, uint32_t size, const uint8_t* signature, const char* mask);
		template <class T> T readmem(HANDLE handle, uint32_t address);
		template <class T> void writemem(HANDLE handle,uint32_t address, const T& data);
		template<class T> T ReadPtr(std::vector<DWORD_OF_BITNESS>address);
		bool is_valid_ptr(PVOID ptr);

		uint32_t OffsetsCalculator(HANDLE handle, uint32_t offset, std::vector<unsigned int> pointers);
		BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
		DWORD FindPatternEx(UINT64 dwAddress, DWORD dwLen, BYTE* bMask, char* szMask);
		DWORD FindPattern(DWORD module, BYTE* bMask, CHAR* szMask, DWORD len);

		std::unordered_map<uint32_t, uint32_t> _allocated_memory;
		std::unordered_map<uint32_t, VirtualProtect> _virtual_protect;
	};

	template <typename T>
	inline T VMH::readmem(HANDLE handle,uint32_t address)
	{
		T result;
		VMH::ReadMemoryBuffer(handle,address, sizeof(T), &result);
		return result;
	}

	template <typename T>
	inline void VMH::writemem(HANDLE handle, uint32_t address, const T& data)
	{
		VMH::WriteMemoryBuffer(handle,address, sizeof(data), &data);
	}

	template<class T>
	T VMH::ReadPtr(std::vector<DWORD_OF_BITNESS>address)
	{
		size_t length_array = address.size() - 1;
		DWORD_OF_BITNESS relative_address;
		relative_address = address[0];
		for (int i = 1; i < length_array + 1; i++)
		{
			if (is_valid_ptr((LPVOID)relative_address) == false)
				return T();

			if (i < length_array)
				relative_address = *(DWORD_OF_BITNESS*)(relative_address + address[i]);
			else
			{
				T readable_address = *(T*)(relative_address + address[length_array]);
				return readable_address;
			}
		}
	}

}