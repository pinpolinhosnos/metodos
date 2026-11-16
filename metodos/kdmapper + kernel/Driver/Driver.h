#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <Utils/Singleton.h> 

#define IOCTL_READ_WRITE_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_REQUEST_PROTECT_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71011, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_BASE_ADDRESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_GUARDED_REGION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x73, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTECT_WINDOW      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x74, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_VIRTUAL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x75, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_START_PREFETCH_BLOCK     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x909, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUSE_MOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
constexpr ULONG DRIVER_SECURITY_CODE = 0x85b3e12;

namespace Request {
	struct ReadWrite {
		INT32 security;
		INT32 process_id;
		ULONGLONG address;
		ULONGLONG buffer;
		ULONGLONG size;
		BOOLEAN write;
	};

	struct BaseAddress {
		INT32 security;
		INT32 process_id;
		ULONGLONG* address;
	};

	struct GuardedRegion {
		INT32 security;
		ULONGLONG* address;
	};

	struct ProtectWindow {
		int64_t window_handle;
		INT32   security;
		DWORD   display_affinity;
	};

	struct ProtectVirtualMemory {
		INT32       security;
		INT32       process_id;
		ULONGLONG   address;
		ULONGLONG   size;
		ULONG       new_protection;
		PULONG      old_protection;
	};

	typedef struct _MODULE_BASE
	{
		ULONG		security;
		UINT32		process_id;
		ULONGLONG	base_address;
		WCHAR		module_name[256];
	} MODULE_BASE, * PMODULE_BASE;

	struct commStruct {
		UINT64 pid = 0;
		UINT64 status = 0;
	};
	struct ProtectProcess {
		ULONG PID;
	};

	struct MouseMove {
		INT32 security;
		LONG dx;
		LONG dy;
	};
}


class Driver : public Singleton<Driver>
{
	friend class Singleton<Driver>;

public:
	uint32_t process_id = 0;
	bool ReadMemory ( uint32_t process_id , uint64_t address , void* buffer , size_t size );
	bool WriteMemory ( uint32_t process_id , uint64_t address , void* buffer , size_t size );
	bool ProtectProcess( int PID );
	std::vector<uint8_t> ReadBytes(uintptr_t Addr, size_t Size);
	BOOL WriteBytes(uintptr_t Addr, std::vector<uint8_t> Bytes);
	bool ReadMemoryImpl ( uint64_t address , void* buffer , size_t size );
	bool WriteMemoryImpl ( uint64_t address , void* buffer , size_t size );

	uint64_t GetProcessBaseAddress ( uint32_t process_id );
	uint64_t GetGuardedRegion ( );
	bool SetWindowDisplayAffinity ( HWND window_handle , ULONG affinity );
	bool StartPrefetchBlock( );
	bool ProtectVirtualMemory(uint64_t address, size_t size, ULONG new_protection, PULONG old_protection);

	template <typename T>
	T ReadMemory ( uint32_t process_id , uint64_t address ) {
		T buffer {};
		ReadMemory ( process_id , address , &buffer , sizeof ( T ) );
		return buffer;
	}
	DWORD ExecuteShellcode_APC(const unsigned char* shellcode, size_t size, HANDLE hThread);
	template <typename T>
	bool WriteMemory ( uint32_t process_id , uint64_t address , T value ) {
		return WriteMemory ( process_id , address , &value , sizeof ( T ) );
	}

	uint32_t FindProcessID ( const std::wstring& processName );
	bool IsValidPtr ( void* pointer ) {
		return pointer && ( uintptr_t ) pointer >= 0x1000 && ( uintptr_t ) pointer <= 0x7FFFFFFFFFFF;
	}
	bool Attach ( const std::wstring& processName );
	void Detach ( );
	uint64_t GetModuleSize ( uint64_t baseAddress );

	uintptr_t PatternScan ( const std::string& pattern , int offset , int instruction_len );
	uintptr_t FindSignature ( const std::vector<uint8_t>& signature , uintptr_t module_base = 0 , uintptr_t module_size = 0 );
	bool NopBytes ( uintptr_t address , int count );
	bool PatchBytes ( uintptr_t address , const std::vector<uint8_t>& bytes );

	uint32_t GetProcessId ( ) const { return process_id; }
	uint64_t GetBaseAddress ( ) const { return base_address; }
	uint64_t GetAttachedModuleSize ( ) const { return module_size; }
	HANDLE GetProcessHandle ( ) const { return hProcess; }
	HANDLE GetDriverHandle ( ) const { return hDriver; }
	BOOL PatchFunc(uintptr_t Addr, int NopCount);
	uint64_t GetModuleBaseAddress ( const std::wstring& moduleName );
	std::string ReadString ( uint64_t address , size_t size = 64 );
	uintptr_t ResolveRelativeAddress ( uintptr_t address , int offset , int instruction_len );
	DWORD ExecuteShellcode(const unsigned char* shellcode, size_t size);
	
	// Mouse movement via kernel driver
	bool MoveMouse(int dx, int dy);
	
	// Método para reinicializar o driver handle
	bool ReinitializeDriver();

private:
	Driver ( );
	~Driver ( );

	bool SendIoControl ( DWORD ioctl_code , PVOID buffer , DWORD buffer_size );

	std::vector<uint8_t> PatternToVector ( const std::string& pattern );

	HANDLE hDriver = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE; 
	uint64_t base_address = 0;
	uint64_t module_size = 0;
};
