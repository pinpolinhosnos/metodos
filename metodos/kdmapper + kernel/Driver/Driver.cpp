#include "driver.h"
#include <stdexcept>
#include <iostream>
#include <TlHelp32.h>
#include <winternl.h>


Driver::Driver( ) {
	// Tentar abrir o driver
	hDriver = CreateFileW(
		L"\\\\.\\Kernel-InformationSystem" ,
		GENERIC_READ | GENERIC_WRITE ,
		FILE_SHARE_READ | FILE_SHARE_WRITE ,
		nullptr ,
		OPEN_EXISTING ,
		0 ,
		nullptr
	);

	if ( hDriver == INVALID_HANDLE_VALUE ) {
		DWORD error = GetLastError();
		printf( "[-] Failed to open driver handle. Error: %lu\n" , error );
		
		if (error == 2) {
			printf( "[-] Driver not found (Error 2). The driver needs to be loaded first.\n" );
		}
		else if (error == 5) {
			printf( "[-] Access denied (Error 5). Run as Administrator.\n" );
		}
		
		printf( "[-] Please load the driver before running the cheat.\n" );
	}
	else {
		printf( "[+] Driver handle opened successfully!\n" );
	}
}

Driver::~Driver( ) {
	if ( hDriver != INVALID_HANDLE_VALUE ) {
		CloseHandle( hDriver );
		hDriver = INVALID_HANDLE_VALUE;
	}
	Detach( );
}

bool Driver::ReinitializeDriver() {
	// Fechar handle antigo se existir
	if (hDriver != INVALID_HANDLE_VALUE) {
		CloseHandle(hDriver);
		hDriver = INVALID_HANDLE_VALUE;
	}
	
	// Tentar abrir novamente
	hDriver = CreateFileW(
		L"\\\\.\\Kernel-InformationSystem",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);
	
	if (hDriver == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		printf("[-] Failed to reinitialize driver handle. Error: %lu\n", error);
		return false;
	}
	
	printf("[+] Driver handle reinitialized successfully!\n");
	return true;
}

bool Driver::SendIoControl( DWORD ioctl_code , PVOID buffer , DWORD buffer_size ) {
	if ( hDriver == INVALID_HANDLE_VALUE ) {
		return false;
	}

	DWORD bytes_returned = 0;
	return DeviceIoControl(
		hDriver ,
		ioctl_code ,
		buffer ,
		buffer_size ,
		buffer ,
		buffer_size ,
		&bytes_returned ,
		nullptr
	);
}

bool Driver::ReadMemory( uint32_t process_id , uint64_t address , void* buffer , size_t size ) {
	Request::ReadWrite request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.process_id = process_id;
	request.address = address;
	request.buffer = reinterpret_cast< ULONGLONG >( buffer );
	request.size = size;
	request.write = FALSE;

	return SendIoControl( IOCTL_READ_WRITE_MEMORY , &request , sizeof( request ) );
}

bool Driver::WriteMemory( uint32_t process_id , uint64_t address , void* buffer , size_t size ) {
	Request::ReadWrite request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.process_id = process_id;
	request.address = address;
	request.buffer = reinterpret_cast< ULONGLONG >( buffer );
	request.size = size;
	request.write = TRUE;

	return SendIoControl( IOCTL_READ_WRITE_MEMORY , &request , sizeof( request ) );
}

bool Driver::ProtectProcess( int PID ) {
	Request::ProtectProcess request = { 0 };
	request.PID = PID;

	return SendIoControl( IOCTL_REQUEST_PROTECT_PROCESS , &request , sizeof( request ) );
}

bool Driver::ReadMemoryImpl( uint64_t address , void* buffer , size_t size ) {
	if ( this->process_id == 0 ) {
		return false;
	}
	return ReadMemory( this->process_id , address , buffer , size );
}

bool Driver::WriteMemoryImpl( uint64_t address , void* buffer , size_t size ) {
	if ( this->process_id == 0 ) {
		return false;
	}
	return WriteMemory( this->process_id , address , buffer , size );
}

uint64_t Driver::GetProcessBaseAddress( uint32_t process_id ) {
	uint64_t base_address = 0;
	Request::BaseAddress request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.process_id = process_id;
	request.address = &base_address;

	if ( SendIoControl( IOCTL_GET_BASE_ADDRESS , &request , sizeof( request ) ) ) {
		return base_address;
	}
	return 0;
}


uint64_t Driver::GetGuardedRegion( ) {
	uint64_t guarded_address = 0;
	Request::GuardedRegion request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.address = &guarded_address;

	if ( SendIoControl( IOCTL_GET_GUARDED_REGION , &request , sizeof( request ) ) ) {
		return guarded_address;
	}
	return 0;
}

bool Driver::SetWindowDisplayAffinity( HWND window_handle , ULONG affinity ) {
	if ( !window_handle ) {
		return false;
	}

	Request::ProtectWindow request = { 0 };
	request.window_handle = reinterpret_cast< int64_t >( window_handle );
	request.security = DRIVER_SECURITY_CODE;
	request.display_affinity = affinity;

	return SendIoControl( IOCTL_PROTECT_WINDOW , &request , sizeof( request ) );
}

bool Driver::StartPrefetchBlock( ) {
	return SendIoControl( IOCTL_START_PREFETCH_BLOCK , nullptr , 0 );
}

bool Driver::ProtectVirtualMemory( uint64_t address , size_t size , ULONG new_protection , PULONG old_protection ) {
	if ( this->process_id == 0 ) {
		return false;
	}

	Request::ProtectVirtualMemory request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.process_id = this->process_id;
	request.address = address;
	request.size = size;
	request.new_protection = new_protection;
	request.old_protection = old_protection;

	return SendIoControl( IOCTL_PROTECT_VIRTUAL_MEMORY , &request , sizeof( request ) );
}

uint32_t Driver::FindProcessID( const std::wstring& processName ) {
	uint32_t pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( snapshot == INVALID_HANDLE_VALUE )
		return 0;

	PROCESSENTRY32W entry {};
	entry.dwSize = sizeof( PROCESSENTRY32W );

	if ( Process32FirstW( snapshot , &entry ) ) {
		do {
			if ( processName == entry.szExeFile ) {
				pid = entry.th32ProcessID;
				break;
			}
		} while ( Process32NextW( snapshot , &entry ) );
	}

	CloseHandle( snapshot );
	return pid;
}

bool Driver::Attach( const std::wstring& processName ) {
	Detach( );

	this->process_id = FindProcessID( processName );
	if ( !this->process_id ) {
		return false;
	}

	this->hProcess = OpenProcess( PROCESS_ALL_ACCESS , FALSE , this->process_id );
	if ( !this->hProcess || this->hProcess == INVALID_HANDLE_VALUE ) {
		this->process_id = 0;
		return false;
	}

	this->base_address = GetProcessBaseAddress( this->process_id );
	if ( !this->base_address ) {
		Detach( );
		return false;
	}

	this->module_size = GetModuleSize( this->base_address );
	if ( !this->module_size ) {
		Detach( );
		return false;
	}

	return true;
}

void Driver::Detach( ) {
	if ( this->hProcess && this->hProcess != INVALID_HANDLE_VALUE ) {
		CloseHandle( this->hProcess );
		this->hProcess = INVALID_HANDLE_VALUE;
	}

	this->process_id = 0;
	this->base_address = 0;
	this->module_size = 0;
}


uint64_t Driver::GetModuleSize( uint64_t baseAddress ) {
	if ( !this->process_id || !baseAddress ) {
		return 0;
	}

	IMAGE_DOS_HEADER dos_header = { 0 };
	if ( !ReadMemory( this->process_id , baseAddress , &dos_header , sizeof( dos_header ) ) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ) {
		return 0;
	}

	IMAGE_NT_HEADERS nt_headers = { 0 };
	if ( !ReadMemory( this->process_id , baseAddress + dos_header.e_lfanew , &nt_headers , sizeof( nt_headers ) ) || nt_headers.Signature != IMAGE_NT_SIGNATURE ) {
		return 0;
	}

	return nt_headers.OptionalHeader.SizeOfImage;
}

uint64_t Driver::GetModuleBaseAddress( const std::wstring& moduleName ) {
	if ( this->process_id == 0 ) return 0;

	uint64_t baseAddress = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 , this->process_id );
	if ( snapshot != INVALID_HANDLE_VALUE ) {
		MODULEENTRY32W entry = { 0 };
		entry.dwSize = sizeof( MODULEENTRY32W );

		if ( Module32FirstW( snapshot , &entry ) ) {
			do {
				if ( moduleName == entry.szModule ) {
					baseAddress = ( uint64_t ) entry.modBaseAddr;
					break;
				}
			} while ( Module32NextW( snapshot , &entry ) );
		}
		CloseHandle( snapshot );
	}
	return baseAddress;
}

std::string Driver::ReadString( uint64_t address , size_t size ) {
	std::vector<char> buffer( size );
	if ( ReadMemory( this->process_id , address , buffer.data( ) , size ) ) {
		for ( size_t i = 0; i < size; ++i ) {
			if ( buffer [ i ] == '\0' ) {
				return std::string( buffer.data( ) , i );
			}
		}
		return std::string( buffer.data( ) , size );
	}
	return "";
}
std::vector<uint8_t> Driver::PatternToVector( const std::string& pattern ) {
	std::vector<uint8_t> result;
	std::stringstream ss( pattern );
	std::string byte_str;

	while ( ss >> byte_str ) {
		if ( byte_str == "?" || byte_str == "??" ) {
			result.push_back( 0x00 );
		}
		else {
			result.push_back( static_cast< uint8_t >( std::stoul( byte_str , nullptr , 16 ) ) );
		}
	}
	return result;
}

uintptr_t Driver::ResolveRelativeAddress( uintptr_t address , int offset , int instruction_len ) {
	if ( !this->process_id || !address ) {
		return 0;
	}

	int32_t relative_offset = ReadMemory<int32_t>( this->process_id , address + offset );
	if ( !relative_offset ) {
		return 0;
	}

	return address + instruction_len + relative_offset;
}

bool Driver::PatchBytes( uintptr_t address , const std::vector<uint8_t>& bytes ) {
	if ( !this->process_id || !address ) {
		return false;
	}
	return WriteMemory( this->process_id , address , ( void* ) bytes.data( ) , bytes.size( ) );
}

bool Driver::NopBytes( uintptr_t address , int count ) {
	if ( count <= 0 ) return false;
	std::vector<uint8_t> nop_bytes( count , 0x90 );
	return PatchBytes( address , nop_bytes );
}

uintptr_t Driver::FindSignature( const std::vector<uint8_t>& signature , uintptr_t module_base , uintptr_t module_size ) {
	if ( !module_base || !module_size || signature.empty( ) ) {
		return 0;
	}

	const size_t CHUNK_SIZE = 4096;
	std::vector<uint8_t> chunk( CHUNK_SIZE );
	ULONG old_protection = 0;

	for ( uintptr_t current_offset = 0; current_offset < module_size; current_offset += CHUNK_SIZE - signature.size( ) ) {
		uint64_t read_address = module_base + current_offset;

		if ( !this->ProtectVirtualMemory( read_address , CHUNK_SIZE , PAGE_EXECUTE_READWRITE , &old_protection ) ) {
			continue;
		}

		bool read_success = this->ReadMemory( this->process_id , read_address , chunk.data( ) , CHUNK_SIZE );

		this->ProtectVirtualMemory( read_address , CHUNK_SIZE , old_protection , &old_protection );

		if ( !read_success ) {
			return 0;
		}

		for ( size_t i = 0; i < CHUNK_SIZE - signature.size( ); ++i ) {
			bool match = true;
			for ( size_t j = 0; j < signature.size( ); ++j ) {
				if ( signature [ j ] != 0x00 && chunk [ i + j ] != signature [ j ] ) {
					match = false;
					break;
				}
			}

			if ( match ) {
				uintptr_t found_address = module_base + current_offset + i;
				return found_address;
			}
		}
	}
	return 0;
}

uintptr_t Driver::PatternScan( const std::string& pattern , int offset , int instruction_len ) {
	if ( !this->process_id || !this->base_address ) {
		return 0;
	}

	std::vector<uint8_t> signature = PatternToVector( pattern );
	if ( signature.empty( ) ) {
		return 0;
	}

	uintptr_t signature_address = FindSignature( signature , this->base_address , this->module_size );
	if ( !signature_address ) {
		return 0;
	}

	if ( offset > 0 && instruction_len > 0 ) {
		return ResolveRelativeAddress( signature_address , offset , instruction_len );
	}

	return signature_address;
}

BOOL Driver::PatchFunc( uintptr_t Addr , int NopCount ) {
	if ( !NopCount ) return false;

	std::vector<uint8_t> PatchTable = { };
	for ( int i = 0; i < NopCount; i++ ) {
		PatchTable.push_back( { 0x90 } );
	}

	return WriteBytes( Addr , PatchTable );
}

DWORD Driver::ExecuteShellcode( const unsigned char* shellcode , size_t size ) {
	if ( !this->hProcess || this->hProcess == INVALID_HANDLE_VALUE ) {
		return 0;
	}

	LPVOID remote_memory = VirtualAllocEx( this->hProcess , nullptr , size , MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE );
	if ( !remote_memory ) {
		return 0;
	}

	if ( !this->WriteMemoryImpl( reinterpret_cast< uint64_t >( remote_memory ) , ( void* ) shellcode , size ) ) {
		VirtualFreeEx( this->hProcess , remote_memory , 0 , MEM_RELEASE );
		return 0;
	}

	HANDLE hThread = CreateRemoteThread( this->hProcess , nullptr , 0 , ( LPTHREAD_START_ROUTINE ) remote_memory , nullptr , 0 , nullptr );
	if ( !hThread ) {
		VirtualFreeEx( this->hProcess , remote_memory , 0 , MEM_RELEASE );
		return 0;
	}

	WaitForSingleObject( hThread , INFINITE );

	DWORD exitCode = 0;
	GetExitCodeThread( hThread , &exitCode );

	CloseHandle( hThread );
	VirtualFreeEx( this->hProcess , remote_memory , 0 , MEM_RELEASE );

	return exitCode;
}

bool Driver::MoveMouse(int dx, int dy) {
	Request::MouseMove request = { 0 };
	request.security = DRIVER_SECURITY_CODE;
	request.dx = dx;
	request.dy = dy;

	return SendIoControl(IOCTL_MOUSE_MOVE, &request, sizeof(request));
}

std::vector<uint8_t> Driver::ReadBytes( uintptr_t Addr , size_t Size ) {
	std::vector<uint8_t> bytes( Size );

	if ( ReadMemoryImpl( Addr , bytes.data( ) , Size ) ) {
		return bytes;
	}

	return {};
}

BOOL Driver::WriteBytes( uintptr_t Addr , std::vector<uint8_t> Bytes ) {

	return WriteMemoryImpl( Addr , Bytes.data( ) , Bytes.size( ) );
}