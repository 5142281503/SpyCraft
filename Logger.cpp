#include "stdafx.h"
#include <fstream>		// wofstream
#include "Logger.h"
#include "helpers.h"	// GetCurrentTimeFormatted

void 
Logger::SetFile(const std::wstring& in_sFileName)
{
	if( !in_sFileName.empty() && m_strFile.empty() )
	{
		m_strFile = in_sFileName + helpers::GetCurrentTimeFormatted(L"%A %B-%d-%y %H.%M.%S") + L".txt";			
	}
}

bool 
Logger::Log(const WORD in_Type, const std::wstring& in_sMsg)
{
	std::wofstream f(m_strFile.c_str(), std::ios::app | std::ios::in);

	if(f)
	{
		if(EVENTLOG_ERROR_TYPE == in_Type) // simply make errors stand out more
			f << " ** ";

		f << helpers::GetCurrentTimeFormatted(L"%H.%M.%S") << L"  ";

		f << in_sMsg << std::endl;

		return true;
	}
	return false;
}

// Logs to pre-set file.
bool 
Logger::LogEvent(const WORD in_Type, const wchar_t* pFormat, ...)
{
	if(m_strFile.empty()) return false;

	bool bRet = false;
	wchar_t chMsg[8192+1] = { 0 };
    va_list pArg;

    va_start(pArg, pFormat);
	vswprintf_s(chMsg, 8192, pFormat, pArg);
    va_end(pArg);

	return Log(in_Type, chMsg);
}