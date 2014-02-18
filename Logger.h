#pragma once
#include <string>

class Logger
{
public:
	void SetFile(const std::wstring& in_sFileName);	
	bool LogEvent(const WORD in_Type, const wchar_t* pFormat, ...);

	static Logger& GetInstance()
	{
		static Logger s_log;
		return s_log;
	}

private:

	bool Log(const WORD in_Type, const std::wstring& in_sMsg);
	std::wstring	m_strFile;
};