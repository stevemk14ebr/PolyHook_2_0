#ifndef POLYHOOK_2_0_ERRORLOG_HPP
#define POLYHOOK_2_0_ERRORLOG_HPP

#include <vector>
#include <string>
#include <iostream>
#include "polyhook2/Enums.hpp"

namespace PLH {

struct Error {
	std::string msg;
	ErrorLevel lvl;
};

class ErrorLog {
public:
	void setLogLevel(ErrorLevel level) {
		m_logLevel = level;
	}
	
	void push(std::string msg, ErrorLevel level) {
			push({ std::move(msg), level });
	}

	void push(Error err) {
		if (err.lvl >= m_logLevel) { 
			switch (err.lvl) {
			case ErrorLevel::INFO:
				std::cout << "[+] Info: " << err.msg << std::endl;
				break;
			case ErrorLevel::WARN:
				std::cout << "[!] Warn: " << err.msg << std::endl;
				break;
			case ErrorLevel::SEV:
				std::cout << "[!] Error: " << err.msg << std::endl;
				break;
			default:
				std::cout << "Unsupported error message logged " << err.msg << std::endl;
			}
		}
		
		m_log.push_back(std::move(err));
	}

	Error pop() {
		Error err{};
		if (!m_log.empty()) {
			err = std::move(m_log.back());
			m_log.pop_back();
		}
		return std::move(err);
	}

	static ErrorLog& singleton() {
		static ErrorLog log;
		return log;
	}
private:
	std::vector<Error> m_log;
	ErrorLevel m_logLevel = ErrorLevel::INFO;
};


}

#endif
