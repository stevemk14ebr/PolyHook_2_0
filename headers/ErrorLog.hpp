#ifndef POLYHOOK_2_0_ERRORLOG_HPP
#define POLYHOOK_2_0_ERRORLOG_HPP

#include <vector>
#include <string>
#include <iostream>
#include "headers/Enums.hpp"

namespace PLH {

struct Error {
	std::string msg;
	ErrorLevel lvl;
};

class ErrorLog {
public:
	void push(const std::string& msg, ErrorLevel level) {
		Error err;
		err.msg = msg;
		err.lvl = level;
		push(err);
	}

	void push(const Error& err) {
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
		
		m_log.push_back(err);
	}

	Error pop() {
		Error err = {};
		if (!m_log.empty()) {
			err = m_log.back();
			m_log.pop_back();
		}
		return err;
	}

	static ErrorLog& singleton() {
		static ErrorLog log;
		return log;
	}
private:
	std::vector<Error> m_log;
};


}

#endif
