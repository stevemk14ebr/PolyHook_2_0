#ifndef POLYHOOK_2_0_ERRORLOG_HPP
#define POLYHOOK_2_0_ERRORLOG_HPP

#include <vector>
#include <string>
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
		std::cout << "[!]ERROR:" << err.msg << std::endl;
		m_log.push_back(err);
	}

	Error pop() {
		Error err = m_log.back();
		m_log.pop_back();
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