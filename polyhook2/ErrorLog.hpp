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
	void setLogLevel(ErrorLevel level);
	void push(std::string msg, ErrorLevel level);
	void push(Error err);
	Error pop();
	static ErrorLog& singleton();
private:
	std::vector<Error> m_log;
	ErrorLevel m_logLevel = ErrorLevel::INFO;
};
}

#endif
