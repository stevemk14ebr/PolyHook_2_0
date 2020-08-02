#ifndef POLYHOOK_2_0_ERRORLOG_HPP
#define POLYHOOK_2_0_ERRORLOG_HPP

#include <vector>
#include <string>
#include <iostream>
#include "polyhook2/Enums.hpp"

namespace PLH {

// abstract base class for logging, clients should subclass this to intercept log messages
class Logger
{
public:
	virtual void log(std::string msg, ErrorLevel level) = 0;
	virtual ~Logger() {};
};

// class for registering client loggers
class Log
{
private:
	static std::shared_ptr<Logger> m_logger;
public:
	static void registerLogger(std::shared_ptr<Logger> logger);
	static void log(std::string msg, ErrorLevel level);
};

// simple logger implementation

struct Error {
	std::string msg;
	ErrorLevel lvl;
};

class ErrorLog : public Logger {
public:
	void setLogLevel(ErrorLevel level);
	void log(std::string msg, ErrorLevel level);
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
