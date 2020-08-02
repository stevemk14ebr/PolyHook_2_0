#include "polyhook2/ErrorLog.hpp"

std::shared_ptr<PLH::Logger> PLH::Log::m_logger = nullptr;

void PLH::Log::registerLogger(std::shared_ptr<Logger> logger) {
	m_logger = logger;
}

void PLH::Log::log(std::string msg, ErrorLevel level) {
	if (m_logger) m_logger->log(std::move(msg), level);
}

void PLH::ErrorLog::setLogLevel(PLH::ErrorLevel level) {
	m_logLevel = level;
}

void PLH::ErrorLog::log(std::string msg, ErrorLevel level)
{
	push({ std::move(msg), level });
}

void PLH::ErrorLog::push(std::string msg, ErrorLevel level)
{
	push({ std::move(msg), level });
}

void PLH::ErrorLog::push(PLH::Error err) {
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

PLH::Error PLH::ErrorLog::pop() {
	Error err{};
	if (!m_log.empty()) {
		err = m_log.back();
		m_log.pop_back();
	}
	return err;
}

PLH::ErrorLog& PLH::ErrorLog::singleton() {
	static ErrorLog log;
	return log;
}
