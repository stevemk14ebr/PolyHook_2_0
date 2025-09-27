#include "./TestUtils.hpp"

#include "polyhook2/ErrorLog.hpp"

#include <memory>

namespace PLH::test {

void registerTestLogger() {
	const auto logger = std::make_shared<PLH::ErrorLog>();
	logger->setLogLevel(PLH::ErrorLevel::INFO);
	PLH::Log::registerLogger(logger);
}

}
