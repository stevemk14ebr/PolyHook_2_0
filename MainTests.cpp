#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"
#include <iostream>

#include "polyhook2/ErrorLog.hpp"
int main(int argc, char* const argv[]) {
	std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
	auto logger = std::make_shared<PLH::ErrorLog>();
	logger->setLogLevel(PLH::ErrorLevel::INFO);
	PLH::Log::registerLogger(logger);
	int result = Catch::Session().run(argc, argv);

	getchar();
	return result;
}

