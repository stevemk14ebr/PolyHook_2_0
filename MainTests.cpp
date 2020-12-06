#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"
#include <iostream>

#include "polyhook2/ErrorLog.hpp"
int main(int argc, char* const argv[]) {
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF );
	std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
	auto logger = std::make_shared<PLH::ErrorLog>();
	logger->setLogLevel(PLH::ErrorLevel::INFO);
	PLH::Log::registerLogger(logger);
	int result = Catch::Session().run(argc, argv);

	getchar();
	return result;
}

