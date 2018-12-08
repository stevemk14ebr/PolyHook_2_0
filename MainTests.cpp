#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"
#include <iostream>

int main(int argc, char* const argv[]) {
	std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
	int result = Catch::Session().run(argc, argv);

	getchar();
	return result;
}

