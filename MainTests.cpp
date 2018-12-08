#include <iostream>
#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"

int main(int argc, char* const argv[]) {
	int result = Catch::Session().run(argc, argv);

	std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
	std::cout << "Press enter key to exit..." << std::endl;
	getchar();
	return result;
}

