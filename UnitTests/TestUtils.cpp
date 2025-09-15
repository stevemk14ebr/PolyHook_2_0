#include "./TestUtils.hpp"

#include "polyhook2/ErrorLog.hpp"
#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/MemProtector.hpp"

#include <memory>

namespace PLH::test {

void registerTestLogger() {
	const auto logger = std::make_shared<PLH::ErrorLog>();
	logger->setLogLevel(PLH::ErrorLevel::INFO);
	PLH::Log::registerLogger(logger);
}

void makeMemoryPageExecutable(const uint8_t byteArray[]) {
	PLH::MemAccessor memAccessor;

	PLH::MemoryProtector prot(
		reinterpret_cast<uint64_t>(byteArray),
		sizeof(byteArray),
		PLH::ProtFlag::R | PLH::ProtFlag::W | PLH::ProtFlag::X,
		memAccessor,
		false
	);
}
}
