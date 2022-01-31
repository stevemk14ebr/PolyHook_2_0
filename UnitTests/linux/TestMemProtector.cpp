#include "Catch.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Tests/StackCanary.hpp"

#include "polyhook2/PolyHookOsIncludes.hpp"

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		PLH::StackCanary canary;
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X) == PROT_EXEC);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R) == PROT_READ);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::W) == PROT_WRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R | PLH::ProtFlag::W) == (PROT_READ|PROT_WRITE));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::R) == (PROT_EXEC|PROT_READ));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W) == (PROT_EXEC|PROT_WRITE));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R) == (PROT_EXEC|PROT_WRITE|PROT_READ));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::NONE) == PROT_NONE);
	}

	SECTION("native to flags") {
		PLH::StackCanary canary;
		REQUIRE(PLH::TranslateProtection(PROT_EXEC) == PLH::ProtFlag::X);
		REQUIRE(PLH::TranslateProtection(PROT_READ) == PLH::ProtFlag::R);
		REQUIRE(PLH::TranslateProtection(PROT_WRITE) == PLH::ProtFlag::W);
		REQUIRE(PLH::TranslateProtection(PROT_WRITE|PROT_READ) == (PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_EXEC|PROT_READ) == (PLH::ProtFlag::X | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_EXEC|PROT_WRITE) == (PLH::ProtFlag::X | PLH::ProtFlag::W));
		REQUIRE(PLH::TranslateProtection(PROT_EXEC|PROT_WRITE|PROT_READ) == (PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_NONE) == PLH::ProtFlag::NONE);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	PLH::StackCanary canary;
	char* page = (char*)mmap(nullptr, 4*1024, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	bool isGood = page != nullptr; // indirection because catch reads var, causing access violation
	REQUIRE(isGood);
	PLH::MemAccessor accessor;

	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::R, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::W, accessor);
		REQUIRE(prot1.isGood());
		REQUIRE(prot1.originalProt() == PLH::ProtFlag::R);

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X, accessor);
		REQUIRE(prot2.isGood());
		REQUIRE((prot2.originalProt() & PLH::ProtFlag::W));
	}

	// protection should now be NOACCESS if destructors worked
	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::W, accessor);
		REQUIRE(prot.isGood());
		REQUIRE((prot1.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::R)));

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R | PLH::ProtFlag::W, accessor);
		REQUIRE(prot.isGood());
		REQUIRE(prot2.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::W));
	}
	munmap(page, 4*1024);
}