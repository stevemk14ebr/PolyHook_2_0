#include "Catch.hpp"
#include "headers/MemProtector.hpp"

#ifdef _WIN32 
	
TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X) == PAGE_EXECUTE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R) == PAGE_READONLY);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R | PLH::ProtFlag::W) == PAGE_READWRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::R) == PAGE_EXECUTE_READ);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W) == PAGE_EXECUTE_READWRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R) == PAGE_EXECUTE_READWRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::NONE) == PAGE_NOACCESS);
	}

	SECTION("native to flags") {
		REQUIRE(PLH::TranslateProtection(PAGE_EXECUTE) == PLH::ProtFlag::X);
		REQUIRE(PLH::TranslateProtection(PAGE_READONLY) == PLH::ProtFlag::R);
		REQUIRE(PLH::TranslateProtection(PAGE_READWRITE) == (PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PAGE_EXECUTE_READ) == (PLH::ProtFlag::X | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PAGE_EXECUTE_READWRITE) == (PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PAGE_NOACCESS) == PLH::ProtFlag::NONE);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	char* page = (char*)VirtualAlloc(0, 4 * 1024, MEM_COMMIT, PAGE_NOACCESS);
	bool isGood = page != nullptr; // indirection because catch reads var, causing access violation
	REQUIRE(isGood);

	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::R);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::W);
		REQUIRE(prot1.isGood());
		REQUIRE(prot1.originalProt() == PLH::ProtFlag::R);

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X);
		REQUIRE(prot2.isGood());
		REQUIRE((prot2.originalProt() & PLH::ProtFlag::W));
	}

	// protection should now be NOACCESS if destructors worked
	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::W);
		REQUIRE(prot.isGood());
		REQUIRE((prot1.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::R)));

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R | PLH::ProtFlag::W);
		REQUIRE(prot.isGood());
		REQUIRE(prot2.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::R | PLH::ProtFlag::W));
	}
	VirtualFree(page, 4 * 1024, MEM_RELEASE);
}

#else

TEST_CASE("Test protflag translation", "[MemProtector],[Enums]") {
	SECTION("flags to native") {
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X) == PROT_EXEC);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R) == PROT_READ);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::W) == PROT_WRITE);
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::R | PLH::ProtFlag::W) == (PROT_READ|PROT_WRITE));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::R) == (PROT_READ|PROT_EXEC));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W) == (PROT_EXEC|PROT_WRITE));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R) == (PROT_READ|PROT_WRITE|PROT_EXEC));
		REQUIRE(PLH::TranslateProtection(PLH::ProtFlag::NONE) == PROT_NONE);
	}

	SECTION("native to flags") {
		REQUIRE(PLH::TranslateProtection(PROT_EXEC) == PLH::ProtFlag::X);
		REQUIRE(PLH::TranslateProtection(PROT_READ) == PLH::ProtFlag::R);
		REQUIRE(PLH::TranslateProtection(PROT_READ|PROT_WRITE) == (PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_READ|PROT_EXEC) == (PLH::ProtFlag::X | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_READ|PROT_WRITE|PROT_EXEC) == (PLH::ProtFlag::X | PLH::ProtFlag::W | PLH::ProtFlag::R));
		REQUIRE(PLH::TranslateProtection(PROT_NONE) == PLH::ProtFlag::NONE);
	}
}

TEST_CASE("Test setting page protections", "[MemProtector]") {
	int pagesize = getpagesize();
	void* page = mmap(0, pagesize, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
	
	if (page == MAP_FAILED) {
		printf("mmap failed:  %s\n", strerror(errno));
		REQUIRE(false);
	}	

	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::R);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::W);
		REQUIRE(prot1.isGood());
		REQUIRE(prot1.originalProt() == PLH::ProtFlag::R);

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X);
		REQUIRE(prot2.isGood());
		REQUIRE((prot2.originalProt() & PLH::ProtFlag::W));
	}

	// protection should now be NOACCESS if destructors worked
	{
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R);
		REQUIRE(prot.isGood());
		REQUIRE(prot.originalProt() == PLH::ProtFlag::NONE);

		PLH::MemoryProtector prot1((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::W);
		REQUIRE(prot.isGood());
		REQUIRE((prot1.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::R)));

		PLH::MemoryProtector prot2((uint64_t)page, 4 * 1024, PLH::ProtFlag::X | PLH::ProtFlag::R | PLH::ProtFlag::W);
		REQUIRE(prot.isGood());
		REQUIRE(prot2.originalProt() == (PLH::ProtFlag::X | PLH::ProtFlag::R | PLH::ProtFlag::W));
	}
	munmap(page, pagesize);
}

#endif
