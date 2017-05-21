//
// Created by steve on 4/7/17.
//
#include "../../Catch.hpp"
#include "../../src/MemoryAllocation/RangeMemorySTLAllocator.h"
#include <inttypes.h>

void PlaceHolderFunction()
{
    printf("Not useful, ignore me totally");
}

TEST_CASE("Tests memory allocator for Unix platform","[ARangeMemAllocator],[RangeMemAllocatorUnixImp]")
{
    std::cout << std::dec << "Process ID: " << getpid();
    PLH::MemAllocatorUnix allocator;
    PLH::ProtFlag R = PLH::ProtFlag::R;
    PLH::ProtFlag W = PLH::ProtFlag::W;
    PLH::ProtFlag X = PLH::ProtFlag::X;
    PLH::ProtFlag N = PLH::ProtFlag::NONE;

    REQUIRE(allocator.TranslateProtection(X) == PROT_EXEC);
    REQUIRE(allocator.TranslateProtection(W) == PROT_WRITE);
    REQUIRE(allocator.TranslateProtection(R) == PROT_READ);
    REQUIRE(allocator.TranslateProtection(N) == PROT_NONE);

    REQUIRE(allocator.TranslateProtection(X | W | R | N) == (PROT_EXEC | PROT_WRITE | PROT_READ | PROT_NONE));

    uint64_t fnAddress = (uint64_t)&PlaceHolderFunction;
    uint64_t MinAddress = fnAddress < 0x80000000 ? 0 : fnAddress - 0x80000000;  //Use 0 if would underflow
    uint64_t MaxAddress = fnAddress > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                          std::numeric_limits<uint64_t>::max() : fnAddress + 0x80000000;

    std::cout << "fnAddress: " << std::hex << fnAddress << " Acceptable Range:" << MinAddress << "-" << MaxAddress << std::endl;

    int PageSize = getpagesize();
    std::cout << std::dec << "PageSize: " << PageSize << std::endl;

    auto AllocBlock = allocator.AllocateMemory(MinAddress,MaxAddress, 200, (X | W | R));
    REQUIRE(AllocBlock);
    std::shared_ptr<uint8_t> Buffer = AllocBlock.get().GetParentBlock();
    REQUIRE(Buffer != nullptr);
    std::cout << std::hex << "Allocated At: " << (uint64_t )Buffer.get()<< std::endl;

    //Compute some statistics about how far away allocation was
    std::intmax_t AllocDelta = imaxabs((std::intmax_t) Buffer.get() - fnAddress);
    double DeltaInGB = AllocDelta / 1000000000.0; //How far was our trampoline allocated from the target, in GB
    double DeltaPercentage = DeltaInGB / .5 * 100.0; //Allowed range is +-2GB, see in percentage how close to tolerance we were
    std::cout << "Delta:[" << DeltaInGB << " GB] Percent Tolerance Used[" << DeltaPercentage << " % out of 2GB]" << std::endl;
    REQUIRE(DeltaInGB <= 2);

    allocator.DeallocateMemory(AllocBlock.get());

    std::vector<int,PLH::Allocator<int,PLH::MemAllocatorUnix>> alloc_vec(PLH::Allocator<int,PLH::MemAllocatorUnix>(MinAddress,MaxAddress));
    alloc_vec.push_back(1);
    alloc_vec.push_back(2);
    std::cout << alloc_vec[0] << alloc_vec[1] << std::endl;
}


