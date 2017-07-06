//
// Created by steve on 4/7/17.
//
#include "Catch.hpp"
#include "headers/MemoryAllocation/RangeAllocator.hpp"
#include <inttypes.h>

volatile void PlaceHolderFunction() {
    printf("Not useful, ignore me totally");
}

uint64_t fnAddress = (uint64_t)&PlaceHolderFunction;
uint64_t MinAddress = fnAddress < 0x80000000 ? 0 : fnAddress - 0x80000000;            //Use 0 if would underflow
uint64_t MaxAddress = fnAddress > std::numeric_limits<uint64_t>::max() - 0x80000000 ? //use max if would overflow
                      std::numeric_limits<uint64_t>::max() : fnAddress + 0x80000000;

//http://stackoverflow.com/questions/25555683/implementation-of-permutation-combinations-and-powerset-in-c
bool increase(std::vector<bool>& bs) {
    for (std::size_t i = 0; i != bs.size(); ++i) {
        bs[i] = !bs[i];
        if (bs[i] == true) {
            return true;
        }
    }
    return false; // overflow
}

template<typename T>
std::vector<std::vector<T>> PowerSet(const std::vector<T>& v) {
    std::vector<bool> bitset(v.size());
    std::vector<std::vector<T>> sets;
    do {
        std::vector<T> set;
        for (std::size_t i = 0; i != v.size(); ++i) {
            if (bitset[i]) {
                set.push_back(v[i]);
            }
        }
        sets.push_back(set);
    } while (increase(bitset));
    return sets;
}

TEST_CASE("Test Unix allocator implementation", "[RangeMemAllocatorUnixImp]") {
    PLH::MemAllocatorUnix allocator;
    PLH::ProtFlag R = PLH::ProtFlag::R;
    PLH::ProtFlag W = PLH::ProtFlag::W;
    PLH::ProtFlag X = PLH::ProtFlag::X;
    PLH::ProtFlag N = PLH::ProtFlag::NONE;

    SECTION("Test Protection Flag bit OR-ing and translation") {
        REQUIRE(allocator.TranslateProtection(X) == PROT_EXEC);
        REQUIRE(allocator.TranslateProtection(W) == PROT_WRITE);
        REQUIRE(allocator.TranslateProtection(R) == PROT_READ);
        REQUIRE(allocator.TranslateProtection(N) == PROT_NONE);

        //Test all combinations translate properly
        auto plhSets = PowerSet<PLH::ProtFlag>({R, W, X, N});
        auto lnxSets = PowerSet<int>({PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE});
        for (int i = 0; i < plhSets.size(); i++) {
            PLH::ProtFlag plhFlag = PLH::ProtFlag::UNSET;
            int lnxFlag = 0;
            for (int j = 0; j < plhSets[i].size(); j++) {
                plhFlag = plhFlag | plhSets[i][j];
                lnxFlag = lnxFlag | lnxSets[i][j];
            }
            REQUIRE(allocator.TranslateProtection(plhFlag) == lnxFlag);
        }
    }

    SECTION("Test implementation can allocate in range") {
        std::cout
                << "fnAddress: "
                << std::hex
                << fnAddress
                << " Acceptable Range:"
                << MinAddress
                << "-"
                << MaxAddress
                << std::endl;

        int PageSize = getpagesize();
        std::cout << std::dec << "PageSize: " << PageSize << std::endl;

        //Try to allocate a few pages
        for (int i = 0; i < 100; i++) {
            auto AllocBlock = allocator.AllocateMemory(MinAddress, MaxAddress, PageSize, (X | W | R));
            REQUIRE(AllocBlock.isOk());
            std::shared_ptr<uint8_t> Buffer = AllocBlock.unwrap().GetParentBlock();
            REQUIRE(Buffer != nullptr);
            std::cout << std::hex << "Allocated At: " << (uint64_t)Buffer.get() << std::endl;

            //Compute some statistics about how far away allocation was
            std::intmax_t AllocDelta = imaxabs((std::intmax_t)Buffer.get() - fnAddress);
            double DeltaInGB = AllocDelta /
                               std::pow(10.0,
                                        9);                                   //How far was our trampoline allocated from the target, in GB
            double DeltaPercentage = DeltaInGB *
                                     100.0;                                //Allowed range is +-2GB, see in percentage how close to tolerance we were
            std::cout << "Delta:[" << DeltaInGB << " GB] Percent Tolerance Used[" << DeltaPercentage << " % out of 2GB]"
                      << std::endl;

            REQUIRE(DeltaInGB <= 2);
        }
    }
}

TEST_CASE("Test MemoryBlock", "[MemoryBlock]") {
    PLH::MemoryBlock block(0x7896, 0x9876, PLH::ProtFlag::UNSET);
    REQUIRE(block.GetStart() == 0x7896);
    REQUIRE(block.GetEnd() == 0x9876);
    REQUIRE(block.GetSize() == 0x1FE0);

    size_t Alignment = 4;
    auto first = block.GetAlignedFirst(Alignment, 8);
    REQUIRE(first.isOk());
    REQUIRE(first.unwrap() == 0x7898);

    auto next = block.GetAlignedNext(first.unwrap(), Alignment, 8);
    REQUIRE(next.isOk());
    REQUIRE(next.unwrap() == 0x78A0);
}

TEST_CASE("Test AllocatedMemoryBlock", "[AllocatedMemoryBlock]") {

}

TEST_CASE("Test range allocator STL wrapper", "[RangeMemorySTLAllocator]") {
    std::cout
            << "fnAddress: "
            << std::hex
            << fnAddress
            << " Acceptable Range:"
            << MinAddress
            << "-"
            << MaxAddress
            << std::endl;

    bool Exception = false;
    try {
        std::vector<int, PLH::RangeAllocator<int, PLH::MemAllocatorUnix>> alloc_vec(
                PLH::RangeAllocator<int, PLH::MemAllocatorUnix>(MinAddress, MaxAddress));
        std::vector<int> correct_vec;
        for (int i = 0; i < 5000; i++) {
            alloc_vec.push_back(i);
            correct_vec.push_back(i);
        }

        //Our custom allocated vector must have the same contents of a standard vector
        REQUIRE(std::equal(alloc_vec.begin(), alloc_vec.end(), correct_vec.begin()));

        //The entire contents must be within [MinAddress, MaxAddress)
        REQUIRE((uint64_t)&alloc_vec[0] >= MinAddress);
        REQUIRE((uint64_t)&alloc_vec[0] + (alloc_vec.size() * sizeof(int)) < MaxAddress);

        alloc_vec.erase(alloc_vec.begin(), alloc_vec.begin() + 10);
        REQUIRE(alloc_vec[1] != 1);
        alloc_vec.reserve(100);
        alloc_vec.shrink_to_fit();
    }catch (const PLH::AllocationFailure& ex) {
        Exception = true;
        std::cout << ex.what() << std::endl;
    }catch (const std::exception& ex) {
        Exception = true;
    }
    REQUIRE(Exception == false);
}


