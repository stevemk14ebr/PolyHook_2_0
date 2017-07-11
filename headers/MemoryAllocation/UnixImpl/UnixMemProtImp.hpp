//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_X86MEMPROTIMP_HPP
#define POLYHOOK_2_X86MEMPROTIMP_HPP

#include "headers/Maybe.hpp"
#include "headers/Enums.hpp"

#include <sys/mman.h>

namespace PLH{

class UnixMemProtImp{
public:
    PLH::Maybe<PLH::ProtFlag> Protect(const uint64_t address, const uint64_t length, const int flags) {
        assert(address % getpagesize() == 0);

        if(mprotect((void*)address, length, flags) == 0)
            return PLH::ProtFlag::UNSET; //TODO: use RangeMemAllocator's to walk protections
        function_fail(std::string(strerror(errno)));
    }
};

}

#endif //POLYHOOK_2_X86MEMPROTIMP_HPP
