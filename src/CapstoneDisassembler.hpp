//
// Created by steve on 3/22/17.
//

#ifndef POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
#define POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP

#include <inttypes.h>
#include "ADisassembler.hpp"
#include "../capstone/include/capstone/capstone.h"

namespace PLH
{
    class CapstoneDisassembler : public ADisassembler
    {
    public:
        CapstoneDisassembler(ADisassembler::Mode mode) : ADisassembler(mode)
        {
            cs_mode capmode = mode == ADisassembler::Mode::x64 ? CS_MODE_64 : CS_MODE_32;
            if (cs_open(CS_ARCH_X86, capmode, &m_CapHandle) != CS_ERR_OK)
                m_ErrorCallback.Invoke(PLH::Message("Capstone Init Failed"));

            cs_option(m_CapHandle, CS_OPT_DETAIL, CS_OPT_ON);
        }

        virtual std::vector<Instruction> Disassemble(uint64_t Start, uint64_t End) override;

    private:
        csh m_CapHandle;
    };
}

std::vector<PLH::Instruction> PLH::CapstoneDisassembler::Disassemble(uint64_t Start, uint64_t End)
{
    cs_insn* InsInfo = cs_malloc(m_CapHandle);
    std::vector<PLH::Instruction> InsVec;
    
    size_t Size = End-Start;
    while(cs_disasm_iter(m_CapHandle,(const uint8_t**)(&Start),&Size,&Start,InsInfo))
    {
        printf("%" PRId64 "[%d]: ", InsInfo->address, InsInfo->size);
        for (uint_fast32_t j = 0; j < InsInfo->size; j++)
            printf("%02X ", InsInfo->bytes[j]);
        printf("%s %s\n", InsInfo->mnemonic, InsInfo->op_str);
    }
    cs_free(InsInfo,1);
    return InsVec;
}

#endif //POLYHOOK_2_0_CAPSTONEDISASSEMBLER_HPP
