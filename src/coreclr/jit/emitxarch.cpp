// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX                                                                           XX
XX                             emitX86.cpp                                   XX
XX                                                                           XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
*/

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_XARCH)

/*****************************************************************************/
/*****************************************************************************/

#include "instr.h"
#include "emit.h"
#include "codegen.h"

bool emitter::IsSSEInstruction(instruction ins)
{
    return (ins >= FIRST_SSE_INSTRUCTION) && (ins <= LAST_SSE_INSTRUCTION);
}

bool emitter::IsSSEOrAVXInstruction(instruction ins)
{
    return (ins >= FIRST_SSE_INSTRUCTION) && (ins <= LAST_AVX_INSTRUCTION);
}

//------------------------------------------------------------------------
// IsKInstruction: Does this instruction require K register?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if this instruction requires K register.
//
bool emitter::IsKInstruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & KInstruction) != 0;
}

//------------------------------------------------------------------------
// IsKInstructionWithLBit: Does this instruction require K register and
//    LBIT_IN_3BYTE_VEX_PREFIX bit.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if this instruction requires K register and
//    LBIT_IN_3BYTE_VEX_PREFIX bit.
//
bool emitter::IsKInstructionWithLBit(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & KInstructionWithLBit) != 0;
}

bool emitter::IsAVXOnlyInstruction(instruction ins)
{
    return (ins >= FIRST_AVX_INSTRUCTION) && (ins <= LAST_AVX_INSTRUCTION);
}

//------------------------------------------------------------------------
// IsAvx512OnlyInstruction: Is this an Avx512 instruction?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if it is a avx512f+ instruction.
//
bool emitter::IsAvx512OnlyInstruction(instruction ins)
{
    return (ins >= FIRST_AVX512_INSTRUCTION) && (ins <= LAST_AVX512_INSTRUCTION);
}

bool emitter::IsApxOnlyInstruction(instruction ins)
{
#ifdef TARGET_AMD64
    return (ins >= FIRST_APX_INSTRUCTION) && (ins <= LAST_APX_INSTRUCTION);
#endif // TARGET_AMD64
    return false;
}

bool emitter::IsAVXVNNIFamilyInstruction(instruction ins)
{
    return (ins >= FIRST_AVXVNNI_INSTRUCTION && ins <= LAST_AVXVNNI_INSTRUCTION) || IsAVXVNNIINTInstruction(ins);
}

bool emitter::IsAVXVNNIINTInstruction(instruction ins)
{
    return (ins >= FIRST_AVXVNNIINT8_INSTRUCTION && ins <= LAST_AVXVNNIINT8_INSTRUCTION) ||
           (ins >= FIRST_AVXVNNIINT16_INSTRUCTION && ins <= LAST_AVXVNNIINT16_INSTRUCTION);
}

bool emitter::Is3OpRmwInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_vpermi2d:
        case INS_vpermi2pd:
        case INS_vpermi2ps:
        case INS_vpermi2q:
        case INS_vpermt2d:
        case INS_vpermt2pd:
        case INS_vpermt2ps:
        case INS_vpermt2q:
        case INS_vpermi2w:
        case INS_vpermt2w:
        case INS_vpermi2b:
        case INS_vpermt2b:
        {
            return true;
        }

        default:
        {
            return ((ins >= FIRST_FMA_INSTRUCTION) && (ins <= LAST_FMA_INSTRUCTION)) ||
                   (IsAVXVNNIFamilyInstruction(ins)) ||
                   ((ins >= FIRST_AVXIFMA_INSTRUCTION) && (ins <= LAST_AVXIFMA_INSTRUCTION));
        }
    }
}

bool emitter::IsBMIInstruction(instruction ins)
{
    return (ins >= FIRST_BMI_INSTRUCTION) && (ins <= LAST_BMI_INSTRUCTION);
}

//------------------------------------------------------------------------
// IsKMOVInstruction: Is this an Avx512 KMOV instruction?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if it is a KMOV instruction.
//
bool emitter::IsKMOVInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_kmovb_gpr:
        case INS_kmovw_gpr:
        case INS_kmovd_gpr:
        case INS_kmovq_gpr:
        case INS_kmovb_msk:
        case INS_kmovw_msk:
        case INS_kmovd_msk:
        case INS_kmovq_msk:
        {
            return true;
        }

        default:
        {
            return false;
        }
    }
}

regNumber emitter::getBmiRegNumber(instruction ins)
{
    switch (ins)
    {
        case INS_blsi:
        {
            return (regNumber)3;
        }

        case INS_blsmsk:
        {
            return (regNumber)2;
        }

        case INS_blsr:
        {
            return (regNumber)1;
        }

        default:
        {
            assert(IsBMIInstruction(ins));
            return REG_NA;
        }
    }
}

regNumber emitter::getSseShiftRegNumber(instruction ins)
{
    switch (ins)
    {
        case INS_psrldq:
        {
            return (regNumber)3;
        }

        case INS_pslldq:
        {
            return (regNumber)7;
        }

        case INS_psrld:
        case INS_psrlw:
        case INS_psrlq:
        {
            return (regNumber)2;
        }

        case INS_pslld:
        case INS_psllw:
        case INS_psllq:
        {
            return (regNumber)6;
        }

        case INS_psrad:
        case INS_psraw:
        case INS_vpsraq:
        {
            return (regNumber)4;
        }

        case INS_vprold:
        case INS_vprolq:
        {
            return (regNumber)1;
        }

        case INS_vprord:
        case INS_vprorq:
        {
            return (regNumber)0;
        }

        default:
        {
            assert(!"Invalid instruction for SSE2 instruction of the form: opcode reg, immed8");
            return REG_NA;
        }
    }
}

bool emitter::HasRex2Encoding(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & Encoding_REX2) != 0;
}

//------------------------------------------------------------------------
// IsApxNddCompatibleInstruction: Is this a APX-EVEX.ND compatible instruction?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if it is a APX-EVEX.ND compatible instruction.
//
bool emitter::IsApxNddCompatibleInstruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_Flags_Has_NDD) != 0;
}

//------------------------------------------------------------------------
// IsApxNfCompatibleInstruction: Is this a APX-EVEX.NF compatible instruction?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if it is a APX-EVEX.NF compatible instruction.
//
bool emitter::IsApxNfCompatibleInstruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_Flags_Has_NF) != 0;
}

//------------------------------------------------------------------------
// IsApxZuCompatibleInstruction: Is this a APX-EVEX.ZU compatible instruction?
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if it is a APX-EVEX.ZU compatible instruction.
//
bool emitter::IsApxZuCompatibleInstruction(instruction ins)
{
#ifdef TARGET_AMD64
    // For now, we only have SETZUcc enabled for EVEX.ZU.
    return ((ins >= INS_seto_apx) && (ins <= INS_setg_apx));
#else
    return false;
#endif
}

bool emitter::IsVexEncodableInstruction(instruction ins) const
{
    if (!UseVEXEncoding())
    {
        return false;
    }

    // These can use compSupportsHWIntrinsic as we'll get here for
    // some NAOT scenarios and it will already have been recorded
    // for appropriate usage.

    switch (ins)
    {
#if defined(FEATURE_HW_INTRINSICS)
        case INS_vpdpbusd:
        case INS_vpdpwssd:
        case INS_vpdpbusds:
        case INS_vpdpwssds:
        {
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVXVNNI);
        }

        case INS_vpdpwsud:
        case INS_vpdpwsuds:
        case INS_vpdpwusd:
        case INS_vpdpwusds:
        case INS_vpdpwuud:
        case INS_vpdpwuuds:
        case INS_vpdpbssd:
        case INS_vpdpbssds:
        case INS_vpdpbsud:
        case INS_vpdpbsuds:
        case INS_vpdpbuud:
        case INS_vpdpbuuds:
        {
            // Vex versions of AvxVnniInt8 + AvxVnniInt16
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVXVNNIINT);
        }

        case INS_vpmadd52huq:
        case INS_vpmadd52luq:
        {
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVXIFMA);
        }
#endif // FEATURE_HW_INTRINSICS

        default:
        {
            insFlags flags = CodeGenInterface::instInfo[ins];
            return (flags & Encoding_VEX) != 0;
        }
    }
}

//------------------------------------------------------------------------
// IsEvexEncodableInstruction: Answer the question- Can this instruction be Evex encoded.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins can be Evex encoded.
//
bool emitter::IsEvexEncodableInstruction(instruction ins) const
{
    if (!UseEvexEncoding())
    {
        return false;
    }

    // These can use compSupportsHWIntrinsic as we'll get here for
    // some NAOT scenarios and it will already have been recorded
    // for appropriate usage.

    if (IsBMIInstruction(ins) || IsKMOVInstruction(ins))
    {
        return UsePromotedEVEXEncoding();
    }

    switch (ins)
    {
#if defined(FEATURE_HW_INTRINSICS)
        case INS_aesdec:
        case INS_aesdeclast:
        case INS_aesenc:
        case INS_aesenclast:
        case INS_pclmulqdq:
        {
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AES_V512);
        }

        case INS_vpdpwsud:
        case INS_vpdpwsuds:
        case INS_vpdpwusd:
        case INS_vpdpwusds:
        case INS_vpdpwuud:
        case INS_vpdpwuuds:
        case INS_vpdpbssd:
        case INS_vpdpbssds:
        case INS_vpdpbsud:
        case INS_vpdpbsuds:
        case INS_vpdpbuud:
        case INS_vpdpbuuds:
        {
            // Evex versions of AvxVnniInt8 + AvxVnniInt16 will be supported
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVXVNNIINT_V512);
        }

        case INS_vpdpbusd:
        case INS_vpdpwssd:
        case INS_vpdpbusds:
        case INS_vpdpwssds:
        {
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVX512v3);
        }

        case INS_vpmadd52huq:
        case INS_vpmadd52luq:
        {
            return emitComp->compSupportsHWIntrinsic(InstructionSet_AVX512v2);
        }
#endif // FEATURE_HW_INTRINSICS

        default:
        {
            insFlags flags = CodeGenInterface::instInfo[ins];
            return (flags & Encoding_EVEX) != 0;
        }
    }
}

//------------------------------------------------------------------------
// IsRex2EncodableInstruction: Answer the question- Can this instruction be Rex2 encoded.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins can be Rex2 encoded.
//
bool emitter::IsRex2EncodableInstruction(instruction ins) const
{
    if (!UseRex2Encoding())
    {
        return false;
    }
    return HasRex2Encoding(ins);
}

//------------------------------------------------------------------------
// IsApxNddEncodableInstruction: Answer the question- does this instruction have apx ndd form.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins has apx ndd form.
//
bool emitter::IsApxNddEncodableInstruction(instruction ins) const
{
    if (!UsePromotedEVEXEncoding())
    {
        return false;
    }

    return IsApxNddCompatibleInstruction(ins);
}

//------------------------------------------------------------------------
// IsApxNfEncodableInstruction: Answer the question - does this instruction have Evex.nf supported
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins is Evex.nf supported.
//
bool emitter::IsApxNfEncodableInstruction(instruction ins) const
{
    if (!UsePromotedEVEXEncoding())
    {
        return false;
    }

    return IsApxNfCompatibleInstruction(ins);
}

//------------------------------------------------------------------------
// IsApxExtendedEvexInstruction: Answer the question - does this instruction have apx extended evex form.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins has apx extended evex form.
//
bool emitter::IsApxExtendedEvexInstruction(instruction ins) const
{
#ifdef TARGET_AMD64
    if (!UsePromotedEVEXEncoding())
    {
        return false;
    }

    if (IsApxNddCompatibleInstruction(ins))
    {
        return true;
    }

    if (IsApxNfCompatibleInstruction(ins))
    {
        return true;
    }

    if (IsApxOnlyInstruction(ins))
    {
        return true;
    }

    return false;
#else // !TARGET_AMD64
    return false;
#endif
}

//------------------------------------------------------------------------
// IsShiftInstruction: Answer the question- is this instruction a shift instruction.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins is a shift instruction.
//
bool emitter::IsShiftInstruction(instruction ins) const
{
    switch (ins)
    {
        case INS_rcl_1:
        case INS_rcr_1:
        case INS_rol_1:
        case INS_ror_1:
        case INS_shl_1:
        case INS_shr_1:
        case INS_sar_1:

        case INS_rcl:
        case INS_rcr:
        case INS_rol:
        case INS_ror:
        case INS_shl:
        case INS_shr:
        case INS_sar:

        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            return true;

        default:
            return false;
    }
}

//------------------------------------------------------------------------
// IsLegacyMap1: Answer the question- Is this instruction on legacy-map-1
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins is a legacy-map-1 instruction.
//
bool emitter::IsLegacyMap1(code_t code) const
{
#ifdef TARGET_AMD64
    // Lagacy-Map-1 opcode is defined as 2-byte opcode with a leading byte of 0x0F,
    // In JIT, it could be in the following style:
    // 2-byte: XX0F
    // 3-byte: 0F00XX
    // 4-byte: 0FPP00XX

    if ((code & 0xFFFF00FF) == 0x0000000F)
    {
        // 2-byte
        return true;
    }
    if ((code & 0xFFFF0000) == 0x000F0000)
    {
        // 3-byte
        return true;
    }

    if ((code & 0xFF00FF00) == 0x0F000000)
    {
        // 4-byte, need to check if PP is prefixs
        BYTE prefix = (BYTE)((code & 0xFF0000) >> 16);
        return ((prefix == 0xF2) || (prefix == 0xF3) || (prefix == 0x66));
    }

    return false;
#endif //  TARGET_AMD64
    return false;
}

//------------------------------------------------------------------------
// Answer the question: Is this a SIMD instruction.
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `true` if ins is a SIMD instruction.
//
bool emitter::IsVexOrEvexEncodableInstruction(instruction ins) const
{
    return IsVexEncodableInstruction(ins) || IsEvexEncodableInstruction(ins);
}

// Returns true if the AVX instruction is a binary operator that requires 3 operands.
// When we emit an instruction with only two operands, we will duplicate the destination
// as a source.
bool emitter::IsDstDstSrcAVXInstruction(instruction ins) const
{
    if (!UseVEXEncoding())
    {
        return false;
    }

    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_Flags_IsDstDstSrcAVXInstruction) != 0;
}

// Returns true if the AVX instruction requires 3 operands that duplicate the source
// register in the vvvv field.
bool emitter::IsDstSrcSrcAVXInstruction(instruction ins) const
{
    if (!UseVEXEncoding())
    {
        return false;
    }

    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_Flags_IsDstSrcSrcAVXInstruction) != 0;
}

bool emitter::IsThreeOperandAVXInstruction(instruction ins) const
{
    if (!UseSimdEncoding())
    {
        return false;
    }

    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_Flags_Is3OperandInstructionMask) != 0;
}

//------------------------------------------------------------------------
// HasRegularWideForm: Many x86/x64 instructions follow a regular encoding scheme where the
// byte-sized version of an instruction has the lowest bit of the opcode cleared
// while the 32-bit version of the instruction (taking potential prefixes to
// override operand size) has the lowest bit set. This function returns true if
// the instruction follows this format.
//
// Note that this bit is called `w` in the encoding table in Section B.2 of
// Volume 2 of the Intel Architecture Software Developer Manual.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction has a regular form where the 'w' bit needs to be set.
bool emitter::HasRegularWideForm(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_FLAGS_Has_Wbit) != 0;
}

//------------------------------------------------------------------------
// HasRegularWideImmediateForm: As above in HasRegularWideForm, many instructions taking
// immediates have a regular form used to encode whether the instruction takes a sign-extended
// 1-byte immediate or a (in 64-bit sign-extended) 4-byte immediate, by respectively setting and
// clearing the second lowest bit.
//
// Note that this bit is called `s` in the encoding table in Section B.2 of
// Volume 2 of the Intel Architecture Software Developer Manual.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction has a regular wide immediate form where the 's' bit needs to set.
bool emitter::HasRegularWideImmediateForm(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & INS_FLAGS_Has_Sbit) != 0;
}

//------------------------------------------------------------------------
// DoesWriteZeroFlag: check if the instruction write the
//     ZF flag.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction writes the ZF flag, false otherwise.
//
bool emitter::DoesWriteZeroFlag(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & Writes_ZF) != 0;
}

//------------------------------------------------------------------------
// DoesWriteParityFlag: check if the instruction write the
//     PF flag.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction writes the PF flag, false otherwise.
//
bool emitter::DoesWriteParityFlag(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & Writes_PF) != 0;
}

//------------------------------------------------------------------------
// DoesWriteSignFlag: check if the instruction writes the
//     SF flag.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction writes the SF flag, false otherwise.
//
bool emitter::DoesWriteSignFlag(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & Writes_SF) != 0;
}

//------------------------------------------------------------------------
// DoesResetOverflowAndCarryFlags: check if the instruction resets the
//     OF and CF flag to 0.
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if instruction resets the OF and CF flag, false otherwise.
//
bool emitter::DoesResetOverflowAndCarryFlags(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];
    return (flags & (Resets_OF | Resets_CF)) == (Resets_OF | Resets_CF);
}

//------------------------------------------------------------------------
// IsFlagsAlwaysModified: check if the instruction guarantee to modify any flags.
//
// Arguments:
//    id - instruction to test
//
// Return Value:
//    false, if instruction is guaranteed to not modify any flag.
//    true, if instruction will modify some flag.
//
bool emitter::IsFlagsAlwaysModified(instrDesc* id)
{
    instruction ins = id->idIns();
    insFormat   fmt = id->idInsFmt();

    if (fmt == IF_RRW_SHF)
    {
        if (id->idIsLargeCns())
        {
            return true;
        }
        else if (id->idSmallCns() == 0)
        {
            switch (ins)
            {
                // If shift-amount for below instructions is 0, then flags are unaffected.
                case INS_rcl_N:
                case INS_rcr_N:
                case INS_rol_N:
                case INS_ror_N:
                case INS_shl_N:
                case INS_shr_N:
                case INS_sar_N:
                    return false;
                default:
                    return true;
            }
        }
    }
    else if (fmt == IF_RRW)
    {
        switch (ins)
        {
            // If shift-amount for below instructions is 0, then flags are unaffected.
            // So, to be conservative, do not optimize if the instruction has register
            // as the shift-amount operand.
            case INS_rcl:
            case INS_rcr:
            case INS_rol:
            case INS_ror:
            case INS_shl:
            case INS_shr:
            case INS_sar:
                return false;
            default:
                return true;
        }
    }

    return true;
}

//------------------------------------------------------------------------
// IsRexW0Instruction: check if the instruction always encodes REX.W as 0
//
// Arguments:
//    id - instruction to test
//
// Return Value:
//    true if the instruction always encodes REX.W as 0; othwerwise, false
//
bool emitter::IsRexW0Instruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];

    if ((flags & REX_W0) != 0)
    {
        assert((flags & (REX_W1 | REX_WX | REX_W1_EVEX)) == 0);
        return true;
    }

    return false;
}

//------------------------------------------------------------------------
// IsRexW1Instruction: check if the instruction always encodes REX.W as 1
//
// Arguments:
//    id - instruction to test
//
// Return Value:
//    true if the instruction always encodes REX.W as 1; othwerwise, false
//
bool emitter::IsRexW1Instruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];

    if ((flags & REX_W1) != 0)
    {
        assert((flags & (REX_W0 | REX_WX | REX_W1_EVEX)) == 0);
        return true;
    }

    return false;
}

//------------------------------------------------------------------------
// IsRexWXInstruction: check if the instruction requires special REX.W encoding
//
// Arguments:
//    id - instruction to test
//
// Return Value:
//    true if the instruction requires special REX.W encoding; othwerwise, false
//
bool emitter::IsRexWXInstruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];

    if ((flags & REX_WX) != 0)
    {
        assert((flags & (REX_W0 | REX_W1 | REX_W1_EVEX)) == 0);
        return true;
    }

    return false;
}

//------------------------------------------------------------------------
// IsRexW1EvexInstruction: check if the instruction always encodes REX.W as 1 for EVEX
//
// Arguments:
//    id - instruction to test
//
// Return Value:
//    true if the instruction always encodes REX.W as 1 for EVEX; othwerwise, false
//
bool emitter::IsRexW1EvexInstruction(instruction ins)
{
    insFlags flags = CodeGenInterface::instInfo[ins];

    if ((flags & REX_W1_EVEX) != 0)
    {
        assert((flags & (REX_W0 | REX_W1 | REX_WX)) == 0);
        return true;
    }

    return false;
}

//------------------------------------------------------------------------
// DoJitUseApxNDD: Answer the question: does JIT use APX NDD feature on the given instruction?
//
// Arguments:
//    ins - instruction to test
//
// Return Value:
//    true if JIT allows APX NDD to be applied on the instructions.
//
bool emitter::DoJitUseApxNDD(instruction ins) const
{
#if !defined(TARGET_AMD64)
    return false;
#else
    return JitConfig.EnableApxNDD() && IsApxNddEncodableInstruction(ins);
#endif
}

inline bool emitter::IsCCMP(instruction ins)
{
    return (ins >= FIRST_CCMP_INSTRUCTION && ins <= LAST_CCMP_INSTRUCTION);
}

//------------------------------------------------------------------------
// GetCCFromCCMP: Get a condition code from a ccmp instruction
//
// Arguments:
//    ins - The instruction to check.
//
// Returns:
//    `insCC` representing the condition code for a ccmp instruction.
//    ccmpx instructions share the same instruction encoding unlike
//    other x86 status bit instructions and instead have a CC coded into
//    the EVEX prefix.
//
inline insCC emitter::GetCCFromCCMP(instruction ins)
{
    assert(IsCCMP(ins));
    switch (ins)
    {
        case INS_ccmpo:
            return INS_CC_O;
        case INS_ccmpno:
            return INS_CC_NO;
        case INS_ccmpb:
            return INS_CC_B;
        case INS_ccmpae:
            return INS_CC_AE;
        case INS_ccmpe:
            return INS_CC_E;
        case INS_ccmpne:
            return INS_CC_NE;
        case INS_ccmpbe:
            return INS_CC_BE;
        case INS_ccmpa:
            return INS_CC_A;
        case INS_ccmps:
            return INS_CC_S;
        case INS_ccmpns:
            return INS_CC_NS;
        case INS_ccmpt:
            return INS_CC_TRUE;
        case INS_ccmpf:
            return INS_CC_FALSE;
        case INS_ccmpl:
            return INS_CC_L;
        case INS_ccmpge:
            return INS_CC_GE;
        case INS_ccmple:
            return INS_CC_LE;
        case INS_ccmpg:
            return INS_CC_G;
        default:
            unreached();
    }
}

#ifdef TARGET_64BIT
//------------------------------------------------------------------------
// AreUpperBitsZero: check if some previously emitted
//     instruction set the upper bits of reg to zero.
//
// Arguments:
//    reg - register of interest
//    size - the size of data that the given register of interest is working with;
//           remaining upper bits of the register that represent a larger size are the bits that are checked for zero
//
// Return Value:
//    true if previous instruction zeroed reg's upper bits.
//    false if it did not, or if we can't safely determine.
//
bool emitter::AreUpperBitsZero(regNumber reg, emitAttr size)
{
    // Only allow GPRs.
    // If not a valid register, then return false.
    if (!genIsValidIntReg(reg))
        return false;

    // Only consider if safe
    //
    if (!emitCanPeepholeLastIns())
    {
        return false;
    }

    bool result = false;

    emitPeepholeIterateLastInstrs([&](instrDesc* id) {
        if (emitIsInstrWritingToReg(id, reg))
        {
            switch (id->idIns())
            {
                // Conservative.
                case INS_call:
                    return PEEPHOLE_ABORT;

                // These instructions sign-extend.
                case INS_cwde:
                case INS_cdq:
                case INS_movsx:
                case INS_movsxd:
                    return PEEPHOLE_ABORT;

                case INS_movzx:
                    if ((size == EA_1BYTE) || (size == EA_2BYTE))
                    {
                        result = (id->idOpSize() <= size);
                    }
                    // movzx always zeroes the upper 32 bits.
                    else if (size == EA_4BYTE)
                    {
                        result = true;
                    }
                    return PEEPHOLE_ABORT;

                default:
                    break;
            }

            // otherwise rely on operation size.
            if (size == EA_4BYTE)
            {
                result = (id->idOpSize() == EA_4BYTE);
            }
            return PEEPHOLE_ABORT;
        }
        else
        {
            return PEEPHOLE_CONTINUE;
        }
    });

    return result;
}

//------------------------------------------------------------------------
// AreUpper32BitsSignExtended: check if some previously emitted
//     instruction sign-extended the upper bits.
//
// Arguments:
//    reg - register of interest
//    size - the size of data that the given register of interest is working with;
//           remaining upper bits of the register that represent a larger size are the bits that are checked for
//           sign-extended
//
// Return Value:
//    true if previous instruction upper bits are sign-extended.
//    false if it did not, or if we can't safely determine.
bool emitter::AreUpperBitsSignExtended(regNumber reg, emitAttr size)
{
    // Only allow GPRs.
    // If not a valid register, then return false.
    if (!genIsValidIntReg(reg))
        return false;

    // Only consider if safe
    //
    if (!emitCanPeepholeLastIns())
    {
        return false;
    }

    instrDesc* id = emitLastIns;

    bool result = false;

    emitPeepholeIterateLastInstrs([&](instrDesc* id) {
        if (emitIsInstrWritingToReg(id, reg))
        {
            switch (id->idIns())
            {
                // Conservative.
                case INS_call:
                    return PEEPHOLE_ABORT;

                case INS_movsx:
                case INS_movsxd:
                    if ((size == EA_1BYTE) || (size == EA_2BYTE))
                    {
                        result = (id->idOpSize() <= size);
                    }
                    // movsx/movsxd always sign extends to 8 bytes. W-bit is set.
                    else if (size == EA_4BYTE)
                    {
                        result = true;
                    }
                    break;

                default:
                    break;
            }

            return PEEPHOLE_ABORT;
        }
        else
        {
            return PEEPHOLE_CONTINUE;
        }
    });

    return result;
}
#endif // TARGET_64BIT

//------------------------------------------------------------------------
// emitDoesInsModifyFlags: checks if the given instruction modifies flags
//
// Arguments:
//    ins - instruction of interest
//
// Return Value:
//    true if the instruction modifies flags.
//    false if it does not.
//
bool emitter::emitDoesInsModifyFlags(instruction ins)
{
    return (CodeGenInterface::instInfo[ins] &
            (Resets_OF | Resets_SF | Resets_AF | Resets_PF | Resets_CF | Undefined_OF | Undefined_SF | Undefined_AF |
             Undefined_PF | Undefined_CF | Undefined_ZF | Writes_OF | Writes_SF | Writes_AF | Writes_PF | Writes_CF |
             Writes_ZF | Restore_SF_ZF_AF_PF_CF));
}

//------------------------------------------------------------------------
// emitIsInstrWritingToReg: checks if the given register is being written to
//
// Arguments:
//    id - instruction of interest
//    reg - register of interest
//
// Return Value:
//    true if the instruction writes to the given register.
//    false if it did not.
//
// Note: This only handles integer registers. Also, an INS_call will always return true.
//
bool emitter::emitIsInstrWritingToReg(instrDesc* id, regNumber reg)
{
    // This only handles integer registers for now.
    assert(genIsValidIntReg(reg));

    instruction ins = id->idIns();

    // These are special cases since they modify one or more register(s) implicitly.
    switch (ins)
    {
        // This is conservative. We assume a call will write to all registers even if it does not.
        case INS_call:
            return true;

        case INS_imul_AX:
        case INS_imul_BP:
        case INS_imul_BX:
        case INS_imul_CX:
        case INS_imul_DI:
        case INS_imul_DX:
        case INS_imul_SI:
        case INS_imul_SP:
#ifdef TARGET_AMD64
        case INS_imul_08:
        case INS_imul_09:
        case INS_imul_10:
        case INS_imul_11:
        case INS_imul_12:
        case INS_imul_13:
        case INS_imul_14:
        case INS_imul_15:
        case INS_imul_16:
        case INS_imul_17:
        case INS_imul_18:
        case INS_imul_19:
        case INS_imul_20:
        case INS_imul_21:
        case INS_imul_22:
        case INS_imul_23:
        case INS_imul_24:
        case INS_imul_25:
        case INS_imul_26:
        case INS_imul_27:
        case INS_imul_28:
        case INS_imul_29:
        case INS_imul_30:
        case INS_imul_31:
#endif // TARGET_AMD64
            if (reg == inst3opImulReg(ins))
            {
                return true;
            }
            break;

        // These always write to RAX and RDX.
        case INS_idiv:
        case INS_div:
        case INS_imulEAX:
        case INS_mulEAX:
            if ((reg == REG_RAX) || (reg == REG_RDX))
            {
                return true;
            }
            break;

        // Always writes to RAX.
        case INS_cmpxchg:
            if (reg == REG_RAX)
            {
                return true;
            }
            break;

        case INS_movsb:
        case INS_movsd:
#ifdef TARGET_AMD64
        case INS_movsq:
#endif // TARGET_AMD64
            if ((reg == REG_RDI) || (reg == REG_RSI))
            {
                return true;
            }
            break;

        case INS_stosb:
        case INS_stosd:
#ifdef TARGET_AMD64
        case INS_stosq:
#endif // TARGET_AMD64
            if (reg == REG_RDI)
            {
                return true;
            }
            break;

        case INS_r_movsb:
        case INS_r_movsd:
#ifdef TARGET_AMD64
        case INS_r_movsq:
#endif // TARGET_AMD64
            if ((reg == REG_RDI) || (reg == REG_RSI) || (reg == REG_RCX))
            {
                return true;
            }
            break;

        case INS_r_stosb:
        case INS_r_stosd:
#ifdef TARGET_AMD64
        case INS_r_stosq:
#endif // TARGET_AMD64
            if ((reg == REG_RDI) || (reg == REG_RCX))
            {
                return true;
            }
            break;

        default:
            break;
    }

#ifdef TARGET_64BIT
    // This is a special case for cdq/cwde.
    switch (ins)
    {
        case INS_cwde:
            if (reg == REG_RAX)
            {
                return true;
            }
            break;

        case INS_cdq:
            if (reg == REG_RDX)
            {
                return true;
            }
            break;

        default:
            break;
    }
#endif // TARGET_64BIT

    if (id->idIsReg1Write() && (id->idReg1() == reg))
    {
        return true;
    }

    if (id->idIsReg2Write() && (id->idReg2() == reg))
    {
        return true;
    }

    assert(!id->idIsReg3Write());
    assert(!id->idIsReg4Write());

    return false;
}

//------------------------------------------------------------------------
// IsRedundantCmp: determines if there is a 'cmp' instruction that is redundant with the given inputs
//
// Arguments:
//    size - size of 'cmp'
//    reg1 - op1 register of 'cmp'
//    reg2 - op2 register of 'cmp'
//
// Return Value:
//    true if there is a redundant 'cmp'
//
bool emitter::IsRedundantCmp(emitAttr size, regNumber reg1, regNumber reg2)
{
    // Only allow GPRs.
    // If not a valid register, then return false.
    if (!genIsValidIntReg(reg1))
        return false;

    if (!genIsValidIntReg(reg2))
        return false;

    // Only consider if safe
    //
    if (!emitCanPeepholeLastIns())
    {
        return false;
    }

    bool result = false;

    emitPeepholeIterateLastInstrs([&](instrDesc* id) {
        instruction ins = id->idIns();

        switch (ins)
        {
            case INS_cmp:
            {
                // We only care about 'cmp reg, reg'.
                if (id->idInsFmt() != IF_RRD_RRD)
                    return PEEPHOLE_ABORT;

                if ((id->idReg1() == reg1) && (id->idReg2() == reg2))
                {
                    result = (size == id->idOpSize());
                }

                return PEEPHOLE_ABORT;
            }

            default:
                break;
        }

        if (emitDoesInsModifyFlags(ins))
        {
            return PEEPHOLE_ABORT;
        }

        if (emitIsInstrWritingToReg(id, reg1) || emitIsInstrWritingToReg(id, reg2))
        {
            return PEEPHOLE_ABORT;
        }

        return PEEPHOLE_CONTINUE;
    });

    return result;
}

//------------------------------------------------------------------------
// AreFlagsSetToZeroCmp: Checks if the previous instruction set the SZ, and optionally OC, flags to
//                       the same values as if there were a compare to 0
//
// Arguments:
//    reg     - register of interest
//    opSize  - size of register
//    cond    - the condition being checked
//
// Return Value:
//    true if the previous instruction set the flags for reg
//    false if not, or if we can't safely determine
//
// Notes:
//    Currently only looks back one instruction.
bool emitter::AreFlagsSetToZeroCmp(regNumber reg, emitAttr opSize, GenCondition cond)
{
    assert(reg != REG_NA);

    if (!emitComp->opts.OptimizationEnabled())
    {
        return false;
    }

    if (!emitCanPeepholeLastIns())
    {
        // Don't consider if not safe
        return false;
    }

    instrDesc*  id      = emitLastIns;
    instruction lastIns = id->idIns();

    if (!id->idIsReg1Write() || (id->idReg1() != reg))
    {
        // Don't consider instructions which didn't write a register
        return false;
    }

    if (id->idHasMemWrite() || id->idIsReg2Write())
    {
        // Don't consider instructions which also wrote a mem location or second register
        return false;
    }

    assert(!id->idIsReg3Write());
    assert(!id->idIsReg4Write());

    // Certain instruction like and, or and xor modifies exactly same flags
    // as "test" instruction.
    // They reset OF and CF to 0 and modifies SF, ZF and PF.
    if (DoesResetOverflowAndCarryFlags(lastIns) && DoesWriteSignFlag(lastIns) && DoesWriteZeroFlag(lastIns) &&
        DoesWriteParityFlag(lastIns))
    {
        return id->idOpSize() == opSize;
    }

    if ((cond.GetCode() == GenCondition::NE) || (cond.GetCode() == GenCondition::EQ))
    {
        if (DoesWriteZeroFlag(lastIns) && IsFlagsAlwaysModified(id))
        {
            return id->idOpSize() == opSize;
        }
    }

    return false;
}

//------------------------------------------------------------------------
// AreFlagsSetToForSignJumpOpt: checks if the previous instruction set the SF if the tree
//                              node qualifies for a jg/jle to jns/js optimization
//
// Arguments:
//    reg    - register of interest
//    opSize - size of register
//    cond   - the condition being checked
//
// Return Value:
//    true if the tree node qualifies for the jg/jle to jns/js optimization
//    false if not, or if we can't safely determine
//
// Notes:
//    Currently only looks back one instruction.
bool emitter::AreFlagsSetForSignJumpOpt(regNumber reg, emitAttr opSize, GenCondition cond)
{
    assert(reg != REG_NA);

    if (!emitComp->opts.OptimizationEnabled())
    {
        return false;
    }

    // Only consider if safe
    //
    if (!emitCanPeepholeLastIns())
    {
        return false;
    }

    instrDesc*  id      = emitLastIns;
    instruction lastIns = id->idIns();
    insFormat   fmt     = id->idInsFmt();

    if (!id->idIsReg1Write() || (id->idReg1() != reg))
    {
        // Don't consider instructions which didn't write a register
        return false;
    }

    if (id->idHasMemWrite() || id->idIsReg2Write())
    {
        // Don't consider instructions which also wrote a mem location or second register
        return false;
    }

    // If we have a GE/LT which generates an jge/jl, and the previous instruction
    // sets the SF, we can omit a test instruction and check for jns/js.
    if ((cond.GetCode() == GenCondition::SGE) || (cond.GetCode() == GenCondition::SLT))
    {
        if (DoesWriteSignFlag(lastIns) && IsFlagsAlwaysModified(id))
        {
            return id->idOpSize() == opSize;
        }
    }

    return false;
}

//------------------------------------------------------------------------
// IsDstSrcImmAvxInstruction: Checks if the instruction has a "reg, reg/mem, imm" or
//                            "reg/mem, reg, imm" form for the legacy, VEX, and EVEX
//                            encodings.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if instruction has a "reg, reg/mem, imm" or "reg/mem, reg, imm" encoding
//    form for the legacy, VEX, and EVEX encodings.
//
//    That is, the instruction takes two operands, one of which is immediate, and it
//    does not need to encode any data in the VEX.vvvv field.
//
static bool IsDstSrcImmAvxInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_aeskeygenassist:
        case INS_extractps:
        case INS_pextrb:
        case INS_pextrw:
        case INS_pextrd:
        case INS_pextrq:
        case INS_pshufd:
        case INS_pshufhw:
        case INS_pshuflw:
        case INS_roundpd:
        case INS_roundps:
            return true;
        default:
            return false;
    }
}

// -------------------------------------------------------------------
// Is4ByteSSEInstruction: Returns true if the SSE instruction is a 4-byte opcode.
//
// Arguments:
//    ins  -  instruction
//
// Note that this should be true for any of the instructions in instrsXArch.h
// that use the SSE38 or SSE3A macro but returns false if the VEX encoding is
// in use, since that encoding does not require an additional byte.
bool emitter::Is4ByteSSEInstruction(instruction ins) const
{
    return !UseVEXEncoding() && EncodedBySSE38orSSE3A(ins);
}

//------------------------------------------------------------------------
// isLowSIMDReg: Checks if a register is a register supported by any SIMD encoding
//
// Arguments:
//     reg -- register to check
//
// Return Value:
//   true if the register is a register supported by any SIMD encoding
static bool isLowSimdReg(regNumber reg)
{
#ifdef TARGET_AMD64
    return (reg >= REG_XMM0) && (reg <= REG_XMM15);
#else
    return (reg >= REG_XMM0) && (reg <= REG_XMM7);
#endif
}

//------------------------------------------------------------------------
// GetEmbRoundingMode: Get the rounding mode for embedded rounding
//
// Arguments:
//     mode -- the flag from the corresponding GenTree node indicating the mode.
//
// Return Value:
//   the instruction option carrying the rounding mode information.
//
insOpts emitter::GetEmbRoundingMode(uint8_t mode) const
{
    switch (mode)
    {
        case 1:
            return INS_OPTS_EVEX_er_rd;
        case 2:
            return INS_OPTS_EVEX_er_ru;
        case 3:
            return INS_OPTS_EVEX_er_rz;
        default:
            unreached();
    }
}

//------------------------------------------------------------------------
// emitHandleGCrefRegs: Update GC ref related registers' liveness.
//
// Arguments:
//   dst - Destination buffer.
//   id  - instruction descriptor to the GC ref instruction.
//
void emitter::emitHandleGCrefRegs(BYTE* dst, instrDesc* id)
{
    regNumber reg1 = id->idReg1(); // dst and src1
    regNumber reg2 = id->idReg2(); // src2
    switch (id->idInsFmt())
    {
        case IF_RRD_RRD:
            break;

        case IF_RWR_RRD:
        {
            if (emitSyncThisObjReg != REG_NA && emitIGisInProlog(emitCurIG) && reg2 == (int)REG_ARG_0)
            {
                // We're relocating "this" in the prolog
                assert(emitComp->lvaIsOriginalThisArg(0));
                assert(emitComp->lvaTable[0].lvRegister);
                assert(emitComp->lvaTable[0].GetRegNum() == reg1);

                if (emitFullGCinfo)
                {
                    emitGCregLiveSet(id->idGCref(), genRegMask(reg1), dst, true);
                    break;
                }
                else
                {
                    /* If emitFullGCinfo==false, the we don't use any
                       regPtrDsc's and so explicitly note the location
                       of "this" in GCEncode.cpp
                     */
                }
            }

            emitGCregLiveUpd(id->idGCref(), reg1, dst);
            break;
        }

        case IF_RRW_RRD:
        case IF_RWR_RRD_RRD:
        {
            regNumber targetReg = reg1; // dst

            // if the instructions is encoded in NDD form,
            // src registers will be the 2nd and 3rd register on id.
            if (id->idInsFmt() == IF_RWR_RRD_RRD)
            {
                reg1 = id->idReg2(); // src1
                reg2 = id->idReg3(); // src2
            }

            switch (id->idIns())
            {
                /*
                    This must be one of the following cases:

                    xor reg, reg        to assign NULL

                    and r1 , r2         if (ptr1 && ptr2) ...
                    or  r1 , r2         if (ptr1 || ptr2) ...

                    add r1 , r2         to compute a normal byref
                    sub r1 , r2         to compute a strange byref (VC only)

                */
                case INS_xor:
                    assert(reg1 == reg2);
                    emitGCregLiveUpd(id->idGCref(), targetReg, dst);
                    break;

                case INS_or:
                case INS_and:
                    emitGCregDeadUpd(targetReg, dst);
                    break;

                case INS_add:
                case INS_sub:
                case INS_sub_hide:
                    assert(id->idGCref() == GCT_BYREF);

#if 0
#ifdef DEBUG
                        // Due to elided register moves, we can't have the following assert.
                        // For example, consider:
                        //    t85 = LCL_VAR byref V01 arg1 rdx (last use) REG rdx
                        //        /--*  t85    byref
                        //        *  STORE_LCL_VAR byref  V40 tmp31 rdx REG rdx
                        // Here, V01 is type `long` on entry, then is stored as a byref. But because
                        // the register allocator assigned the same register, no instruction was
                        // generated, and we only (currently) make gcref/byref changes in emitter GC info
                        // when an instruction is generated. We still generate correct GC info, as this
                        // instruction, if writing a GC ref even through reading a long, will go live here.
                        // These situations typically occur due to unsafe casting, such as with Span<T>.

                        regMaskTP regMask;
                        regMask = genRegMask(reg1) | genRegMask(reg2);

                        // r1/r2 could have been a GCREF as GCREF + int=BYREF
                        //                               or BYREF+/-int=BYREF
                        assert(((regMask & emitThisGCrefRegs) && (ins == INS_add)) ||
                               ((regMask & emitThisByrefRegs) && (ins == INS_add || ins == INS_sub || ins == INS_sub_hide)));
#endif // DEBUG
#endif // 0

                    // Mark r1 as holding a byref
                    emitGCregLiveUpd(GCT_BYREF, targetReg, dst);
                    break;

                default:
#ifdef DEBUG
                    emitDispIns(id, false, false, false);
#endif
                    assert(!"unexpected GC reg update instruction");
            }

            break;
        }

        case IF_RRW_RRW:
        {
            // This must be "xchg reg1, reg2"
            assert(id->idIns() == INS_xchg);

            // If we got here, the GC-ness of the registers doesn't match, so we have to "swap" them in the GC
            // register pointer mask.

            GCtype gc1, gc2;

            gc1 = emitRegGCtype(reg1);
            gc2 = emitRegGCtype(reg2);

            if (gc1 != gc2)
            {
                // Kill the GC-info about the GC registers

                if (needsGC(gc1))
                {
                    emitGCregDeadUpd(reg1, dst);
                }

                if (needsGC(gc2))
                {
                    emitGCregDeadUpd(reg2, dst);
                }

                // Now, swap the info

                if (needsGC(gc1))
                {
                    emitGCregLiveUpd(gc1, reg2, dst);
                }

                if (needsGC(gc2))
                {
                    emitGCregLiveUpd(gc2, reg1, dst);
                }
            }
            break;
        }

        default:
#ifdef DEBUG
            emitDispIns(id, false, false, false);
#endif
            assert(!"unexpected GC ref instruction format");
    }
}

//------------------------------------------------------------------------
// encodeRegAsIval: Encodes a register as an ival for use by a SIMD instruction
//
// Arguments
//    opReg -- The register being encoded
//
// Returns:
//    opReg encoded as an ival
static int8_t encodeRegAsIval(regNumber opReg)
{
    assert(isLowSimdReg(opReg) || emitter::isMaskReg(opReg));
    ssize_t ival = static_cast<ssize_t>(opReg);

    assert((ival >= 0x00) && (ival <= 0xFF));
    return static_cast<int8_t>(ival);
}

//------------------------------------------------------------------------
// decodeRegFromIval: Decodes a register from an ival for use by a SIMD instruction
//
// Arguments
//    ival -- The ival being decoded
//
// Returns:
//    The regNumber that was encoded as an ival
static regNumber decodeRegFromIval(ssize_t ival)
{
    assert((ival >= -128) && (ival <= +127));
    regNumber opReg = static_cast<regNumber>(ival);

    assert(isLowSimdReg(opReg) || emitter::isMaskReg(opReg));
    return opReg;
}

//------------------------------------------------------------------------
// TakesSimdPrefix: Checks if the instruction should be VEX or EVEX encoded.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if this instruction requires a VEX or EVEX prefix.
//
bool emitter::TakesSimdPrefix(const instrDesc* id) const
{
    instruction ins = id->idIns();
    return TakesVexPrefix(ins) || TakesEvexPrefix(id);
}

//------------------------------------------------------------------------
// TakesEvexPrefix: Checks if the instruction should be EVEX encoded.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if this instruction requires a EVEX prefix.
//
bool emitter::TakesEvexPrefix(const instrDesc* id) const
{
    instruction ins = id->idIns();

    if (!IsEvexEncodableInstruction(ins))
    {
        // Never supports the EVEX encoding
        return false;
    }

    if (!IsVexEncodableInstruction(ins))
    {
        // Only supports the EVEX encoding
        return true;
    }

    if (HasHighSIMDReg(id) || (id->idOpSize() == EA_64BYTE) || HasMaskReg(id))
    {
        // Requires the EVEX encoding due to used registers
        // A special case here is KMOV, the original KMOV introduced in Avx512 can only be encoded in VEX, APX promoted
        // them to EVEX, so only return true when APX is available.
        if (IsKMOVInstruction(ins))
        {
            // Use EVEX only when needed.
            return HasExtendedGPReg(id);
        }
        return true;
    }

    if (id->idIsEvexbContextSet() || HasEmbeddedMask(id))
    {
        // Requires the EVEX encoding due to embedded functionality
        return true;
    }

    if (HasExtendedGPReg(id))
    {
        // TODO-XArch-apx:
        // revisit this part: this may have some conflicts with REX2 prefix, we may prefer REX2 if only EGPR is
        // involved.
        return true;
    }

    if (id->idIsEvexNfContextSet() && IsBMIInstruction(ins))
    {
        // Only a few BMI instructions shall be promoted to APX-EVEX due to NF feature.
        // TODO-XArch-APX: convert the check into forms like Has* as above.
        return true;
    }

#if defined(DEBUG)
    if (emitComp->DoJitStressEvexEncoding())
    {
        // Requires the EVEX encoding due to STRESS mode
        return true;
    }
#endif // DEBUG

    if (id->idHasMem())
    {
        if ((ins == INS_pslldq) || (ins == INS_psrldq))
        {
            // The memory operand can only be encoded using the EVEX encoding
            return true;
        }

        if ((insTupleTypeInfo(ins) & INS_TT_MEM128) != 0)
        {
            assert((ins == INS_pslld) || (ins == INS_psllq) || (ins == INS_psllw) || (ins == INS_psrad) ||
                   (ins == INS_psraw) || (ins == INS_psrld) || (ins == INS_psrlq) || (ins == INS_psrlw));

            if (id->idHasMemAndCns())
            {
                // Memory operand with immediate can only be encoded using EVEX
                return true;
            }
        }
    }

    return false;
}

//------------------------------------------------------------------------
// TakesRex2Prefix: Checks if the instruction should be Rex2 encoded.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if this instruction requires a Rex2 prefix.
//
bool emitter::TakesRex2Prefix(const instrDesc* id) const
{
#ifdef TARGET_AMD64
    // Return true iff the instruction supports REX2 encoding, and it requires to access EGPRs.

    // TODO-xarch-apx:
    // At this stage, we are only using REX2 in the case that non-simd integer instructions
    // with EGPRs being used in its operands, it could be either direct register uses, or
    // memory addressing operands, i.e. index and base.
    instruction ins = id->idIns();
    if (!IsRex2EncodableInstruction(ins))
    {
        return false;
    }

    if (TakesEvexPrefix(id))
    {
        return false;
    }

    if (HasExtendedGPReg(id))
    {
        return true;
    }

    if (ins >= INS_imul_16 && ins <= INS_imul_31)
    {
        // The instructions have implicit use of EGPRs.
        return true;
    }

    if (id->idIsApxPpxContextSet())
    {
        // The instruction uses PPX hint, and it requires REX2.
        return true;
    }

#if defined(DEBUG)
    if (emitComp->DoJitStressRex2Encoding())
    {
        return true;
    }
#endif // DEBUG

    return false;
#else // !TARGET_AMD64
    return false;
#endif
}

//------------------------------------------------------------------------
// TakesApxExtendedEvexPrefix: Checks if the instruction should be legacy-promoted-EVEX encoded.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if this instruction requires a legacy-promoted-EVEX prefix.
//
bool emitter::TakesApxExtendedEvexPrefix(const instrDesc* id) const
{
#ifdef TARGET_AMD64
    instruction ins = id->idIns();
    if (!IsApxExtendedEvexInstruction(ins))
    {
        return false;
    }

    if (IsSimdInstruction(ins))
    {
        // This check should reject any instruction not from legacy map-0 or 1.
        return false;
    }

    if (id->idIsNoApxEvexPromotion())
    {
        return false;
    }

    if (IsApxNddCompatibleInstruction(ins) && id->idIsEvexNdContextSet())
    {
        // The instruction uses APX-ND hint, and it requires EVEX.
        return true;
    }

    if (IsApxNfCompatibleInstruction(ins) && id->idIsEvexNfContextSet())
    {
        // The instruction uses APX-NF hint, and it requires EVEX.
        return true;
    }

#if defined(DEBUG)
    if (emitComp->DoJitStressPromotedEvexEncoding())
    {
        return true;
    }
#endif // DEBUG
    if (IsApxOnlyInstruction(ins))
    {
        return true;
    }

    return false;
#else // !TARGET_AMD64
    return false;
#endif
}

// Intel AVX-512 encoding is defined in "Intel 64 and ia-32 architectures software developer's manual volume 2", Section
// 2.6.
// Add base EVEX prefix without setting W, R, X, or B bits
// L'L bits will be set based on emitter attr.
//
// 4-byte EVEX prefix = 62 <R, X, B, R', 0, 0, m, m> <W, v, v, v, v, 1, p, p> <z, L', L, b, V', a, a, a>
// - R, X, B, W - bits to express corresponding REX prefixes.Additionally, X combines with B to expand r/m to 32 SIMD
// registers
// - R' - combines with R to expand reg to 32 SIMD registers
// - mmm - Encodes the map number to which the instruction belongs to
//   mm - lower 2 bits of m-mmmmm (5-bit) in corresponding VEX prefix (For AVX10.1 and below)
//   mmm - map number to which the instruction belongs to (For AVX10.2 and above)
// - vvvv (4-bits) - register specifier in 1's complement form; must be 1111 if unused
// - pp (2-bits) - opcode extension providing equivalent functionality of a SIMD size prefix
//                 these prefixes are treated mandatory when used with escape opcode 0Fh for
//                 some SIMD instructions
//   00  - None   (0F    - packed float)
//   01  - 66     (66 0F - packed double)
//   10  - F3     (F3 0F - scalar float
//   11  - F2     (F2 0F - scalar double)
// - z - bit to specify merging mode
// - L - scalar or AVX-128 bit operations (L=0),  256-bit operations (L=1)
// - L'- bit to support 512-bit operations or rounding control mode
// - b - broadcast/rc/sae context
// - V'- bit to extend vvvv
// - aaa - specifies mask register
//    Rest    - reserved for future use and usage of them will uresult in Undefined instruction exception.
// - B' - reserved as of now
//   set to 0 for future compatibility.
//
#define DEFAULT_BYTE_EVEX_PREFIX 0x62F07C0800000000ULL

#define DEFAULT_BYTE_EVEX_PREFIX_MASK 0xFFFFFFFF00000000ULL
#define BBIT_IN_BYTE_EVEX_PREFIX      0x0000001000000000ULL
#define LBIT_IN_BYTE_EVEX_PREFIX      0x0000002000000000ULL
#define LPRIMEBIT_IN_BYTE_EVEX_PREFIX 0x0000004000000000ULL
#define ZBIT_IN_BYTE_EVEX_PREFIX      0x0000008000000000ULL

#define MAP4_IN_BYTE_EVEX_PREFIX   0x4000000000000ULL
#define ND_BIT_IN_BYTE_EVEX_PREFIX 0x1000000000ULL
#define NF_BIT_IN_BYTE_EVEX_PREFIX 0x400000000ULL
#define EXTENDED_EVEX_PP_BITS      0x10000000000ULL
//------------------------------------------------------------------------
// AddEvexPrefix: Add default EVEX prefix with only LL' bits set.
//
// Arguments:
//    id   -- instruction descriptor for encoding
//    code -- opcode bits.
//    attr -- operand size
//
// Return Value:
//    encoded code with EVEX prefix.
//
emitter::code_t emitter::AddEvexPrefix(const instrDesc* id, code_t code, emitAttr attr)
{
    // Only AVX512 instructions require EVEX prefix
    // After APX, some instructions in legacy or VEX space will be promoted to EVEX.
    instruction ins = id->idIns();
    assert(IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));

    if (instrIsExtendedReg3opImul(ins))
    {
        // the only case imul(0x68) will need EVEX prefix is EVEX.NF feature enabled.
        // imul(0x68) opcode comes with ModR/M.REG byte to indicate implicit register use,
        // when it is using extended registers (>= REG_R8), it comes with built-in REX prefix,
        // remove them first and add the counter part in EVEX.
        code &= 0xFFFFFFFF;
    }

    // Shouldn't have already added EVEX prefix
    assert(!hasEvexPrefix(code));

    assert((code & DEFAULT_BYTE_EVEX_PREFIX_MASK) == 0);

    code |= DEFAULT_BYTE_EVEX_PREFIX;

    if (IsApxExtendedEvexInstruction(ins))
    {
        if (!IsEvexEncodableInstruction(ins))
        {
            // Legacy-promoted insutrcions are not labeled with Encoding_EVEX.
            code |= MAP4_IN_BYTE_EVEX_PREFIX;
        }

        // TODO-XArch-APX:
        // verify if it is actually safe to reuse the EVEX.ND with EVEX.B on instrDesc.
        if (IsApxNddCompatibleInstruction(ins) && id->idIsEvexNdContextSet())
        {
            code |= ND_BIT_IN_BYTE_EVEX_PREFIX;
        }

        if (IsApxZuCompatibleInstruction(ins) && id->idIsEvexZuContextSet())
        {
            // EVEX.ZU reuses the EVEX.ND bit for SETcc and IMUL.
            code |= ND_BIT_IN_BYTE_EVEX_PREFIX;
        }

        if (IsApxNfCompatibleInstruction(ins) && id->idIsEvexNfContextSet())
        {
            code |= NF_BIT_IN_BYTE_EVEX_PREFIX;
        }

        if (attr == EA_2BYTE)
        {
            code |= EXTENDED_EVEX_PP_BITS;
        }

        if (instrIsExtendedReg3opImul(ins))
        {
            // EVEX.R3
            code &= 0xFF7FFFFFFFFFFFFFULL;
        }
#ifdef TARGET_AMD64
        if (IsCCMP(ins))
        {
            code &= 0xFFFF87F0FFFFFFFF;
            code |= ((size_t)id->idGetEvexDFV()) << 43;
            code |= ((size_t)GetCCFromCCMP(ins)) << 32;
        }
#endif

        return code;
    }

    // No APX-NDD instructions should reach code below.
    assert(!IsApxExtendedEvexInstruction(ins));

    if (attr == EA_32BYTE)
    {
        // Set EVEX.L'L bits to 01 in case of instructions that operate on 256-bits.
        code |= LBIT_IN_BYTE_EVEX_PREFIX;
    }
    else if (attr == EA_64BYTE)
    {
        // Set EVEX.L'L bits to 10 in case of instructions that operate on 512-bits.
        code |= LPRIMEBIT_IN_BYTE_EVEX_PREFIX;
    }

    if (id->idIsEvexbContextSet())
    {
        if (!id->idHasMem())
        {
            // For non-memory operations, this holds the EVEX.RC bits
            // that indicate the rounding mode to use, EVEX.b is implied

            unsigned roundingMode = id->idGetEvexbContext();

            if (roundingMode == 1)
            {
                // {rd-sae}
                code &= ~(LPRIMEBIT_IN_BYTE_EVEX_PREFIX);
                code |= LBIT_IN_BYTE_EVEX_PREFIX;
            }
            else if (roundingMode == 2)
            {
                // {ru-sae}
                code |= LPRIMEBIT_IN_BYTE_EVEX_PREFIX;
                code &= ~(LBIT_IN_BYTE_EVEX_PREFIX);
            }
            else if (roundingMode == 3)
            {
                // {rz-sae}
                code |= LPRIMEBIT_IN_BYTE_EVEX_PREFIX;
                code |= LBIT_IN_BYTE_EVEX_PREFIX;
            }
            else
            {
                unreached();
            }

            code |= BBIT_IN_BYTE_EVEX_PREFIX;
        }
        else if (HasEmbeddedBroadcast(id))
        {
            // For memory operations, the low bit being set indicates
            // we are using embedded broadcast, while the upper bit
            // being set indicates we are using compressed displacement

            code |= BBIT_IN_BYTE_EVEX_PREFIX;
        }
    }

    regNumber maskReg = REG_NA;

    switch (id->idInsFmt())
    {
        case IF_RWR_RRD_ARD_RRD:
        {
            assert(!id->idIsEvexAaaContextSet());

            CnsVal cnsVal;
            emitGetInsAmdCns(id, &cnsVal);

            maskReg = decodeRegFromIval(cnsVal.cnsVal);
            break;
        }

        case IF_RWR_RRD_MRD_RRD:
        {
            assert(!id->idIsEvexAaaContextSet());

            CnsVal cnsVal;
            emitGetInsDcmCns(id, &cnsVal);

            maskReg = decodeRegFromIval(cnsVal.cnsVal);
            break;
        }

        case IF_RWR_RRD_SRD_RRD:
        {
            assert(!id->idIsEvexAaaContextSet());

            CnsVal cnsVal;
            emitGetInsCns(id, &cnsVal);

            maskReg = decodeRegFromIval(cnsVal.cnsVal);
            break;
        }

        case IF_RWR_RRD_RRD_RRD:
        {
            assert(!id->idIsEvexAaaContextSet());
            maskReg = id->idReg4();
            break;
        }

        default:
        {
#ifdef TARGET_AMD64
            if (IsCCMP(id->idIns())) // Special case for conditional ins such as CCMP, CCMOV
            {
                break;
            }
#endif
            unsigned aaaContext = id->idGetEvexAaaContext();

            if (aaaContext != 0)
            {
                maskReg = static_cast<regNumber>(aaaContext + KBASE);
            }
            break;
        }
    }

    if (isMaskReg(maskReg))
    {
        code |= (static_cast<code_t>(maskReg - KBASE) << 32);

        if (id->idIsEvexZContextSet())
        {
            code |= ZBIT_IN_BYTE_EVEX_PREFIX;
        }
    }
    return code;
}

// Returns true if this instruction requires a VEX prefix
// All AVX instructions require a VEX prefix
bool emitter::TakesVexPrefix(instruction ins) const
{
    // special case vzeroupper as it requires 2-byte VEX prefix
    return IsVexEncodableInstruction(ins) && (ins != INS_vzeroupper);
}

// Add base VEX prefix without setting W, R, X, or B bits
// L bit will be set based on emitter attr.
//
// 2-byte VEX prefix = C5 <R,vvvv,L,pp>
// 3-byte VEX prefix = C4 <R,X,B,m-mmmm> <W,vvvv,L,pp>
//  - R, X, B, W - bits to express corresponding REX prefixes
//  - m-mmmmm (5-bit)
//    0-00001 - implied leading 0F opcode byte
//    0-00010 - implied leading 0F 38 opcode bytes
//    0-00011 - implied leading 0F 3A opcode bytes
//    Rest    - reserved for future use and usage of them will uresult in Undefined instruction exception
//
// - vvvv (4-bits) - register specifier in 1's complement form; must be 1111 if unused
// - L - scalar or AVX-128 bit operations (L=0),  256-bit operations (L=1)
// - pp (2-bits) - opcode extension providing equivalent functionality of a SIMD size prefix
//                 these prefixes are treated mandatory when used with escape opcode 0Fh for
//                 some SIMD instructions
//   00  - None   (0F    - packed float)
//   01  - 66     (66 0F - packed double)
//   10  - F3     (F3 0F - scalar float
//   11  - F2     (F2 0F - scalar double)
#define DEFAULT_3BYTE_VEX_PREFIX      0xC4E07800000000ULL
#define DEFAULT_3BYTE_VEX_PREFIX_MASK 0xFFFFFF00000000ULL
#define LBIT_IN_3BYTE_VEX_PREFIX      0x00000400000000ULL
emitter::code_t emitter::AddVexPrefix(instruction ins, code_t code, emitAttr attr)
{
    // The 2-byte VEX encoding is preferred when possible, but actually emitting
    // it depends on a number of factors that we may not know until much later.
    //
    // In order to handle this "easily", we just carry the 3-byte encoding all
    // the way through and "fix-up" the encoding when the VEX prefix is actually
    // emitted, by simply checking that all the requirements were met.

    // Only AVX instructions require VEX prefix
    assert(IsVexEncodableInstruction(ins));

    // Shouldn't have already added VEX prefix
    assert(!hasVexPrefix(code));

    assert((code & DEFAULT_3BYTE_VEX_PREFIX_MASK) == 0);

    code |= DEFAULT_3BYTE_VEX_PREFIX;

    if ((attr == EA_32BYTE) || IsKInstructionWithLBit(ins))
    {
        // Set L bit to 1 in case of instructions that operate on 256-bits.
        code |= LBIT_IN_3BYTE_VEX_PREFIX;
    }

    return code;
}

// Add base REX2 prefix without setting higher register index bits
#define DEFAULT_2BYTE_REX2_PREFIX      0xD50000000000ULL
#define DEFAULT_2BYTE_REX2_PREFIX_MASK 0xFFFF00000000ULL
#define REX2_MAP1_PREFIX               0x008000000000ULL
emitter::code_t emitter::AddRex2Prefix(instruction ins, code_t code)
{
    assert(IsRex2EncodableInstruction(ins));

    // Note that there are cases that some register field might be filled before adding prefix,
    // So we don't check if the code has REX2 prefix already or not.

    code |= DEFAULT_2BYTE_REX2_PREFIX;
    if (IsLegacyMap1(code)) // 2-byte opcode on Map-1
    {
        code |= REX2_MAP1_PREFIX;
    }

    return code;
}

// Returns true if this instruction, for the given EA_SIZE(attr), will require a REX.W prefix
bool emitter::TakesRexWPrefix(const instrDesc* id) const
{
#if defined(TARGET_X86)
    if (!UseVEXEncoding())
    {
        return false;
    }
#endif // TARGET_X86

    instruction ins  = id->idIns();
    emitAttr    attr = id->idOpSize();

    if (IsRexW0Instruction(ins))
    {
        return false;
    }
    else if (IsRexW1Instruction(ins))
    {
        return true;
    }
    else if (IsRexW1EvexInstruction(ins))
    {
        return TakesEvexPrefix(id);
    }

    if (IsRexWXInstruction(ins))
    {
        switch (ins)
        {
            case INS_andn:
            case INS_bextr:
            case INS_blsi:
            case INS_blsmsk:
            case INS_blsr:
            case INS_bzhi:
            case INS_mulx:
            case INS_pdep:
            case INS_pext:
            case INS_rorx:
            case INS_sarx:
            case INS_shlx:
            case INS_shrx:
            {
                if (attr == EA_8BYTE)
                {
                    return true;
                }

                // TODO-Cleanup: This should really only ever be EA_4BYTE
                assert((attr == EA_4BYTE) || (attr == EA_16BYTE));
                return false;
            }

            case INS_gf2p8affineinvqb:
            case INS_gf2p8affineqb:
            {
                return TakesVexPrefix(ins);
            }

            default:
            {
                unreached();
            }
        }
    }

    assert(!IsSimdInstruction(ins));

#ifdef TARGET_AMD64
    // movsx should always sign extend out to 8 bytes just because we don't track
    // whether the dest should be 4 bytes or 8 bytes (attr indicates the size
    // of the source, not the dest).
    // A 4-byte movzx is equivalent to an 8 byte movzx, so it is not special
    // cased here.
    if (ins == INS_movsx)
    {
        return true;
    }

    if (EA_SIZE(attr) != EA_8BYTE)
    {
        return false;
    }

    // TODO-XArch-Cleanup: Better way to not emit REX.W when we don't need it, than just testing all these
    // opcodes...
    // These are all the instructions that default to 8-byte operand without the REX.W bit
    // With 1 special case: movzx because the 4 byte version still zeros-out the hi 4 bytes
    // so we never need it
    if ((ins != INS_push) && (ins != INS_pop) && (ins != INS_movq) && (ins != INS_movzx) && (ins != INS_push_hide) &&
        (ins != INS_pop_hide) && (ins != INS_ret) && (ins != INS_call) && (ins != INS_tail_i_jmp) &&
        !((ins >= INS_i_jmp) && (ins <= INS_l_jg)))
    {
        return true;
    }
    else
    {
        return false;
    }
#else  //! TARGET_AMD64 = TARGET_X86
    return false;
#endif //! TARGET_AMD64
}

//------------------------------------------------------------------------
// HasHighSIMDReg: Checks if an instruction uses a high SIMD registers (mm16-mm31)
// and will require one of the EVEX high SIMD bits (EVEX.R', EVEX.V', EVEX.X)
//
// Arguments:
// id -- instruction descriptor for encoding
//
// Return Value:
// true if instruction will require EVEX encoding for its register operands.
bool emitter::HasHighSIMDReg(const instrDesc* id) const
{
#if defined(TARGET_AMD64)
    if (isHighSimdReg(id->idReg1()) || isHighSimdReg(id->idReg2()))
        return true;

    if (id->idIsSmallDsc())
        return false;

    if ((id->idHasReg3() && isHighSimdReg(id->idReg3())) || (id->idHasReg4() && isHighSimdReg(id->idReg4())))
        return true;
#endif
    // X86 JIT operates in 32-bit mode and hence extended reg are not available.
    return false;
}

//------------------------------------------------------------------------
// HasExtendedGPReg: Checks if an instruction uses an extended general-purpose register - EGPR (r16-r31)
// and will require one of the REX2 EGPR bits (REX2.R4/R3, REX2.B4/B3, REX2.X4/X3)
//
// Arguments:
// id -- instruction descriptor for encoding
//
// Return Value:
// true if instruction will require REX2 encoding for its register operands.
bool emitter::HasExtendedGPReg(const instrDesc* id) const
{
#if defined(TARGET_AMD64)
    // First check if addressing mode is used and if any of those uses eGPRs.
    if (id->idHasMemAdr() &&
        (IsExtendedGPReg(id->idAddr()->iiaAddrMode.amBaseReg) || IsExtendedGPReg(id->idAddr()->iiaAddrMode.amIndxReg)))
    {
        return true;
    }

    if ((id->idHasReg1() && IsExtendedGPReg(id->idReg1())) || (id->idHasReg2() && IsExtendedGPReg(id->idReg2())) ||
        (id->idHasReg3() && IsExtendedGPReg(id->idReg3())) || (id->idHasReg4() && IsExtendedGPReg(id->idReg4())))
    {
        return true;
    }

#endif
    // X86 JIT operates in 32-bit mode and hence extended reg are not available.
    return false;
}

//------------------------------------------------------------------------
// HasMaskReg: Checks if an instruction uses a KMask registers (k0-k7)
//
// Arguments:
// id -- instruction descriptor for encoding
//
// Return Value:
// true if instruction will require EVEX encoding for its register operands.
bool emitter::HasMaskReg(const instrDesc* id) const
{
    if (isMaskReg(id->idReg1()))
    {
        assert(HasKMaskRegisterDest(id->idIns()));
        return true;
    }

#if defined(DEBUG)
    // After APX, KMOV instructions can be encoded in EVEX.
    if (isMaskReg(id->idReg2()))
    {
        assert(IsKInstruction(id->idIns()));
        return UsePromotedEVEXEncoding();
    }

    if (!id->idIsSmallDsc())
    {
        if (id->idHasReg3())
        {
            assert(!isMaskReg(id->idReg3()));
        }

        if (id->idHasReg4())
        {
            assert(!isMaskReg(id->idReg4()));
        }
    }
#endif // DEBUG

    return false;
}

//------------------------------------------------------------------------
// AbsRegNumber: Returns the register value to be used for encoding.
// JIT internally represents registers using regnumber 0 - (REG_STK-1).
// For encoding, we need to separate out GPR, SIMD and K registers.
//
// Arguments:
// reg -- The register being encoded.
//
// Return Value:
// The register value to be used for encoding.
regNumber AbsRegNumber(regNumber reg)
{
    assert(reg < REG_STK);
    if (reg >= KBASE)
    {
        return (regNumber)(reg - KBASE);
    }
    else if (reg >= XMMBASE)
    {
        return (regNumber)(reg - XMMBASE);
    }
    return reg;
}

// Returns true if using this register will require a REX.* prefix.
// Since XMM registers overlap with YMM registers, this routine
// can also be used to know whether a YMM register if the
// instruction in question is AVX.
bool IsExtendedReg(regNumber reg)
{
#ifdef TARGET_AMD64
    return ((reg >= REG_R8) && (reg <= REG_R31)) || ((reg >= REG_XMM8) && (reg <= REG_XMM31));
#else
    // X86 JIT operates in 32-bit mode and hence extended reg are not available.
    return false;
#endif
}

bool emitter::IsExtendedGPReg(regNumber reg) const
{
// TODO-XArch-apx:
// Consider merge this method into IsExtendedReg(regNumber reg)
#ifdef TARGET_AMD64
    if (reg > REG_STK)
    {
        // not an actual reg
        return false;
    }

    if (isHighGPReg(reg))
    {
        // TODO-XArch-APX: Once eEVEX is supported, this should be 'if APX anabled machine'
        assert(UseRex2Encoding());
        return true;
    }
#endif
    return false;
}

// Returns true if using this register, for the given EA_SIZE(attr), will require a REX.* prefix
bool IsExtendedReg(regNumber reg, emitAttr attr)
{
#ifdef TARGET_AMD64
    // Not a register, so doesn't need a prefix
    if (reg > REG_XMM31)
    {
        return false;
    }

    // Opcode field only has 3 bits for the register, these high registers
    // need a 4th bit, that comes from the REX prefix (either REX.X, REX.R, or REX.B)
    if (IsExtendedReg(reg))
    {
        return true;
    }

    if (EA_SIZE(attr) != EA_1BYTE)
    {
        return false;
    }

    // There are 12 one byte registers addressible 'below' r8b:
    //     al, cl, dl, bl, ah, ch, dh, bh, spl, bpl, sil, dil.
    // The first 4 are always addressible, the last 8 are divided into 2 sets:
    //     ah,  ch,  dh,  bh
    //          -- or --
    //     spl, bpl, sil, dil
    // Both sets are encoded exactly the same, the difference is the presence
    // of a REX prefix, even a REX prefix with no other bits set (0x40).
    // So in order to get to the second set we need a REX prefix (but no bits).
    //
    // TODO-AMD64-CQ: if we ever want to start using the first set, we'll need a different way of
    // encoding/tracking/encoding registers.
    return (reg >= REG_RSP);
#else
    // X86 JIT operates in 32-bit mode and hence extended reg are not available.
    return false;
#endif
}

// Since XMM registers overlap with YMM registers, this routine
// can also used to know whether a YMM register in case of AVX instructions.
bool IsXMMReg(regNumber reg)
{
#ifdef TARGET_AMD64
    return (reg >= REG_XMM0) && (reg <= REG_XMM31);
#else  // !TARGET_AMD64
    return (reg >= REG_XMM0) && (reg <= REG_XMM7);
#endif // !TARGET_AMD64
}

//------------------------------------------------------------------------
// HighAwareRegEncoding: For EVEX encoded high SIMD registers (mm16-mm31),
// get a register encoding for bits 0-4, where the 5th bit is encoded via
// EVEX.R', EVEX.R, or EVEX.X.
//
// Arguments:
// reg -- register to encode
//
// Return Value:
// bits 0-4 of register encoding
//
unsigned HighAwareRegEncoding(regNumber reg)
{
    static_assert((REG_XMM0 & 0x7) == 0, "bad XMMBASE");
    return (unsigned)(AbsRegNumber(reg) & 0xF);
}

// Returns bits to be encoded in instruction for the given register.
unsigned RegEncoding(regNumber reg)
{
    static_assert((REG_XMM0 & 0x7) == 0, "bad XMMBASE");
    return (unsigned)(AbsRegNumber(reg) & 0x7);
}

// Utility routines that abstract the logic of adding REX.W, REX.R, REX.X, REX.B and REX prefixes
// SSE2: separate 1-byte prefix gets added before opcode.
// AVX:  specific bits within VEX prefix need to be set in bit-inverted form.
emitter::code_t emitter::AddRexWPrefix(const instrDesc* id, code_t code)
{
    instruction ins = id->idIns();

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        if (TakesEvexPrefix(id) && codeEvexMigrationCheck(code))
        {
            // W-bit is available in 4-byte EVEX prefix that starts with byte 62.
            assert(hasEvexPrefix(code));

            // W-bit is the only bit that is added in non bit-inverted form.
            return emitter::code_t(code | 0x0000800000000000ULL);
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));

            // W-bit is available only in 3-byte VEX prefix that starts with byte C4.
            assert(hasVexPrefix(code));

            // W-bit is the only bit that is added in non bit-inverted form.
            return emitter::code_t(code | 0x00008000000000ULL);
        }
    }
#ifdef TARGET_AMD64
    else if (TakesApxExtendedEvexPrefix(id))
    {
        // If the instruction is not VEX/EVEX encodable, and has EVEX prefix,
        // then it is legacy promoted EVEX.
        assert(hasEvexPrefix(code));
        assert(IsApxExtendedEvexInstruction(ins));
        return emitter::code_t(code | 0x0000800000000000ULL);
    }
    else if (hasRex2Prefix(code))
    {
        return emitter::code_t(code | 0x000800000000ULL);
    }
    return emitter::code_t(code | 0x4800000000ULL);
#else
    assert(!"UNREACHED");
    return code;
#endif
}

#ifdef TARGET_AMD64

emitter::code_t emitter::AddRexRPrefix(const instrDesc* id, code_t code)
{
    instruction ins = id->idIns();

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        if (TakesEvexPrefix(id) && codeEvexMigrationCheck(code)) // TODO-XArch-AVX512: Remove codeEvexMigrationCheck().
        {
            // R-bit is available in 4-byte EVEX prefix that starts with byte 62.
            assert(hasEvexPrefix(code));

            // R-bit is added in bit-inverted form.
            return code & 0xFF7FFFFFFFFFFFFFULL;
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));

            // R-bit is supported by both 2-byte and 3-byte VEX prefix
            assert(hasVexPrefix(code));

            // R-bit is added in bit-inverted form.
            return code & 0xFF7FFFFFFFFFFFULL;
        }
    }
    else if (TakesApxExtendedEvexPrefix(id))
    {
        assert(hasEvexPrefix(code));
        assert(IsApxExtendedEvexInstruction(ins));
        // R-bit is added in bit-inverted form.
        return code & 0xFF7FFFFFFFFFFFFFULL;
    }
    else if (TakesRex2Prefix(id))
    {
        assert(IsRex2EncodableInstruction(ins));
        return code |= 0xD50400000000ULL; // REX2.B3
    }

    return code | 0x4400000000ULL;
}

emitter::code_t emitter::AddRexXPrefix(const instrDesc* id, code_t code)
{
    instruction ins = id->idIns();

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        if (TakesEvexPrefix(id) && codeEvexMigrationCheck(code)) // TODO-XArch-AVX512: Remove codeEvexMigrationCheck().
        {
            // X-bit is available in 4-byte EVEX prefix that starts with byte 62.
            assert(hasEvexPrefix(code));

            // X-bit is added in bit-inverted form.
            return code & 0xFFBFFFFFFFFFFFFFULL;
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));

            // X-bit is available only in 3-byte VEX prefix that starts with byte C4.
            assert(hasVexPrefix(code));

            // X-bit is added in bit-inverted form.
            return code & 0xFFBFFFFFFFFFFFULL;
        }
    }
    else if (TakesApxExtendedEvexPrefix(id))
    {
        assert(hasEvexPrefix(code));
        assert(IsApxExtendedEvexInstruction(ins));
        // X-bit is added in bit-inverted form.
        return code & 0xFFBFFFFFFFFFFFFFULL;
    }
    else if (TakesRex2Prefix(id))
    {
        assert(IsRex2EncodableInstruction(ins));
        return code |= 0xD50200000000ULL; // REX2.B3
    }

    return code | 0x4200000000ULL;
}

emitter::code_t emitter::AddRexBPrefix(const instrDesc* id, code_t code)
{
    instruction ins = id->idIns();

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        if (TakesEvexPrefix(id) && codeEvexMigrationCheck(code)) // TODO-XArch-AVX512: Remove codeEvexMigrationCheck().
        {
            // B-bit is available in 4-byte EVEX prefix that starts with byte 62.
            assert(hasEvexPrefix(code));

            // B-bit is added in bit-inverted form.
            return code & 0xFFDFFFFFFFFFFFFFULL;
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));

            // B-bit is available only in 3-byte VEX prefix that starts with byte C4.
            assert(hasVexPrefix(code));

            // B-bit is added in bit-inverted form.
            return code & 0xFFDFFFFFFFFFFFULL;
        }
    }
    else if (TakesApxExtendedEvexPrefix(id))
    {
        assert(IsApxExtendedEvexInstruction(ins));
        // R-bit is added in bit-inverted form.
        return code & 0xFFDFFFFFFFFFFFFFULL;
    }
    else if (TakesRex2Prefix(id))
    {
        assert(IsRex2EncodableInstruction(ins));
        return code |= 0xD50100000000ULL; // REX2.B3
    }

    return code | 0x4100000000ULL;
}

// Adds REX prefix (0x40) without W, R, X or B bits set
emitter::code_t emitter::AddRexPrefix(instruction ins, code_t code)
{
    assert(!IsVexEncodableInstruction(ins));
    return code | 0x4000000000ULL;
}

//------------------------------------------------------------------------
// AddEvexVPrimePrefix: Add the EVEX.V' bit to the EVEX prefix. EVEX.V'
// is encoded in inverted form.
//
// Arguments:
// code -- register to encode
//
// Return Value:
// code with EVEX.V' set in verted form.
//
emitter::code_t emitter::AddEvexVPrimePrefix(code_t code)
{
#if defined(TARGET_AMD64)
    assert((UseEvexEncoding() || UsePromotedEVEXEncoding()) && hasEvexPrefix(code));
    return emitter::code_t(code & 0xFFFFFFF7FFFFFFFFULL);
#else
    unreached();
#endif
}

//------------------------------------------------------------------------
// AddEvexRPrimePrefix: Add the EVEX.R' bit to the EVEX prefix. EVEX.R'
// is encoded in inverted form.
//
// Arguments:
// code -- register to encode
//
// Return Value:
// code with EVEX.R' set in verted form.
//
emitter::code_t emitter::AddEvexRPrimePrefix(code_t code)
{
#if defined(TARGET_AMD64)
    assert((UseEvexEncoding() || UsePromotedEVEXEncoding()) && hasEvexPrefix(code));
    return emitter::code_t(code & 0xFFEFFFFFFFFFFFFFULL);
#else
    unreached();
#endif
}

#endif // TARGET_AMD64

bool isPrefix(BYTE b)
{
    assert(b != 0);    // Caller should check this
    assert(b != 0x67); // We don't use the address size prefix
    assert(b != 0x65); // The GS segment override prefix is emitted separately
    assert(b != 0x64); // The FS segment override prefix is emitted separately
    assert(b != 0xF0); // The lock prefix is emitted separately
    assert(b != 0x2E); // We don't use the CS segment override prefix
    assert(b != 0x3E); // Or the DS segment override prefix
    assert(b != 0x26); // Or the ES segment override prefix
    assert(b != 0x36); // Or the SS segment override prefix

    // That just leaves the size prefixes used in SSE opcodes:
    //      Scalar Double  Scalar Single  Packed Double
    return ((b == 0xF2) || (b == 0xF3) || (b == 0x66));
}

//------------------------------------------------------------------------
// emitExtractEvexPrefix: Extract the EVEX prefix
//
// Arguments:
//    [In]      ins  -- processor instruction to check.
//    [In, Out] code -- opcode bits which will no longer contain the evex prefix on return
//
// Return Value:
//    The extracted EVEX prefix.
//
emitter::code_t emitter::emitExtractEvexPrefix(instruction ins, code_t& code) const
{
    assert(IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));

    code_t evexPrefix = (code >> 32) & 0xFFFFFFFF;
    code &= 0x00000000FFFFFFFFLL;

    WORD leadingBytes = 0;
    BYTE check        = (code >> 24) & 0xFF;

    if (check != 0)
    {
        // check for a prefix in the 11 position
        BYTE sizePrefix = (code >> 16) & 0xFF;

        if (sizePrefix == 0)
        {
            // no simd prefix for EVEX2 - AVX10.2 and above
            assert(emitComp->compIsaSupportedDebugOnly(InstructionSet_AVX10v2) ||
                   emitComp->compIsaSupportedDebugOnly(InstructionSet_AVXVNNIINT) ||
                   emitComp->compIsaSupportedDebugOnly(InstructionSet_AVXVNNIINT_V512));
        }
        else if (isPrefix(sizePrefix))
        {
            // EVEX1 - EVEX encoding before Avx10.2
            // 'pp' bits in byte 1 of EVEX prefix allows us to encode SIMD size prefixes as two bits
            //
            //   00  - None   (0F    - packed float)
            //   01  - 66     (66 0F - packed double)
            //   10  - F3     (F3 0F - scalar float)
            //   11  - F2     (F2 0F - scalar double)
            switch (sizePrefix)
            {
                case 0x66:
                {
                    // After APX, BMI instructions can be encoded in EVEX.
                    if (IsBMIInstruction(ins))
                    {
                        switch (ins)
                        {
                            case INS_rorx:
                            case INS_pdep:
                            case INS_mulx:
                            case INS_shrx:
                            {
                                evexPrefix |= (0x03 << 8);
                                break;
                            }

                            case INS_pext:
                            case INS_sarx:
                            {
                                evexPrefix |= (0x02 << 8);
                                break;
                            }

                            case INS_shlx:
                            {
                                evexPrefix |= (0x01 << 8);
                                break;
                            }

                            default:
                            {
                                break;
                            }
                        }
                        break;
                    }
                    assert(!IsBMIInstruction(ins));
                    evexPrefix |= (0x01 << 8);
                    break;
                }

                case 0xF3:
                {
                    evexPrefix |= (0x02 << 8);
                    break;
                }

                case 0xF2:
                {
                    evexPrefix |= (0x03 << 8);
                    break;
                }

                default:
                {
                    assert(!"unrecognized SIMD size prefix");
                    unreached();
                }
            }
        }
        else
        {
            unreached();
        }
        // Now the byte in the 22 position should be either of the below:
        //                          1. An escape byte 0F (For isa before AVX10.2)
        //                          2. A map number from 0 to 7 (For AVX10.2 and above)
        leadingBytes = check;
        assert((leadingBytes == 0x0F) || ((emitComp->compIsaSupportedDebugOnly(InstructionSet_AVX10v2) ||
                                           (emitComp->compIsaSupportedDebugOnly(InstructionSet_APX))) &&
                                          (leadingBytes >= 0x00) && (leadingBytes <= 0x07)));

        // Get rid of both sizePrefix and escape byte
        code &= 0x0000FFFFLL;

        // Check the byte in the 33 position to see if it is 3A or 38.
        // In such a case escape bytes must be 0x0F3A or 0x0F38
        check = code & 0xFF;

        if ((check == 0x3A) || (check == 0x38))
        {
            leadingBytes = (leadingBytes << 8) | check;
            code &= 0x0000FF00LL;
        }
    }
    else
    {
        // 2-byte opcode with the bytes ordered as 0x0011RM22. There are 2 posibilities here:
        //      1. the byte in position 11 must be an escape byte.
        //      2. the byte in position 11 must be a map number from 0 to 7.

        // APX promoted EVEX instructions might also go onto this path, so the opcode can also be 1-byte in the form of
        // 0x0000RM11.
        leadingBytes = (code >> 16) & 0xFF;
        assert(leadingBytes == 0x0F ||
               (emitComp->compIsaSupportedDebugOnly(InstructionSet_AVX10v2) && leadingBytes >= 0x00 &&
                leadingBytes <= 0x07) ||
               (IsApxExtendedEvexInstruction(ins) && leadingBytes == 0));
        code &= 0xFFFF;
    }

    // Encode the escape byte in the evex prefix using either of the below:
    //          1. If there is an escape byte it must be 0x0F or 0x0F3A or 0x0F38
    //             mm bits in byte 0 of EVEX prefix allows us to encode these
    //             implied leading bytes. They are identical to low two bits of VEX.mmmmm
    //          2. If there is no escape byte but a map number from 0 to 7,
    //             EVEX.mmm bits in byte 0 of EVEX prefix allows us to encode these
    //             map numbers

    switch (leadingBytes)
    {
        case 0x00:
        {
            // there is no leading byte
            break;
        }

        case 0x0F:
        {
            if (((evexPrefix >> 16) & 0x07) == 0x04)
            {
                // MAP index equal to 4 indicates this instruction is a promoted legacy instruction.
                // the MAP ID has been set when EVEX prefix is added.
                break;
            }
            evexPrefix |= (0x01 << 16);
            break;
        }

        case 0x0F38:
        {
            evexPrefix |= (0x02 << 16);
            break;
        }

        case 0x0F3A:
        {
            evexPrefix |= (0x03 << 16);
            break;
        }

        case 0x04:
        {
            assert(emitComp->compIsaSupportedDebugOnly(InstructionSet_APX));
            evexPrefix |= (0x04 << 16);
            break;
        }

        case 0x05:
        {
            assert(emitComp->compIsaSupportedDebugOnly(InstructionSet_AVX10v2));
            evexPrefix |= (0x05 << 16);
            break;
        }

        case 0x01:
        case 0x02:
        case 0x03:
        case 0x06:
        case 0x07:
        default:
        {
            assert(!"encountered unknown leading bytes");
            unreached();
        }
    }

    // At this point
    //     EVEX.2211RM33 got transformed as EVEX.0000RM33
    //     EVEX.0011RM22 got transformed as EVEX.0000RM22
    //
    // Now output EVEX prefix leaving the 4-byte opcode
    // EVEX prefix is always 4 bytes

    return evexPrefix;
}

//------------------------------------------------------------------------
// emitExtractVexPrefix: Extract the VEX prefix
//
// Arguments:
//    [In]      ins  -- processor instruction to check.
//    [In, Out] code -- opcode bits which will no longer contain the vex prefix on return
//
// Return Value:
//    The extracted VEX prefix.
//
emitter::code_t emitter::emitExtractVexPrefix(instruction ins, code_t& code) const
{
    assert(IsVexEncodableInstruction(ins));

    code_t vexPrefix = (code >> 32) & 0x00FFFFFF;
    code &= 0x00000000FFFFFFFFLL;

    WORD leadingBytes = 0;
    BYTE check        = (code >> 24) & 0xFF;

    if (check != 0)
    {
        // 3-byte opcode: with the bytes ordered as 0x2211RM33 or
        // 4-byte opcode: with the bytes ordered as 0x22114433
        //
        // check for a prefix in the 11 position
        BYTE sizePrefix = (code >> 16) & 0xFF;

        if (sizePrefix == 0)
        {
            // no simd prefix for Avx-Vnni-Int* ISAs subset of instructions
            // INS_vpdpbuud[,s], INS_vpdpwuud[,s]
            assert(emitComp->compIsaSupportedDebugOnly(InstructionSet_AVXVNNIINT) ||
                   emitComp->compIsaSupportedDebugOnly(InstructionSet_AVXVNNIINT_V512));
        }
        else if (isPrefix(sizePrefix))
        {
            // 'pp' bits in byte2 of VEX prefix allows us to encode SIMD size prefixes as two bits
            //
            //   00  - None   (0F    - packed float)
            //   01  - 66     (66 0F - packed double)
            //   10  - F3     (F3 0F - scalar float
            //   11  - F2     (F2 0F - scalar double)
            switch (sizePrefix)
            {
                case 0x66:
                {
                    if (IsBMIInstruction(ins))
                    {
                        switch (ins)
                        {
                            case INS_rorx:
                            case INS_pdep:
                            case INS_mulx:
                            case INS_shrx:
                            {
                                vexPrefix |= 0x03;
                                break;
                            }

                            case INS_pext:
                            case INS_sarx:
                            {
                                vexPrefix |= 0x02;
                                break;
                            }

                            case INS_shlx:
                            {
                                vexPrefix |= 0x01;
                                break;
                            }

                            default:
                            {
                                vexPrefix |= 0x00;
                                break;
                            }
                        }
                    }
                    else
                    {
                        vexPrefix |= 0x01;
                    }
                    break;
                }

                case 0xF3:
                {
                    vexPrefix |= 0x02;
                    break;
                }

                case 0xF2:
                {
                    vexPrefix |= 0x03;
                    break;
                }

                default:
                {
                    assert(!"unrecognized SIMD size prefix");
                    unreached();
                }
            }
        }
        else
        {
            unreached();
        }

        // Now the byte in the 22 position must be an escape byte 0F
        leadingBytes = check;
        assert(leadingBytes == 0x0F);

        // Get rid of both sizePrefix and escape byte
        code &= 0x0000FFFFLL;

        // Check the byte in the 33 position to see if it is 3A or 38.
        // In such a case escape bytes must be 0x0F3A or 0x0F38
        check = code & 0xFF;

        if ((check == 0x3A) || (check == 0x38))
        {
            leadingBytes = (leadingBytes << 8) | check;
            code &= 0x0000FF00LL;
        }
    }
    else
    {
        // 2-byte opcode with the bytes ordered as 0x0011RM22
        // the byte in position 11 must be an escape byte.
        leadingBytes = (code >> 16) & 0xFF;
        assert(leadingBytes == 0x0F || leadingBytes == 0x00);
        code &= 0xFFFF;
    }

    // If there is an escape byte it must be 0x0F or 0x0F3A or 0x0F38
    // m-mmmmm bits in byte 1 of VEX prefix allows us to encode these
    // implied leading bytes. 0x0F is supported by both the 2-byte and
    // 3-byte encoding. While 0x0F3A and 0x0F38 are only supported by
    // the 3-byte version.

    switch (leadingBytes)
    {
        case 0x00:
        {
            // there is no leading byte
            break;
        }

        case 0x0F:
        {
            vexPrefix |= 0x0100;
            break;
        }

        case 0x0F38:
        {
            vexPrefix |= 0x0200;
            break;
        }

        case 0x0F3A:
        {
            vexPrefix |= 0x0300;
            break;
        }

        default:
        {
            assert(!"encountered unknown leading bytes");
            unreached();
        }
    }

    // At this point
    //     VEX.2211RM33 got transformed as VEX.0000RM33
    //     VEX.0011RM22 got transformed as VEX.0000RM22
    //
    // Now output VEX prefix leaving the 4-byte opcode

    return vexPrefix;
}

//------------------------------------------------------------------------
// emitOutputRexOrSimdPrefixIfNeeded: Outputs EVEX prefix (in case of AVX512 instructions),
// VEX prefix (in case of AVX instructions) and REX.R/X/W/B otherwise.
//
// Arguments:
//    ins -- processor instruction to check.
//    dst -- buffer to write prefix to.
//    code -- opcode bits.
//    attr -- operand size
//
// Return Value:
//    Size of prefix.
//
unsigned emitter::emitOutputRexOrSimdPrefixIfNeeded(instruction ins, BYTE* dst, code_t& code)
{
    // TODO-XArch-AVX512: Remove redundant code and collapse into single pathway for EVEX and VEX if possible.
    if (hasEvexPrefix(code))
    {
        code_t evexPrefix = emitExtractEvexPrefix(ins, code);
        assert(evexPrefix != 0);

        emitOutputByte(dst, ((evexPrefix >> 24) & 0xFF));
        emitOutputByte(dst + 1, ((evexPrefix >> 16) & 0xFF));
        emitOutputByte(dst + 2, (evexPrefix >> 8) & 0xFF);
        emitOutputByte(dst + 3, evexPrefix & 0xFF);

        return 4;
    }
    else if (hasVexPrefix(code))
    {
        code_t vexPrefix = emitExtractVexPrefix(ins, code);
        assert(vexPrefix != 0);

        // The 2-byte VEX encoding, requires that the X and B-bits are set (these
        // bits are inverted from the REX values so set means off), the W-bit is
        // not set (this bit is not inverted), and that the m-mmmm bits are 0-0001
        // (the 2-byte VEX encoding only supports the 0x0F leading byte). When these
        // conditions are met, we can change byte-0 from 0xC4 to 0xC5 and then
        // byte-1 is the logical-or of bit 7 from byte-1 and bits 0-6 from byte 2
        // from the 3-byte VEX encoding.
        //
        // Given the above, the check can be reduced to a simple mask and comparison.
        // * 0xFFFF7F80 is a mask that ignores any bits whose value we don't care about:
        //   * R can be set or unset              (0x7F ignores bit 7)
        //   * vvvv can be any value              (0x80 ignores bits 3-6)
        //   * L can be set or unset              (0x80 ignores bit 2)
        //   * pp can be any value                (0x80 ignores bits 0-1)
        // * 0x00C46100 is a value that signifies the requirements listed above were met:
        //   * We must be a three-byte VEX opcode (0x00C4)
        //   * X and B must be set                (0x61 validates bits 5-6)
        //   * m-mmmm must be 0-00001             (0x61 validates bits 0-4)
        //   * W must be unset                    (0x00 validates bit 7)

        if ((vexPrefix & 0xFFFF7F80) == 0x00C46100)
        {
            emitOutputByte(dst, 0xC5);
            emitOutputByte(dst + 1, ((vexPrefix >> 8) & 0x80) | (vexPrefix & 0x7F));

            return 2;
        }

        emitOutputByte(dst, ((vexPrefix >> 16) & 0xFF));
        emitOutputByte(dst + 1, ((vexPrefix >> 8) & 0xFF));
        emitOutputByte(dst + 2, vexPrefix & 0xFF);

        return 3;
    }
    else if (hasRex2Prefix(code))
    {
        WORD rex2Prefix = (code >> 32) & 0xFFFF;
        noway_assert(rex2Prefix >= 0xD500 && rex2Prefix <= 0xD5FF);
        code &= 0x00000000FFFFFFFFLL;
        int emittedSize = 0;

        if ((code & 0xFF) == 0x0F)
        {
            // some map-1 instructions have opcode in forms like:
            // XX0F, remove the leading 0x0F byte as it has been recorded in REX2.
            code = code >> 8;
        }

        BYTE check = (code >> 24) & 0xFF;
        if (check == 0)
        {
            // 3-byte opcode: with the bytes ordered as 0x00113322
            // check for a prefix in the 11 position
            check = (code >> 16) & 0xFF;
            if (check != 0 && isPrefix(check))
            {
                code &= 0x00000000FF00FFFFLL;
                emittedSize += emitOutputByte(dst, check);
                dst += 1;
            }

            if (check == 0x0F)
            {
                // REX2 does not need 0F in the opcode.
                code &= 0x00000000FF00FFFFLL;
            }
        }
        else
        {
            // 4-byte opcode with the bytes ordered as 0x22114433
            // first check for a prefix in the 11 position
            BYTE check2 = (code >> 16) & 0xFF;
            if (isPrefix(check2))
            {
                assert(!isPrefix(check)); // We currently don't use this, so it is untested
                if (isPrefix(check))
                {
                    // 3 prefixes were rex = rr, check = c1, check2 = c2 encoded as 0xrrc1c2XXXX
                    // Change to c2rrc1XXXX, and emit check2 now
                    // code = (((code_t)prefix << 24) | ((code_t)check << 16) | (code & 0x0000FFFFLL));
                    code &= 0x000000000000FFFFLL;
                    emittedSize += emitOutputByte(dst, check2);
                    dst += 1;
                    emittedSize += emitOutputByte(dst, check);
                    dst += 1;
                }
                else
                {
                    // REX2 do not need the 0F prefix.
                    code &= 0x000000000000FFFFLL;
                    emittedSize += emitOutputByte(dst, check2);
                    dst += 1;
                }
            }
        }

        emittedSize += emitOutputByte(dst, ((rex2Prefix >> 8) & 0xFF));
        emittedSize += emitOutputByte(dst + 1, (rex2Prefix & 0xFF));

        return emittedSize;
    }

#ifdef TARGET_AMD64
    if (code > 0x00FFFFFFFFLL)
    {
        BYTE prefix = (code >> 32) & 0xFF;
        noway_assert(prefix >= 0x40 && prefix <= 0x4F);
        code &= 0x00000000FFFFFFFFLL;

        // TODO-AMD64-Cleanup: when we remove the prefixes (just the SSE opcodes right now)
        // we can remove this code as well

        // The REX prefix is required to come after all other prefixes.
        // Some of our 'opcodes' actually include some prefixes, if that
        // is the case, shift them over and place the REX prefix after
        // the other prefixes, and emit any prefix that got moved out.
        BYTE check = (code >> 24) & 0xFF;
        if (check == 0)
        {
            // 3-byte opcode: with the bytes ordered as 0x00113322
            // check for a prefix in the 11 position
            check = (code >> 16) & 0xFF;
            if (check != 0 && isPrefix(check))
            {
                // Swap the rex prefix and whatever this prefix is
                code = (((DWORD)prefix << 16) | (code & 0x0000FFFFLL));
                // and then emit the other prefix
                return emitOutputByte(dst, check);
            }
        }
        else
        {
            // 4-byte opcode with the bytes ordered as 0x22114433
            // first check for a prefix in the 11 position
            BYTE check2 = (code >> 16) & 0xFF;
            if (isPrefix(check2))
            {
                assert(!isPrefix(check)); // We currently don't use this, so it is untested
                if (isPrefix(check))
                {
                    // 3 prefixes were rex = rr, check = c1, check2 = c2 encoded as 0xrrc1c2XXXX
                    // Change to c2rrc1XXXX, and emit check2 now
                    code = (((code_t)prefix << 24) | ((code_t)check << 16) | (code & 0x0000FFFFLL));
                }
                else
                {
                    // 2 prefixes were rex = rr, check2 = c2 encoded as 0xrrXXc2XXXX, (check is part of the opcode)
                    // Change to c2XXrrXXXX, and emit check2 now
                    code = (((code_t)check << 24) | ((code_t)prefix << 16) | (code & 0x0000FFFFLL));
                }
                return emitOutputByte(dst, check2);
            }
        }

        return emitOutputByte(dst, prefix);
    }
#endif // TARGET_AMD64

    return 0;
}

#ifdef TARGET_AMD64
/*****************************************************************************
 * Is the last instruction emitted a call instruction?
 */
bool emitter::emitIsLastInsCall()
{
    if (emitHasLastIns() && (emitLastIns->idIns() == INS_call))
    {
        return true;
    }

    return false;
}

/*****************************************************************************
 * We're about to create an epilog. If the last instruction we output was a 'call',
 * then we need to insert a NOP, to allow for proper exception-handling behavior.
 */
void emitter::emitOutputPreEpilogNOP()
{
    if (emitIsLastInsCall())
    {
        emitIns(INS_nop);
    }
}

#endif // TARGET_AMD64

// Size of rex prefix in bytes
unsigned emitter::emitGetRexPrefixSize(instruction ins)
{
    // In case of AVX instructions, REX prefixes are part of VEX prefix.
    // And hence requires no additional byte to encode REX prefixes.
    if (IsVexOrEvexEncodableInstruction(ins))
    {
        return 0;
    }

    // If not AVX, then we would need 1-byte to encode REX prefix.
    return 1;
}

// Size of rex prefix in bytes
unsigned emitter::emitGetRexPrefixSize(instrDesc* id, instruction ins)
{
    // In case of AVX instructions, REX prefixes are part of VEX prefix.
    // And hence requires no additional byte to encode REX prefixes.
    if (IsVexOrEvexEncodableInstruction(ins))
    {
        return 0;
    }

    if (TakesApxExtendedEvexPrefix(id))
    {
        return 0;
    }

    if (TakesRex2Prefix(id))
    {
        return 0;
    }

    // If not AVX, then we would need 1-byte to encode REX prefix.
    return 1;
}

//------------------------------------------------------------------------
// emitGetEvexPrefixSize: Gets Size of EVEX prefix in bytes
//
// Arguments:
//    ins   -- The instruction descriptor
//
// Returns:
//    Prefix size in bytes.
//
unsigned emitter::emitGetEvexPrefixSize(instrDesc* id) const
{
    assert(IsEvexEncodableInstruction(id->idIns()));
    return 4;
}

//------------------------------------------------------------------------
// emitGetAdjustedSize: Determines any size adjustment needed for a given instruction based on the current
// configuration.
//
// Arguments:
//    id    -- The instruction descriptor being emitted
//    code  -- The current opcode and any known prefixes
//
// Returns:
//    Updated size.
//
unsigned emitter::emitGetAdjustedSize(instrDesc* id, code_t code) const
{
    instruction ins          = id->idIns();
    unsigned    adjustedSize = 0;

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        unsigned prefixAdjustedSize = 0;

        // VEX/EVEX prefix encodes some bytes of the opcode and as a result, overall size of the instruction reduces.
        // Therefore, to estimate the size adding VEX/EVEX prefix size and size of instruction opcode bytes will always
        // overstimate.
        //
        // Instead this routine will adjust the size of VEX/EVEX prefix based on the number of bytes of opcode it
        // encodes so that instruction size estimate will be accurate.
        //
        // Basically this  will decrease the prefixSize, so that opcodeSize + prefixAdjustedSize will be the
        // right size.
        //
        // rightOpcodeSize + prefixSize
        //  = (opcodeSize - extraBytesSize) + prefixSize
        //  = opcodeSize + (prefixSize - extraBytesSize)
        //  = opcodeSize + prefixAdjustedSize

        if (TakesEvexPrefix(id))
        {
            prefixAdjustedSize = emitGetEvexPrefixSize(id);
            assert(prefixAdjustedSize == 4);
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));

            prefixAdjustedSize = emitGetVexPrefixSize(id);
            assert((prefixAdjustedSize == 2) || (prefixAdjustedSize == 3));
        }

        assert(prefixAdjustedSize != 0);

        // In this case, opcode will contains escape prefix at least one byte,
        // prefixAdjustedSize should be minus one.
        prefixAdjustedSize -= 1;

        // Get the fourth byte in Opcode.
        // If this byte is non-zero, then we should check whether the opcode contains SIMD prefix or not.
        BYTE check = (code >> 24) & 0xFF;

        if (check != 0)
        {
            // 3-byte opcode: with the bytes ordered as 0x2211RM33 or
            // 4-byte opcode: with the bytes ordered as 0x22114433
            // Simd prefix is at the first byte.
            BYTE sizePrefix = (code >> 16) & 0xFF;

            if (sizePrefix != 0 && isPrefix(sizePrefix))
            {
                prefixAdjustedSize -= 1;
            }

            // If the opcode size is 4 bytes, then the second escape prefix is at fourth byte in opcode.
            // But in this case the opcode has not counted R\M part.
            // opcodeSize + prefixAdjustedSize - extraEscapePrefixSize + modRMSize
            //  = opcodeSize + prefixAdjustedSize -1 + 1
            //  = opcodeSize + prefixAdjustedSize
            // So although we may have second byte escape prefix, we won't decrease prefixAdjustedSize.
        }

        adjustedSize = prefixAdjustedSize;
    }
    else if (Is4ByteSSEInstruction(ins))
    {
        // The 4-Byte SSE instructions require one additional byte to hold the ModRM byte
        adjustedSize++;
    }
#ifdef TARGET_AMD64
    else if (IsRex2EncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
    {
        unsigned prefixAdjustedSize = 0;
        if (TakesApxExtendedEvexPrefix(id))
        {
            prefixAdjustedSize = 4;
            // If the opcode will be prefixed by EVEX, then all the map-1-legacy instructions can remove the escape
            // prefix
            if (IsLegacyMap1(code))
            {
                prefixAdjustedSize -= 1;
            }
        }
        else if (TakesRex2Prefix(id))
        {
            prefixAdjustedSize = 2;
            // If the opcode will be prefixed by REX2, then all the map-1-legacy instructions can remove the escape
            // prefix
            if (IsLegacyMap1(code))
            {
                prefixAdjustedSize -= 1;
            }
        }

        emitAttr attr = id->idOpSize();
        if ((attr == EA_2BYTE) && (ins != INS_movzx) && (ins != INS_movsx) && !TakesApxExtendedEvexPrefix(id))
        {
            // Most 16-bit operand instructions will need a 0x66 prefix.
            prefixAdjustedSize++;
        }

        adjustedSize = prefixAdjustedSize;
    }
#endif // TARGET_AMD64
    else
    {
        if (ins == INS_crc32)
        {
            // Adjust code size for CRC32 that has 4-byte opcode but does not use SSE38 or EES3A encoding.
            adjustedSize++;
        }

        emitAttr attr = id->idOpSize();

        if ((attr == EA_2BYTE) && (ins != INS_movzx) && (ins != INS_movsx))
        {
            // Most 16-bit operand instructions will need a 0x66 prefix.
            adjustedSize++;
        }
    }

    return adjustedSize;
}

//
//------------------------------------------------------------------------
// emitGetPrefixSize: Get size of rex or vex prefix emitted in code
//
// Arguments:
//    id                    -- The instruction descriptor for which to get its prefix size
//    code                  -- The current opcode and any known prefixes
//    includeRexPrefixSize  -- If Rex Prefix size should be included or not
//
unsigned emitter::emitGetPrefixSize(instrDesc* id, code_t code, bool includeRexPrefixSize)
{
    if (hasEvexPrefix(code))
    {
        return emitGetEvexPrefixSize(id);
    }

    if (hasVexPrefix(code))
    {
        return emitGetVexPrefixSize(id);
    }

    if (hasRex2Prefix(code))
    {
        assert(IsRex2EncodableInstruction(id->idIns()));
        return 2;
    }

    if (includeRexPrefixSize && hasRexPrefix(code))
    {
        if (instrIsExtendedReg3opImul(id->idIns()) && TakesApxExtendedEvexPrefix(id))
        {
            // there is a special case when calculating the size of IMUL with APX-EVEX,
            // IMUL_08 or beyond will have a built-in REX prefix with its opcode,
            // so it will hit this branch, but when IMUL is encoded with APX-EVEX,
            // the size of REX is included in the prefix size, where should be calculated outside.
            return 0;
        }
        return 1;
    }

    return 0;
}

#ifdef TARGET_X86
/*****************************************************************************
 *
 *  Record a non-empty stack
 */

void emitter::emitMarkStackLvl(unsigned stackLevel)
{
    assert(int(stackLevel) >= 0);
    assert(emitCurStackLvl == 0);
    assert(emitCurIG->igStkLvl == 0);
    assert(emitCurIGfreeNext == emitCurIGfreeBase);

    assert(stackLevel && stackLevel % sizeof(int) == 0);

    emitCurStackLvl = emitCurIG->igStkLvl = stackLevel;

    if (emitMaxStackDepth < emitCurStackLvl)
    {
        JITDUMP("Upping emitMaxStackDepth from %d to %d\n", emitMaxStackDepth, emitCurStackLvl);
        emitMaxStackDepth = emitCurStackLvl;
    }
}
#endif

/*****************************************************************************
 *
 *  Get hold of the address mode displacement value for an indirect call.
 */

inline ssize_t emitter::emitGetInsCIdisp(instrDesc* id) const
{
    if (id->idIsLargeCall())
    {
        return ((instrDescCGCA*)id)->idcDisp;
    }
    else
    {
        assert(!id->idIsLargeDsp());
        assert(!id->idIsLargeCns());

        return id->idAddr()->iiaAddrMode.amDisp;
    }
}

/** ***************************************************************************
 *
 *  The following table is used by the instIsFP()/instUse/DefFlags() helpers.
 */

// clang-format off
const insFlags CodeGenInterface::instInfo[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) static_cast<insFlags>(flags),
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) static_cast<insFlags>(flags),
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) static_cast<insFlags>(flags),
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) static_cast<insFlags>(flags),
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) static_cast<insFlags>(flags),
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) static_cast<insFlags>(flags),
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

/*****************************************************************************
 *
 *  Initialize the table used by emitInsModeFormat().
 */

// clang-format off
const uint8_t emitter::emitInsModeFmtTab[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) um,
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) um,
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) um,
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) um,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) um,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) um,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

#ifdef DEBUG
unsigned const emitter::emitInsModeFmtCnt = ArrLen(emitInsModeFmtTab);
#endif

/*****************************************************************************
 *
 *  Combine the given base format with the update mode of the instruction.
 */

inline emitter::insFormat emitter::emitInsModeFormat(instruction ins, insFormat base, bool useNDD)
{
    assert(IF_RRD + IUM_RD == IF_RRD);
    assert(IF_RRD + IUM_WR == IF_RWR);
    assert(IF_RRD + IUM_RW == IF_RRW);

#ifdef TARGET_AMD64
    if (useNDD)
    {
        assert(IsApxNddEncodableInstruction(ins));
        if (ins == INS_rcl_N || ins == INS_rcr_N || ins == INS_rol_N || ins == INS_ror_N || ins == INS_shl_N ||
            ins == INS_shr_N || ins == INS_sar_N)
        {
            // shift instructions has its own instruction format.
            return IF_RWR_RRD_SHF;
        }
        // NDD instructions have the following operand encoding:
        // 1. (w, r, r) for binary
        // 2. (w, r) for unary
        // These format are not properly tracked by the original IF table, we need to fix them here.
        switch (base)
        {
            case IF_RRD_RRD_RRD:
                return IF_RWR_RRD_RRD;

            case IF_RRD_RRD_ARD:
                return IF_RWR_RRD_ARD;

            case IF_RRD_RRD_CNS:
                return IF_RWR_RRD_CNS;

            case IF_RRD_RRD_SRD:
                return IF_RWR_RRD_SRD;

            // we only apply NDD on unary instructions with register uses.
            case IF_RRD_RRD:
                return IF_RWR_RRD;

            default:
                // There should not be any other instruction format with NDD feature.
                unreached();
        }
    }
    else
    {
        return (insFormat)(base + emitInsUpdateMode(ins));
    }
#endif

    return (insFormat)(base + emitInsUpdateMode(ins));
}

// This is a helper we need due to Vs Whidbey #254016 in order to distinguish
// if we can not possibly be updating an integer register. This is not the best
// solution, but the other ones (see bug) are going to be much more complicated.
bool emitter::emitInsCanOnlyWriteSSE2OrAVXReg(instrDesc* id)
{
    instruction ins = id->idIns();

    if (!IsSimdInstruction(ins))
    {
        return false;
    }

    switch (ins)
    {
        case INS_andn:
        case INS_bextr:
        case INS_blsi:
        case INS_blsmsk:
        case INS_blsr:
        case INS_bzhi:
        case INS_cvttsd2si32:
        case INS_cvttsd2si64:
        case INS_cvttss2si32:
        case INS_cvttss2si64:
        case INS_cvtsd2si32:
        case INS_cvtsd2si64:
        case INS_cvtss2si32:
        case INS_cvtss2si64:
        case INS_extractps:
        case INS_movd32:
        case INS_movd64:
        case INS_movmskpd:
        case INS_movmskps:
        case INS_mulx:
        case INS_pdep:
        case INS_pext:
        case INS_pmovmskb:
        case INS_pextrb:
        case INS_pextrd:
        case INS_pextrq:
        case INS_pextrw:
        case INS_pextrw_sse42:
        case INS_rorx:
        case INS_shlx:
        case INS_sarx:
        case INS_shrx:
        case INS_vcvtsd2usi32:
        case INS_vcvtsd2usi64:
        case INS_vcvtss2usi32:
        case INS_vcvtss2usi64:
        case INS_vcvttsd2usi32:
        case INS_vcvttsd2usi64:
        case INS_vcvttss2usi32:
        case INS_vcvttss2usi64:
        {
            // These SSE instructions write to a general purpose integer register.
            return false;
        }
        case INS_kmovb_gpr:
        case INS_kmovw_gpr:
        case INS_kmovd_gpr:
        case INS_kmovq_gpr:
        {
            // These kmov writes to a general purpose integer register
            return !isGeneralRegister(id->idReg1());
        }
        default:
        {
            return true;
        }
    }
}

/*****************************************************************************
 *
 *  Returns the base encoding of the given CPU instruction.
 */

inline size_t insCode(instruction ins)
{
    // clang-format off
    const static uint32_t insCodes[] =
    {
        #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) mr,
        #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) mr,
        #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) mr,
        #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) mr,
        #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) mr,
        #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) mr,
        #include "instrs.h"
        #undef  INST0
        #undef  INST1
        #undef  INST2
        #undef  INST3
        #undef  INST4
        #undef  INST5
    };
    // clang-format on

    assert((unsigned)ins < ArrLen(insCodes));
    assert((insCodes[ins] != BAD_CODE));

    return insCodes[ins];
}

/*****************************************************************************
 *
 *  Returns the "AL/AX/EAX, imm" accumulator encoding of the given instruction.
 */

inline size_t insCodeACC(instruction ins)
{
    // clang-format off
    const static uint32_t insCodesACC[] =
    {
        #define INST0(id, nm, um, mr,                 lat, tp, tt, flags)
        #define INST1(id, nm, um, mr,                 lat, tp, tt, flags)
        #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags)
        #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags)
        #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) a4,
        #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) a4,
        #include "instrs.h"
        #undef  INST0
        #undef  INST1
        #undef  INST2
        #undef  INST3
        #undef  INST4
        #undef  INST5
    };
    // clang-format on

    assert((unsigned)ins < ArrLen(insCodesACC));
    assert((insCodesACC[ins] != BAD_CODE));

    return insCodesACC[ins];
}

/*****************************************************************************
 *
 *  Returns the "register" encoding of the given CPU instruction.
 */

inline size_t insCodeRR(instruction ins)
{
    // clang-format off
    const static uint32_t insCodesRR[] =
    {
        #define INST0(id, nm, um, mr,                 lat, tp, tt, flags)
        #define INST1(id, nm, um, mr,                 lat, tp, tt, flags)
        #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags)
        #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags)
        #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags)
        #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) rr,
        #include "instrs.h"
        #undef  INST0
        #undef  INST1
        #undef  INST2
        #undef  INST3
        #undef  INST4
        #undef  INST5
    };
    // clang-format on

    assert((unsigned)ins < ArrLen(insCodesRR));
    assert((insCodesRR[ins] != BAD_CODE));

    return insCodesRR[ins];
}

// clang-format off
const static size_t insCodesRM[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags)
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags)
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags)
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) rm,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) rm,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) rm,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

// Returns true iff the give CPU instruction has an RM encoding.
inline bool hasCodeRM(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesRM));
    return ((insCodesRM[ins] != BAD_CODE));
}

/*****************************************************************************
 *
 *  Returns the "reg, [r/m]" encoding of the given CPU instruction.
 */

inline size_t insCodeRM(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesRM));
    assert((insCodesRM[ins] != BAD_CODE));

    return insCodesRM[ins];
}

// clang-format off
const static size_t insCodesMI[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags)
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags)
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) mi,
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) mi,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) mi,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) mi,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

// Returns true iff the give CPU instruction has an MI encoding.
inline bool hasCodeMI(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesMI));
    return ((insCodesMI[ins] != BAD_CODE));
}

/*****************************************************************************
 *
 *  Returns the "[r/m], 32-bit icon" encoding of the given CPU instruction.
 */

inline size_t insCodeMI(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesMI));
    assert((insCodesMI[ins] != BAD_CODE));

    return insCodesMI[ins];
}

// clang-format off
const static uint32_t insCodesMR[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags)
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) mr,
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) mr,
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) mr,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) mr,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) mr,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

// Returns true iff the give CPU instruction has an MR encoding.
inline bool hasCodeMR(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesMR));
    return ((insCodesMR[ins] != BAD_CODE));
}

//------------------------------------------------------------------------
// emitGetVexPrefixSize: Gets size of VEX prefix in bytes
//
// Arguments:
//    id   -- The instruction descriptor
//
// Returns:
//    Prefix size in bytes.
//
unsigned emitter::emitGetVexPrefixSize(instrDesc* id) const
{
    instruction ins = id->idIns();
    assert(IsVexEncodableInstruction(ins));

    if (EncodedBySSE38orSSE3A(ins))
    {
        // When the prefix is 0x0F38 or 0x0F3A, we must use the 3-byte encoding
        return 3;
    }

    switch (ins)
    {
        case INS_crc32:
        case INS_sarx:
        case INS_shrx:
        {
            // When the prefix is 0x0F38 or 0x0F3A, we must use the 3-byte encoding
            // These are special cases where the pp-bit is 0xF2 or 0xF3 and not 0x66
            return 3;
        }

        default:
        {
            break;
        }
    }

    emitAttr size = id->idOpSize();

    if (TakesRexWPrefix(id))
    {
        // When the REX.W bit is present, we must use the 3-byte encoding
        return 3;
    }

    regNumber regFor012Bits;

    if (id->idHasMemAdr())
    {
        regNumber regForSibBits = id->idAddr()->iiaAddrMode.amIndxReg;

        if (IsExtendedReg(regForSibBits))
        {
            // When the REX.X bit is present, we must use the 3-byte encoding
            // - REX.X is used to encode the extended index field for SIB addressing
            return 3;
        }

        regFor012Bits = id->idAddr()->iiaAddrMode.amBaseReg;
    }
    else if (id->idHasMemGen() || id->idHasMemStk())
    {
        // Nothing is encoded in a way to prevent the 2-byte encoding
        // - We don't encode an index or base field so can't use REX.X or REX.B
        return 2;
    }
    else if (id->idHasReg3())
    {
        // All instructions which have 3 registers encode reg3 in the r/m byte
        regFor012Bits = id->idReg3();
    }
    else if (id->idHasReg2())
    {
        // Most instructions which have 2 registers encode reg2 in the r/m byte
        regFor012Bits = id->idReg2();

        // However, there are a couple with MR variants (such as the extract instructions)
        // and movd which uses both float and general registers which may use op1
        ID_OPS idOp = static_cast<ID_OPS>(emitFmtToOps[id->idInsFmt()]);

        if (idOp == ID_OP_SCNS)
        {
            if (hasCodeMR(ins))
            {
                regFor012Bits = id->idReg1();
            }
        }
        else if ((ins == INS_movd32) || (ins == INS_movd64))
        {
            if (isFloatReg(regFor012Bits))
            {
                regFor012Bits = id->idReg1();
            }
        }
    }
    else
    {
        assert(id->idHasReg1());
        regFor012Bits = id->idReg1();
    }

    if (IsExtendedReg(regFor012Bits))
    {
        // When the REX.B bit is present, we must use the 3-byte encoding
        return 3;
    }

    return 2;
}

/*****************************************************************************
 *
 *  Returns the "[r/m], reg" or "[r/m]" encoding of the given CPU instruction.
 */

inline size_t insCodeMR(instruction ins)
{
    assert((unsigned)ins < ArrLen(insCodesMR));
    assert((insCodesMR[ins] != BAD_CODE));

    return insCodesMR[ins];
}

// clang-format off
const static insTupleType insTupleTypeInfos[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) static_cast<insTupleType>(tt),
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

//------------------------------------------------------------------------
// hasTupleTypeInfo: Checks if the instruction has tuple type info.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    true if this instruction has tuple type info.
//
inline bool hasTupleTypeInfo(instruction ins)
{
    assert((unsigned)ins < ArrLen(insTupleTypeInfos));
    return (insTupleTypeInfos[ins] != INS_TT_NONE);
}

//------------------------------------------------------------------------
// insTupleTypeInfo: Returns the tuple type info for a given CPU instruction.
//
// Arguments:
//    instruction -- processor instruction to check
//
// Return Value:
//    the tuple type info for a given CPU instruction.
//
insTupleType emitter::insTupleTypeInfo(instruction ins)
{
    assert((unsigned)ins < ArrLen(insTupleTypeInfos));
    return insTupleTypeInfos[ins];
}

// Return true if the instruction uses the SSE38 or SSE3A macro in instrsXArch.h.
bool emitter::EncodedBySSE38orSSE3A(instruction ins) const
{
    const size_t SSE38 = 0x0F000038;
    const size_t SSE3A = 0x0F00003A;
    const size_t MASK  = 0xFF0000FF;

    size_t insCode = 0;

    if (!IsSimdInstruction(ins))
    {
        return false;
    }

    if (hasCodeRM(ins))
    {
        insCode = insCodeRM(ins);
    }
    else if (hasCodeMI(ins))
    {
        insCode = insCodeMI(ins);
    }
    else if (hasCodeMR(ins))
    {
        insCode = insCodeMR(ins);
    }

    size_t mskCode = insCode & MASK;

    if ((mskCode != SSE38) && (mskCode != SSE3A))
    {
        return false;
    }

#if defined(DEBUG)
    insCode = (insCode >> 16) & 0xFF;
    assert((insCode == 0x00) || (insCode == 0x66) || (insCode == 0xF2) || (insCode == 0xF3));
#endif // DEBUG

    return true;
}

/*****************************************************************************
 *
 *  Returns an encoding for the specified register to be used in the bit0-2
 *  part of an opcode.
 */

inline unsigned emitter::insEncodeReg012(const instrDesc* id, regNumber reg, emitAttr size, code_t* code)
{
    assert(reg < REG_STK);

    instruction ins = id->idIns();

#ifdef TARGET_AMD64
    // Either code is not NULL or reg is not an extended reg.
    // If reg is an extended reg, instruction needs to be prefixed with 'REX'
    // which would require code != NULL.
    assert(code != nullptr || !IsExtendedReg(reg));

    if (IsExtendedReg(reg))
    {
        if (isHighSimdReg(reg))
        {
            *code = AddRexXPrefix(id, *code); // EVEX.X
        }
        if (AbsRegNumber(reg) & 0x8)
        {
            *code = AddRexBPrefix(id, *code); // REX.B
        }
        if (IsExtendedGPReg(reg))
        {
            // Seperate the encoding for REX2.B3/B4, REX2.B3 will be handled in `AddRexBPrefix`.
            assert(TakesRex2Prefix(id) || TakesApxExtendedEvexPrefix(id) || TakesEvexPrefix(id));
            if (hasRex2Prefix(*code))
            {
                *code |= 0x001000000000ULL; // REX2.B4
            }
            else if (hasEvexPrefix(*code))
            {
                *code |= 0x8000000000000ULL; // EVEX.B4
            }
            else
            {
                // There are cases when this method is called before prefix is attached.
            }
        }
    }
    else if ((EA_SIZE(size) == EA_1BYTE) && (reg > REG_RBX) && (code != nullptr))
    {
        // We are assuming that we only use/encode SPL, BPL, SIL and DIL
        // not the corresponding AH, CH, DH, or BH
        *code = (hasRex2Prefix(*code) || hasEvexPrefix(*code)) ? *code : AddRexPrefix(ins, *code); // REX
    }
#endif // TARGET_AMD64

    unsigned regBits = RegEncoding(reg);

    assert(regBits < 8);
    return regBits;
}

/*****************************************************************************
 *
 *  Returns an encoding for the specified register to be used in the bit3-5
 *  part of an opcode.
 */

inline unsigned emitter::insEncodeReg345(const instrDesc* id, regNumber reg, emitAttr size, code_t* code)
{
    assert(reg < REG_STK);

    instruction ins = id->idIns();

#ifdef TARGET_AMD64
    // Either code is not NULL or reg is not an extended reg.
    // If reg is an extended reg, instruction needs to be prefixed with 'REX'
    // which would require code != NULL.
    assert(code != nullptr || !IsExtendedReg(reg));

    if (IsExtendedReg(reg))
    {
        if (isHighSimdReg(reg))
        {
            *code = AddEvexRPrimePrefix(*code); // EVEX.R'
        }
        if (AbsRegNumber(reg) & 0x8)
        {
            *code = AddRexRPrefix(id, *code); // REX.R
        }
        if (IsExtendedGPReg(reg))
        {
            // Seperate the encoding for REX2.R3/R4, REX2.R3 will be handled in `AddRexRPrefix`.
            assert(TakesRex2Prefix(id) || TakesApxExtendedEvexPrefix(id) || TakesEvexPrefix(id));
            if (hasRex2Prefix(*code))
            {
                *code |= 0x004000000000ULL; // REX2.R4
            }
            else if (hasEvexPrefix(*code))
            {
                *code = AddEvexRPrimePrefix(*code); // EVEX.R4
            }
            else
            {
                // There are cases when this method is called before prefix is attached.
            }
        }
    }
    else if ((EA_SIZE(size) == EA_1BYTE) && (reg > REG_RBX) && (code != nullptr))
    {
        // We are assuming that we only use/encode SPL, BPL, SIL and DIL
        // not the corresponding AH, CH, DH, or BH
        *code = (hasRex2Prefix(*code) || hasEvexPrefix(*code)) ? *code : AddRexPrefix(ins, *code); // REX
    }
#endif // TARGET_AMD64

    unsigned regBits = RegEncoding(reg);

    assert(regBits < 8);
    return (regBits << 3);
}

/***********************************************************************************
 *
 *  Returns modified SIMD opcode with the specified register encoded in bits 3-6 of
 *  byte 2 of VEX and EVEX prefix.
 */
inline emitter::code_t emitter::insEncodeReg3456(const instrDesc* id, regNumber reg, emitAttr size, code_t code)
{
    instruction ins = id->idIns();

    assert(reg < REG_STK);
    assert(IsVexOrEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));
    assert(hasVexOrEvexPrefix(code));

    // Get 4-bit register encoding
    // RegEncoding() gives lower 3 bits
    // IsExtendedReg() gives MSB.
    code_t regBits = RegEncoding(reg);
    if (IsExtendedReg(reg))
    {
        regBits |= 0x08;
    }

    // Both prefix encodes register operand in 1's complement form
    assert(regBits <= 0xF);

    if (IsVexOrEvexEncodableInstruction(ins))
    {
        if (TakesEvexPrefix(id) && codeEvexMigrationCheck(code)) // TODO-XArch-AVX512: Remove codeEvexMigrationCheck().
        {
            assert(hasEvexPrefix(code));

#if defined(TARGET_AMD64)
            // TODO-XARCH-AVX512 I don't like that we redefine regBits on the EVEX case.
            // Rather see these paths cleaned up.
            regBits = HighAwareRegEncoding(reg);

            if (isHighSimdReg(reg))
            {
                // Have to set the EVEX V' bit
                code = AddEvexVPrimePrefix(code);
            }

            if (isHighGPReg(reg) && IsBMIInstruction(ins))
            {
                // APX: BMI instructions use RVM operand encoding
                code = AddEvexVPrimePrefix(code);
            }
#endif

            // Shift count = 5-bytes of opcode + 0-2 bits for EVEX
            regBits <<= 43;
            return code ^ regBits;
        }
        else
        {
            assert(IsVexEncodableInstruction(ins));
            assert(hasVexPrefix(code));

            // Shift count = 4-bytes of opcode + 0-2 bits for VEX
            regBits <<= 35;
            return code ^ regBits;
        }
    }
    else
    {
        assert(TakesApxExtendedEvexPrefix(id));
        assert(hasEvexPrefix(code));
#if defined(TARGET_AMD64)
        // TODO-XARCH-AVX512 I don't like that we redefine regBits on the EVEX case.
        // Rather see these paths cleaned up.
        regBits = HighAwareRegEncoding(reg);

        if (isHighGPReg(reg))
        {
            // Have to set the EVEX V' bit
            code = AddEvexVPrimePrefix(code);
        }
#endif
        // Shift count = 5-bytes of opcode + 0-2 bits for EVEX
        regBits <<= 43;
        return code ^ regBits;
    }

    return code ^ regBits;
}

/*****************************************************************************
 *
 *  Returns an encoding for the specified register to be used in the bit3-5
 *  part of an SIB byte (unshifted).
 *  Used exclusively to generate the REX.X bit and truncate the register.
 */

inline unsigned emitter::insEncodeRegSIB(const instrDesc* id, regNumber reg, code_t* code)
{
    instruction ins = id->idIns();

    assert(reg < REG_STK);

#ifdef TARGET_AMD64
    // Either code is not NULL or reg is not an extended reg.
    // If reg is an extended reg, instruction needs to be prefixed with 'REX'
    // which would require code != NULL.
    assert(code != nullptr || reg < REG_R8 || (reg >= REG_XMM0 && reg < REG_XMM8));

    if (IsExtendedReg(reg))
    {
        if (isHighSimdReg(reg))
        {
            *code = AddEvexVPrimePrefix(*code); // EVEX.X
        }
        if (AbsRegNumber(reg) & 0x8)
        {
            *code = AddRexXPrefix(id, *code); // REX.X
        }
        if (IsExtendedGPReg(reg))
        {
            // Separate the encoding for REX2.X3/X4, REX2.X3 will be handled in `AddRexXPrefix`.
            assert(TakesRex2Prefix(id) || TakesApxExtendedEvexPrefix(id) || TakesEvexPrefix(id));
            if (hasRex2Prefix(*code))
            {
                *code |= 0x002000000000ULL; // REX2.X4
            }
            else if (hasEvexPrefix(*code))
            {
                // Note that APX-EVEX use EVEX.X4 as the MSB of the INDEX register to address GPRs, and the original
                // EVEX.V4 is used for VSIB addressing.
                *code &= 0xFFFFFBFFFFFFFFFFULL; // EVEX.X4
            }
            else
            {
                // There are cases when this method is called before prefix is attached.
            }
        }
    }
    unsigned regBits = RegEncoding(reg);
#else  // !TARGET_AMD64
    unsigned regBits = reg;
#endif // !TARGET_AMD64

    assert(regBits < 8);
    return regBits;
}

/*****************************************************************************
 *
 *  Returns the "[r/m]" opcode with the mod/RM field set to register.
 */

inline emitter::code_t emitter::insEncodeMRreg(const instrDesc* id, code_t code)
{
    // If Byte 4 (which is 0xFF00) is 0, that's where the RM encoding goes.
    // Otherwise, it will be placed after the 4 byte encoding.
    if ((code & 0xFF00) == 0)
    {
        assert((code & 0xC000) == 0);
        code |= 0xC000;
    }

    return code;
}

/*****************************************************************************
 *
 *  Returns the given "[r/m]" opcode with the mod/RM field set to register.
 */

inline emitter::code_t emitter::insEncodeRMreg(const instrDesc* id, code_t code)
{
    // If Byte 4 (which is 0xFF00) is 0, that's where the RM encoding goes.
    // Otherwise, it will be placed after the 4 byte encoding.
    if ((code & 0xFF00) == 0)
    {
        assert((code & 0xC000) == 0);
        code |= 0xC000;
    }
    return code;
}

/*****************************************************************************
 *
 *  Returns the "byte ptr [r/m]" opcode with the mod/RM field set to
 *  the given register.
 */

inline emitter::code_t emitter::insEncodeMRreg(const instrDesc* id, regNumber reg, emitAttr size, code_t code)
{
    assert((code & 0xC000) == 0);
    code |= 0xC000;
    unsigned regcode = insEncodeReg012(id, reg, size, &code) << 8;
    code |= regcode;
    return code;
}

/*****************************************************************************
 *
 *  Returns the "byte ptr [r/m], icon" opcode with the mod/RM field set to
 *  the given register.
 */

inline emitter::code_t emitter::insEncodeMIreg(const instrDesc* id, regNumber reg, emitAttr size, code_t code)
{
    assert((code & 0xC000) == 0);
    code |= 0xC000;
    unsigned regcode = insEncodeReg012(id, reg, size, &code) << 8;
    code |= regcode;
    return code;
}

/*****************************************************************************
 *
 *  Returns true iff the given instruction does not have a "[r/m], icon" form, but *does* have a
 *  "reg,reg,imm8" form.
 */
inline bool insNeedsRRIb(instruction ins)
{
    // If this list gets longer, use a switch or a table.
    return ins == INS_imul;
}

/*****************************************************************************
 *
 *  Returns the "reg,reg,imm8" opcode with both the reg's set to the
 *  the given register.
 */
inline emitter::code_t emitter::insEncodeRRIb(const instrDesc* id, regNumber reg, emitAttr size)
{
    assert(size == EA_4BYTE); // All we handle for now.
    assert(insNeedsRRIb(id->idIns()));
    // If this list gets longer, use a switch, or a table lookup.
    code_t   code    = 0x69c0;
    unsigned regcode = insEncodeReg012(id, reg, size, &code);
    // We use the same register as source and destination.  (Could have another version that does both regs...)
    code |= regcode;
    code |= (regcode << 3);
    return code;
}

/*****************************************************************************
 *
 *  Returns the "+reg" opcode with the given register set into the low
 *  nibble of the opcode
 */

inline emitter::code_t emitter::insEncodeOpreg(const instrDesc* id, regNumber reg, emitAttr size)
{
    code_t   code    = insCodeRR(id->idIns());
    unsigned regcode = insEncodeReg012(id, reg, size, &code);
    code |= regcode;
    return code;
}

/*****************************************************************************
 *
 *  Return the 'SS' field value for the given index scale factor.
 */

inline unsigned emitter::insSSval(unsigned scale)
{
    assert(scale == 1 || scale == 2 || scale == 4 || scale == 8);

    const static BYTE scales[] = {
        0x00, // 1
        0x40, // 2
        0xFF, // 3
        0x80, // 4
        0xFF, // 5
        0xFF, // 6
        0xFF, // 7
        0xC0, // 8
    };

    return scales[scale - 1];
}

const instruction emitJumpKindInstructions[] = {INS_nop,

#define JMP_SMALL(en, rev, ins) INS_##ins,
#include "emitjmps.h"

                                                INS_call};

const emitJumpKind emitReverseJumpKinds[] = {
    EJ_NONE,

#define JMP_SMALL(en, rev, ins) EJ_##rev,
#include "emitjmps.h"
};

/*****************************************************************************
 * Look up the instruction for a jump kind
 */

/*static*/ instruction emitter::emitJumpKindToIns(emitJumpKind jumpKind)
{
    assert((unsigned)jumpKind < ArrLen(emitJumpKindInstructions));
    return emitJumpKindInstructions[jumpKind];
}

/*****************************************************************************
 * Reverse the conditional jump
 */

/* static */ emitJumpKind emitter::emitReverseJumpKind(emitJumpKind jumpKind)
{
    assert(jumpKind < EJ_COUNT);
    return emitReverseJumpKinds[jumpKind];
}

//------------------------------------------------------------------------
// emitAlignInstHasNoCode: Returns true if the 'id' is an align instruction
//      that was later removed and hence has codeSize==0.
//
// Arguments:
//    id   -- The instruction to check
//
/* static */ bool emitter::emitAlignInstHasNoCode(instrDesc* id)
{
    return (id->idIns() == INS_align) && (id->idCodeSize() == 0);
}

//------------------------------------------------------------------------
// emitJmpInstHasNoCode: Returns true if the 'id' is a jump instruction
//      that was later removed and hence has codeSize==0.
//
// Arguments:
//    id   -- The instruction to check
//
/* static */ bool emitter::emitJmpInstHasNoCode(instrDesc* id)
{
    bool result = (id->idIns() == INS_jmp) && ((instrDescJmp*)id)->idjIsRemovableJmpCandidate;

// A jump marked for removal must have a code size of 0,
// except for jumps that must be replaced by nops on AMD64 (these must have a size of 1)
#ifdef TARGET_AMD64
    const bool isNopReplacement = ((instrDescJmp*)id)->idjIsAfterCallBeforeEpilog && (id->idCodeSize() == 1);
    assert(!result || (id->idCodeSize() == 0) || isNopReplacement);
#else  // !TARGET_AMD64
    assert(!result || (id->idCodeSize() == 0));
#endif // !TARGET_AMD64

    return result;
}

//------------------------------------------------------------------------
// emitInstHasNoCode: Returns true if the 'id' is an instruction
//      that was later removed and hence has codeSize==0.
//      Currently it is one of `align` or `jmp`.
//
// Arguments:
//    id   -- The instruction to check
//
/* static */ bool emitter::emitInstHasNoCode(instrDesc* id)
{
    return emitAlignInstHasNoCode(id) || emitJmpInstHasNoCode(id);
}

/*****************************************************************************
 * When encoding instructions that operate on byte registers
 * we have to ensure that we use a low register (EAX, EBX, ECX or EDX)
 * otherwise we will incorrectly encode the instruction
 */

bool emitter::emitVerifyEncodable(instruction ins, emitAttr size, regNumber reg1, regNumber reg2 /* = REG_NA */)
{
#if CPU_HAS_BYTE_REGS
    if (size != EA_1BYTE) // Not operating on a byte register is fine
    {
        return true;
    }

    if ((ins != INS_movsx) && // These three instructions support high register
        (ins != INS_movzx)    // encodings for reg1
#ifdef FEATURE_HW_INTRINSICS
        && (ins != INS_crc32)
#endif
    )
    {
        // reg1 must be a byte-able register
        if ((genRegMask(reg1) & RBM_BYTE_REGS) == 0)
        {
            return false;
        }
    }
    // if reg2 is not REG_NA then reg2 must be a byte-able register
    if ((reg2 != REG_NA) && ((genRegMask(reg2) & RBM_BYTE_REGS) == 0))
    {
        return false;
    }
#endif
    // The instruction can be encoded
    return true;
}

//------------------------------------------------------------------------
// emitInsSize: Estimate the size (in bytes of generated code) of the given instruction.
//
// Arguments:
//    id    -- The instruction descriptor for which to estimate its size
//    code  -- The current opcode and any known prefixes
//    includeRexPrefixSize  -- If Rex Prefix size should be included or not
//
inline UNATIVE_OFFSET emitter::emitInsSize(instrDesc* id, code_t code, bool includeRexPrefixSize)
{
    UNATIVE_OFFSET size = (code & 0xFF000000) ? 4 : (code & 0x00FF0000) ? 3 : 2;
#ifdef TARGET_AMD64
    size += emitGetPrefixSize(id, code, includeRexPrefixSize);
#endif
    return size;
}

//------------------------------------------------------------------------
// emitInsSizeRR: Determines the code size for an instruction encoding that does not have any addressing modes
//
// Arguments:
//    ins   -- The instruction being emitted
//    code  -- The current opcode and any known prefixes
inline UNATIVE_OFFSET emitter::emitInsSizeRR(instrDesc* id, code_t code)
{
    assert(id->idIns() != INS_invalid);

    instruction ins  = id->idIns();
    emitAttr    attr = id->idOpSize();

    UNATIVE_OFFSET sz = emitGetAdjustedSize(id, code);

    bool includeRexPrefixSize = true;
    // REX prefix
    if (TakesRexWPrefix(id) || IsExtendedReg(id->idReg1(), attr) || IsExtendedReg(id->idReg2(), attr) ||
        (!id->idIsSmallDsc() && (IsExtendedReg(id->idReg3(), attr) || IsExtendedReg(id->idReg4(), attr))))
    {
        sz += emitGetRexPrefixSize(id, ins);
        includeRexPrefixSize = !IsVexEncodableInstruction(ins);
    }

    sz += emitInsSize(id, code, includeRexPrefixSize);

    return sz;
}

//------------------------------------------------------------------------
// emitInsSizeRR: Determines the code size for an instruction encoding that does not have any addressing modes and
// includes an immediate value
//
// Arguments:
//    ins   -- The instruction being emitted
//    code  -- The current opcode and any known prefixes
//    val   -- The immediate value to encode
inline UNATIVE_OFFSET emitter::emitInsSizeRR(instrDesc* id, code_t code, int val)
{
    instruction    ins       = id->idIns();
    UNATIVE_OFFSET valSize   = EA_SIZE_IN_BYTES(id->idOpSize());
    bool           valInByte = ((signed char)val == val) && (ins != INS_mov) && (ins != INS_test);

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(valSize <= sizeof(INT32) || !id->idIsCnsReloc());
#endif // TARGET_AMD64

    if (valSize > sizeof(INT32))
    {
        valSize = sizeof(INT32);
    }

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte
        assert(valSize == sizeof(INT32));
    }

    if (valInByte)
    {
        valSize = sizeof(char);
    }
    else
    {
        assert(!IsSimdInstruction(ins));
    }

    return valSize + emitInsSizeRR(id, code);
}

//------------------------------------------------------------------------
// emitInsSizeRR: Determines the code size for an instruction encoding that does not have any addressing modes
//
// Arguments:
//    id    -- The instruction descriptor being emitted
//
// TODO-Cleanup: This method should really be merged with emitInsSizeRR(instrDesc*, code_t). However, it has
// existed for a long time and its not trivial to determine why it exists as a separate method.
//
inline UNATIVE_OFFSET emitter::emitInsSizeRR(instrDesc* id)
{
    instruction ins = id->idIns();

    // If Byte 4 (which is 0xFF00) is zero, that's where the RM encoding goes.
    // Otherwise, it will be placed after the 4 byte encoding, making the total 5 bytes.
    // This would probably be better expressed as a different format or something?
    code_t code = 0;

    if (hasCodeRM(ins))
    {
        code = insCodeRM(ins);
    }
    else
    {
        code = insCodeMR(ins);
    }

    if (IsKInstruction(ins))
    {
        code = AddVexPrefix(ins, code, EA_SIZE(id->idOpSize()));
    }

    UNATIVE_OFFSET sz = emitGetAdjustedSize(id, code);

    bool includeRexPrefixSize = true;
    // REX prefix
    if (!hasRexPrefix(code))
    {
        regNumber reg1 = id->idReg1();
        regNumber reg2 = id->idReg2();
        emitAttr  attr = id->idOpSize();
        emitAttr  size = EA_SIZE(attr);

        if ((TakesRexWPrefix(id) && ((ins != INS_xor) || (reg1 != reg2))) || IsExtendedReg(reg1, attr) ||
            IsExtendedReg(reg2, attr))
        {
            sz += emitGetRexPrefixSize(id, ins);
            includeRexPrefixSize = false;
        }
    }

    if ((code & 0xFF00) != 0)
    {
        sz += (IsSimdInstruction(ins) || TakesApxExtendedEvexPrefix(id)) ? emitInsSize(id, code, includeRexPrefixSize)
                                                                         : 5;
    }
    else
    {
        sz += emitInsSize(id, insEncodeRMreg(id, code), includeRexPrefixSize);
    }

    return sz;
}

//------------------------------------------------------------------------
// emitInsSizeSVCalcDisp: Calculate instruction size.
//
// Arguments:
//    id -- Instruction descriptor.
//    code -- The current opcode and any known prefixes
//    var - Stack variable
//    dsp -- Displacemnt.
//
// Return Value:
//    Estimated instruction size.
//
inline UNATIVE_OFFSET emitter::emitInsSizeSVCalcDisp(instrDesc* id, code_t code, int var, int dsp)
{
    instruction    ins  = id->idIns();
    UNATIVE_OFFSET size = emitInsSize(id, code, /* includeRexPrefixSize */ true);

    int  adr;
    bool EBPbased;
    bool dspInByte;
    bool dspIsZero;

    adr = emitComp->lvaFrameAddress(var, &EBPbased);
    dsp = adr + id->idAddr()->iiaLclVar.lvaOffset();

    dspIsZero = (dsp == 0);

    bool tryCompress = true;

    if (EBPbased)
    {
        // EBP always requires a displacement
        dspIsZero = false;
    }
    else
    {
        // An address off of ESP takes an extra byte
        size++;

#if !FEATURE_FIXED_OUT_ARGS
        // Adjust the offset by the amount currently pushed on the CPU stack
        dsp += emitCurStackLvl;

        // At this point, the amount pushed onto the stack is an estimate and
        // so we cannot reliably predict if it will be zero or if compression
        // can occur. So we'll pessimize to not compressing and not using zero
        // displacement here, potentially resulting in over-allocation of bytes
        tryCompress = false;
        dspIsZero   = false;
#endif // !FEATURE_FIXED_OUT_ARGS
    }

    if (IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
    {
        if (tryCompress)
        {
            ssize_t compressedDsp;

            // Only the scaling factor of the original EVEX instructions can be changed by embedded broadcast.
            // If the instruction does not have tuple type info, say extended EVEX from APX, the scaling factor is
            // constantly 1, then this optimization cannot be performed, and whether disp8 or disp32 should be applied
            // only depends dspInByte.
            if (TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte) && hasTupleTypeInfo(ins))
            {
                SetEvexCompressedDisplacement(id);
            }
        }
        else if (TakesEvexPrefix(id))
        {
            // EVEX requires compressed displacement to fit in a byte
            dspInByte = false;
        }
        else
        {
            dspInByte = ((signed char)dsp == (ssize_t)dsp);
        }
    }
    else
    {
        dspInByte = ((signed char)dsp == (ssize_t)dsp);
    }

    if (dspIsZero)
    {
        return size;
    }
    else if (dspInByte)
    {
        return size + sizeof(char);
    }
    else
    {
        return size + sizeof(int);
    }
}

inline UNATIVE_OFFSET emitter::emitInsSizeSV(instrDesc* id, code_t code, int var, int dsp)
{
    assert(id->idIns() != INS_invalid);
    instruction    ins      = id->idIns();
    emitAttr       attrSize = id->idOpSize();
    UNATIVE_OFFSET size     = emitInsSizeSVCalcDisp(id, code, var, dsp);

    size += emitGetAdjustedSize(id, code);

    // REX prefix
    if (TakesRexWPrefix(id) || IsExtendedReg(id->idReg1(), attrSize) || IsExtendedReg(id->idReg2(), attrSize))
    {
        size += emitGetRexPrefixSize(id, ins);
    }

    return size;
}

inline UNATIVE_OFFSET emitter::emitInsSizeSV(instrDesc* id, code_t code, int var, int dsp, int val)
{
    assert(id->idIns() != INS_invalid);
    instruction    ins       = id->idIns();
    UNATIVE_OFFSET valSize   = EA_SIZE_IN_BYTES(id->idOpSize());
    bool           valInByte = ((signed char)val == val) && (ins != INS_mov) && (ins != INS_test);

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(valSize <= sizeof(int) || !id->idIsCnsReloc());
#endif // TARGET_AMD64

    if (valSize > sizeof(int))
    {
        valSize = sizeof(int);
    }

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte
        assert(valSize == sizeof(int));
    }

    if (valInByte)
    {
        valSize = sizeof(char);
    }
    else
    {
        assert(!IsSSEOrAVXInstruction(ins));
    }

    return valSize + emitInsSizeSV(id, code, var, dsp);
}

/*****************************************************************************/

static bool baseRegisterRequiresSibByte(regNumber base)
{
#ifdef TARGET_AMD64
    return base == REG_ESP || base == REG_R12 || base == REG_R20 || base == REG_R28;
#else
    return base == REG_ESP;
#endif
}

static bool baseRegisterRequiresDisplacement(regNumber base)
{
#ifdef TARGET_AMD64
    return base == REG_EBP || base == REG_R13 || base == REG_R21 || base == REG_R29;
#else
    return base == REG_EBP;
#endif
}

UNATIVE_OFFSET emitter::emitInsSizeAM(instrDesc* id, code_t code)
{
    assert(id->idIns() != INS_invalid);
    instruction ins      = id->idIns();
    emitAttr    attrSize = id->idOpSize();
    /* The displacement field is in an unusual place for (tail-)calls */
    ssize_t        dsp = (ins == INS_call) || (ins == INS_tail_i_jmp) ? emitGetInsCIdisp(id) : emitGetInsAmdAny(id);
    bool           dspInByte = ((signed char)dsp == (ssize_t)dsp);
    bool           dspIsZero = (dsp == 0);
    UNATIVE_OFFSET size;

    // Note that the values in reg and rgx are used in this method to decide
    // how many bytes will be needed by the address [reg+rgx+cns]
    // this includes the prefix bytes when reg or rgx are registers R8-R15
    regNumber reg;
    regNumber rgx;

    // The idAddr field is a union and only some of the instruction formats use the iiaAddrMode variant
    // these are IF_ARD_*, IF_ARW_*, and IF_AWR_*
    // ideally these should really be the only idInsFmts that we see here
    //  but we have some outliers to deal with:
    //     emitIns_R_L adds IF_RWR_LABEL and calls emitInsSizeAM
    //     emitInsRMW adds IF_MRW_CNS, IF_MRW_RRD, IF_MRW_SHF, and calls emitInsSizeAM

    if (id->idHasMemAdr())
    {
        reg = id->idAddr()->iiaAddrMode.amBaseReg;
        rgx = id->idAddr()->iiaAddrMode.amIndxReg;
    }
    else
    {
        reg = REG_NA;
        rgx = REG_NA;

#if defined(DEBUG)
        switch (id->idInsFmt())
        {
            case IF_RWR_LABEL:
            case IF_MRW_CNS:
            case IF_MRW_RRD:
            case IF_MRW_SHF:
            {
                break;
            }

            default:
            {
                assert(!"Unexpected insFormat in emitInsSizeAMD");
                reg = id->idAddr()->iiaAddrMode.amBaseReg;
                rgx = id->idAddr()->iiaAddrMode.amIndxReg;
                break;
            }
        }
#endif // DEBUG
    }

    if (id->idIsDspReloc())
    {
        dspInByte = false; // relocs can't be placed in a byte
        dspIsZero = false; // relocs won't always be zero
    }
    else if (IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
    {
        ssize_t compressedDsp;

        if (TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte) && hasTupleTypeInfo(ins))
        {
            SetEvexCompressedDisplacement(id);
        }
    }

    if (code & 0xFF000000)
    {
        size = 4;
    }
    else if (code & 0x00FF0000)
    {
        // BT supports 16 bit operands and this code doesn't handle the necessary 66 prefix.
        assert(ins != INS_bt);

        assert((attrSize == EA_4BYTE) || (attrSize == EA_PTRSIZE)                               // Only for x64
               || (attrSize == EA_16BYTE) || (attrSize == EA_32BYTE) || (attrSize == EA_64BYTE) // only for x64
               || (ins == INS_movzx) || (ins == INS_movsx) ||
               (ins == INS_cmpxchg)
               // The prefetch instructions are always 3 bytes and have part of their modr/m byte hardcoded
               || isPrefetch(ins));

        size = (attrSize == EA_2BYTE) && (ins == INS_cmpxchg) ? 4 : 3;
    }
    else
    {
        size = 2;
    }

    size += emitGetAdjustedSize(id, code);

    if (hasRexPrefix(code))
    {
        // REX prefix
        size += emitGetRexPrefixSize(id, ins);
    }
    else if (TakesRexWPrefix(id))
    {
        // REX.W prefix
        size += emitGetRexPrefixSize(id, ins);
    }
    else if (IsExtendedReg(reg, EA_PTRSIZE) || IsExtendedReg(rgx, EA_PTRSIZE) ||
             ((ins != INS_call) && (IsExtendedReg(id->idReg1(), attrSize) || IsExtendedReg(id->idReg2(), attrSize))))
    {
        // Should have a REX byte
        size += emitGetRexPrefixSize(id, ins);
    }

    if (rgx == REG_NA)
    {
        /* The address is of the form "[reg+disp]" */

        if (reg == REG_NA)
        {
            /* The address is of the form "[disp]" */

#ifdef TARGET_X86
            // Special case: "mov eax, [disp]" and "mov [disp], eax" can use a smaller 1-byte encoding.
            if ((ins == INS_mov) && (id->idReg1() == REG_EAX) &&
                ((id->idInsFmt() == IF_RWR_ARD) || (id->idInsFmt() == IF_AWR_RRD)))
            {
                // Amd64: this is one case where addr can be 64-bit in size. This is currently unused.
                // If this ever changes, this code will need to be updated to add "sizeof(INT64)" to "size".
                assert((size == 2) || ((size == 3) && (id->idOpSize() == EA_2BYTE)));
                size--;
            }
#endif

            size += sizeof(INT32);

#ifdef TARGET_AMD64
            // If id is not marked for reloc, add 1 additional byte for SIB that follows disp32
            if (!id->idIsDspReloc())
            {
                size++;
            }
#endif
            return size;
        }

        // If this is just "call reg", we're done.
        if (((ins == INS_call) || (ins == INS_tail_i_jmp)) && id->idIsCallRegPtr())
        {
            assert(dsp == 0);
            return size;
        }

        // If the base register is ESP (or R12 on 64-bit systems), a SIB byte must be used.
        if (baseRegisterRequiresSibByte(reg))
        {
            size++;
        }

        // If the base register is EBP (or R13 on 64-bit systems), a displacement is required.
        // Otherwise, the displacement can be elided if it is zero.
        if (dspIsZero && !baseRegisterRequiresDisplacement(reg))
        {
            return size;
        }

        /* Does the offset fit in a byte? */

        if (dspInByte)
        {
            size += sizeof(char);
        }
        else
        {
            size += sizeof(INT32);
        }
    }
    else
    {
        /* An index register is present */

        size++;

        /* Is the index value scaled? */

        if (emitDecodeScale(id->idAddr()->iiaAddrMode.amScale) > 1)
        {
            /* Is there a base register? */

            if (reg != REG_NA)
            {
                /* The address is "[reg + {2/4/8} * rgx + icon]" */

                if (dspIsZero && !baseRegisterRequiresDisplacement(reg))
                {
                    /* The address is "[reg + {2/4/8} * rgx]" */
                }
                else
                {
                    /* The address is "[reg + {2/4/8} * rgx + disp]" */

                    if (dspInByte)
                    {
                        size += sizeof(char);
                    }
                    else
                    {
                        size += sizeof(int);
                    }
                }
            }
            else
            {
                /* The address is "[{2/4/8} * rgx + icon]" */

                size += sizeof(INT32);
            }
        }
        else
        {
            // When we are using the SIB or VSIB format with EBP or R13 as a base, we must emit at least
            // a 1 byte displacement (this is a special case in the encoding to allow for the case of no
            // base register at all). In order to avoid this when we have no scaling, we can reverse the
            // registers so that we don't have to add that extra byte. However, we can't do that if the
            // index register is a vector, such as for a gather instruction.
            //
            if (dspIsZero && baseRegisterRequiresDisplacement(reg) && !baseRegisterRequiresDisplacement(rgx) &&
                !isFloatReg(rgx))
            {
                // Swap reg and rgx, such that reg is not EBP/R13.
                regNumber tmp                       = reg;
                id->idAddr()->iiaAddrMode.amBaseReg = reg = rgx;
                id->idAddr()->iiaAddrMode.amIndxReg = rgx = tmp;
            }

            /* The address is "[reg+rgx+dsp]" */

            if (dspIsZero && !baseRegisterRequiresDisplacement(reg))
            {
                /* This is [reg+rgx]" */
            }
            else
            {
                /* This is [reg+rgx+dsp]" */

                if (dspInByte)
                {
                    size += sizeof(char);
                }
                else
                {
                    size += sizeof(int);
                }
            }
        }
    }

    return size;
}

inline UNATIVE_OFFSET emitter::emitInsSizeAM(instrDesc* id, code_t code, int val)
{
    assert(id->idIns() != INS_invalid);
    instruction    ins       = id->idIns();
    UNATIVE_OFFSET valSize   = EA_SIZE_IN_BYTES(id->idOpSize());
    bool           valInByte = ((signed char)val == val) && (ins != INS_mov) && (ins != INS_test);

    // We should never generate BT mem,reg because it has poor performance. BT mem,imm might be useful
    // but it requires special handling of the immediate value (it is always encoded in a byte).
    // Let's not complicate things until this is needed.
    assert(ins != INS_bt);

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(valSize <= sizeof(INT32) || !id->idIsCnsReloc());
#endif // TARGET_AMD64

    if (valSize > sizeof(INT32))
    {
        valSize = sizeof(INT32);
    }

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte
        assert(valSize == sizeof(INT32));
    }

    if (valInByte)
    {
        valSize = sizeof(char);
    }
    else
    {
        assert(!IsSimdInstruction(ins));
    }

    return valSize + emitInsSizeAM(id, code);
}

inline UNATIVE_OFFSET emitter::emitInsSizeCV(instrDesc* id, code_t code)
{
    assert(id->idIns() != INS_invalid);
    instruction ins      = id->idIns();
    emitAttr    attrSize = id->idOpSize();

    // It is assumed that all addresses for the "M" format
    // can be reached via RIP-relative addressing.
    UNATIVE_OFFSET size = sizeof(INT32);

    size += emitGetAdjustedSize(id, code);

    bool includeRexPrefixSize = true;

    // 64-bit operand instructions will need a REX.W prefix
    if (TakesRexWPrefix(id) || IsExtendedReg(id->idReg1(), attrSize) || IsExtendedReg(id->idReg2(), attrSize))
    {
        size += emitGetRexPrefixSize(id, ins);
        includeRexPrefixSize = false;
    }

    return size + emitInsSize(id, code, includeRexPrefixSize);
}

inline UNATIVE_OFFSET emitter::emitInsSizeCV(instrDesc* id, code_t code, int val)
{
    instruction    ins       = id->idIns();
    UNATIVE_OFFSET valSize   = EA_SIZE_IN_BYTES(id->idOpSize());
    bool           valInByte = ((signed char)val == val) && (ins != INS_mov) && (ins != INS_test);

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(valSize <= sizeof(INT32) || !id->idIsCnsReloc());
#endif // TARGET_AMD64

    if (valSize > sizeof(INT32))
    {
        valSize = sizeof(INT32);
    }

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte
        assert(valSize == sizeof(INT32));
    }

    if (valInByte)
    {
        valSize = sizeof(char);
    }
    else
    {
        assert(!IsSimdInstruction(ins));
    }

    return valSize + emitInsSizeCV(id, code);
}

/*****************************************************************************
 *
 *  Allocate instruction descriptors for instructions with address modes.
 */

inline emitter::instrDesc* emitter::emitNewInstrAmd(emitAttr size, ssize_t dsp)
{
    if (dsp < AM_DISP_MIN || dsp > AM_DISP_MAX)
    {
        instrDescAmd* id = emitAllocInstrAmd(size);

        id->idSetIsLargeDsp();
#ifdef DEBUG
        id->idAddr()->iiaAddrMode.amDisp = AM_DISP_BIG_VAL;
#endif
        id->idaAmdVal = dsp;

        return id;
    }
    else
    {
        instrDesc* id = emitAllocInstr(size);

        id->idAddr()->iiaAddrMode.amDisp = dsp;
        assert(id->idAddr()->iiaAddrMode.amDisp == dsp); // make sure the value fit

        return id;
    }
}

/*****************************************************************************
 *
 *  Set the displacement field in an instruction. Only handles instrDescAmd type.
 */

inline void emitter::emitSetAmdDisp(instrDescAmd* id, ssize_t dsp)
{
    if (dsp < AM_DISP_MIN || dsp > AM_DISP_MAX)
    {
        id->idSetIsLargeDsp();
#ifdef DEBUG
        id->idAddr()->iiaAddrMode.amDisp = AM_DISP_BIG_VAL;
#endif
        id->idaAmdVal = dsp;
    }
    else
    {
        id->idSetIsSmallDsp();
        id->idAddr()->iiaAddrMode.amDisp = dsp;
        assert(id->idAddr()->iiaAddrMode.amDisp == dsp); // make sure the value fit
    }
}

/*****************************************************************************
 *
 *  Allocate an instruction descriptor for an instruction that uses both
 *  an address mode displacement and a constant.
 */

emitter::instrDesc* emitter::emitNewInstrAmdCns(emitAttr size, ssize_t dsp, int cns)
{
    if (dsp >= AM_DISP_MIN && dsp <= AM_DISP_MAX)
    {
        instrDesc* id                    = emitNewInstrCns(size, cns);
        id->idAddr()->iiaAddrMode.amDisp = dsp;
        assert(id->idAddr()->iiaAddrMode.amDisp == dsp); // make sure the value fit

        return id;
    }
    else
    {
        if (instrDesc::fitsInSmallCns(cns))
        {
            instrDescAmd* id = emitAllocInstrAmd(size);

            id->idSetIsLargeDsp();
#ifdef DEBUG
            id->idAddr()->iiaAddrMode.amDisp = AM_DISP_BIG_VAL;
#endif
            id->idaAmdVal = dsp;

            id->idSmallCns(cns);

            return id;
        }
        else
        {
            instrDescCnsAmd* id = emitAllocInstrCnsAmd(size);

            id->idSetIsLargeCns();
            id->idacCnsVal = cns;

            id->idSetIsLargeDsp();
#ifdef DEBUG
            id->idAddr()->iiaAddrMode.amDisp = AM_DISP_BIG_VAL;
#endif
            id->idacAmdVal = dsp;

            return id;
        }
    }
}

/*****************************************************************************
 *
 *  Add a data16 instruction of the 1 byte.
 */

void emitter::emitIns_Data16()
{
    instrDesc* id = emitNewInstrSmall(emitAttr::EA_1BYTE);
    id->idIns(INS_data16);
    id->idInsFmt(IF_NONE);
    id->idCodeSize(1);

    dispIns(id);
    emitCurIGsize += 1;
}

/*****************************************************************************
 *
 *  Add a NOP instruction of the given size.
 */

void emitter::emitIns_Nop(unsigned size)
{
    assert(size <= MAX_ENCODED_SIZE);

    instrDesc* id = emitNewInstr();
    id->idIns(INS_nop);
    id->idInsFmt(IF_NONE);
    id->idCodeSize(size);

    dispIns(id);
    emitCurIGsize += size;
}

/*****************************************************************************
 *
 *  Add an instruction with no operands.
 */
void emitter::emitIns(instruction ins)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id   = emitNewInstr();
    code_t         code = insCodeMR(ins);

#ifdef DEBUG
    {
        // We cannot have #ifdef inside macro expansion.
        bool assertCond =
            (ins == INS_cdq || ins == INS_int3 || ins == INS_lock || ins == INS_leave || ins == INS_movsb ||
             ins == INS_movsd || ins == INS_movsp || ins == INS_nop || ins == INS_r_movsb || ins == INS_r_movsd ||
             ins == INS_r_movsp || ins == INS_r_stosb || ins == INS_r_stosd || ins == INS_r_stosp || ins == INS_ret ||
             ins == INS_sahf || ins == INS_stosb || ins == INS_stosd ||
             ins == INS_stosp
             // These instructions take zero operands
             || ins == INS_vzeroupper || ins == INS_lfence || ins == INS_mfence || ins == INS_sfence ||
             ins == INS_pause || ins == INS_serialize);

        assert(assertCond);
    }
#endif // DEBUG

    assert(!hasRexPrefix(code)); // Can't have a REX bit with no operands, right?

    if (code & 0xFF000000)
    {
        sz = 2; // TODO-XArch-Bug?: Shouldn't this be 4? Or maybe we should assert that we don't see this case.
    }
    else if (code & 0x00FF0000)
    {
        sz = 3;
    }
    else if (code & 0x0000FF00)
    {
        sz = 2;
    }
    else
    {
        sz = 1;
    }

    // vzeroupper includes its 2-byte VEX prefix in its MR code.
    assert((ins != INS_vzeroupper) || (sz == 3));

    insFormat fmt = IF_NONE;

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

// Add an instruction with no operands, but whose encoding depends on the size
// (Only CDQ/CQO/CWDE/CDQE currently)
void emitter::emitIns(instruction ins, emitAttr attr)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id   = emitNewInstr(attr);
    code_t         code = insCodeMR(ins);
    assert((ins == INS_cdq) || (ins == INS_cwde));
    assert((code & 0xFFFFFF00) == 0);
    sz = 1;

    insFormat fmt = IF_NONE;

    id->idIns(ins);
    id->idInsFmt(fmt);

    sz += emitGetAdjustedSize(id, code);
    if (TakesRexWPrefix(id))
    {
        sz += emitGetRexPrefixSize(id, ins);
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitMapFmtForIns: map the instruction format based on the instruction.
// Shift-by-a-constant instructions have a special format.
//
// Arguments:
//    fmt - the instruction format to map
//    ins - the instruction
//
// Returns:
//    The mapped instruction format.
//
emitter::insFormat emitter::emitMapFmtForIns(insFormat fmt, instruction ins)
{
    switch (ins)
    {
        case INS_rol_N:
        case INS_ror_N:
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
        {
            switch (fmt)
            {
                case IF_RRW_CNS:
                    return IF_RRW_SHF;
                case IF_MRW_CNS:
                    return IF_MRW_SHF;
                case IF_SRW_CNS:
                    return IF_SRW_SHF;
                case IF_ARW_CNS:
                    return IF_ARW_SHF;
                default:
                    unreached();
            }
        }

        default:
        {
            if (IsMovInstruction(ins))
            {
                // A `mov` instruction is always "write"
                // and not "read/write".
                if (fmt == IF_RRW_ARD)
                {
                    return IF_RWR_ARD;
                }
            }
            return fmt;
        }
    }
}

//------------------------------------------------------------------------
// emitMapFmtAtoM: map the address mode formats ARD, ARW, and AWR to their direct address equivalents.
//
// Arguments:
//    fmt - the instruction format to map
//
// Returns:
//    The mapped instruction format.
//
emitter::insFormat emitter::emitMapFmtAtoM(insFormat fmt)
{
    // We should only get here for AM formats
    assert((fmt >= IF_ARD) && (fmt <= IF_RWR_RRD_ARD_RRD));

    // We should have the same number of AM and GM formats
    static_assert_no_msg((IF_RWR_RRD_ARD_RRD - IF_ARD) == (IF_RWR_RRD_MRD_RRD - IF_MRD));

    // GM should precede AM in the list
    static_assert_no_msg(IF_MRD < IF_ARD);

    const unsigned delta = IF_ARD - IF_MRD;

    // Spot check a few entries
    static_assert_no_msg((IF_ARD - delta) == IF_MRD);
    static_assert_no_msg((IF_ARD_CNS - delta) == IF_MRD_CNS);
    static_assert_no_msg((IF_ARD_RRD - delta) == IF_MRD_RRD);
    static_assert_no_msg((IF_RRD_ARD - delta) == IF_RRD_MRD);
    static_assert_no_msg((IF_RRD_ARD_CNS - delta) == IF_RRD_MRD_CNS);
    static_assert_no_msg((IF_RRD_ARD_RRD - delta) == IF_RRD_MRD_RRD);
    static_assert_no_msg((IF_RRD_RRD_ARD - delta) == IF_RRD_RRD_MRD);
    static_assert_no_msg((IF_RWR_RRD_ARD_RRD - delta) == IF_RWR_RRD_MRD_RRD);

    return static_cast<insFormat>(fmt - delta);
}

//------------------------------------------------------------------------
// emitHandleMemOp: For a memory operand, fill in the relevant fields of the instrDesc.
//
// Arguments:
//    indir - the memory operand.
//    id - the instrDesc to fill in.
//    fmt - the instruction format to use. This must be one of the ARD, AWR, or ARW formats.
//    ins - the instruction we are generating. This might affect the instruction format we choose.
//
// Assumptions:
//    The correctly sized instrDesc must already be created, e.g., via emitNewInstrAmd() or emitNewInstrAmdCns();
//
// Post-conditions:
//    For base address of int constant:
//        -- the caller must have added the int constant base to the instrDesc when creating it via
//           emitNewInstrAmdCns().
//    For simple address modes (base + scale * index + offset):
//        -- the base register, index register, and scale factor are set.
//        -- the caller must have added the addressing mode offset int constant to the instrDesc when creating it via
//           emitNewInstrAmdCns().
//
//    The instruction format is set.
//
//    idSetIsDspReloc() is called if necessary.
//
void emitter::emitHandleMemOp(GenTreeIndir* indir, instrDesc* id, insFormat fmt, instruction ins)
{
    assert(fmt != IF_NONE);

    GenTree* memBase = indir->Base();

    if ((memBase != nullptr) && memBase->IsCnsIntOrI() && memBase->isContained())
    {
        // Absolute addresses marked as contained should fit within the base of addr mode.
        assert(memBase->AsIntConCommon()->FitsInAddrBase(emitComp));

        // If we reach here, either:
        // - we are not generating relocatable code, (typically the non-AOT JIT case)
        // - the base address is a handle represented by an integer constant,
        // - the base address is a constant zero, or
        // - the base address is a constant that fits into the memory instruction (this can happen on x86).
        //   This last case is captured in the FitsInAddrBase method which is used by Lowering to determine that it can
        //   be contained.
        //
        assert(!emitComp->opts.compReloc || memBase->IsIconHandle() || memBase->IsIntegralConst(0) ||
               memBase->AsIntConCommon()->FitsInAddrBase(emitComp));

        if (memBase->AsIntConCommon()->AddrNeedsReloc(emitComp))
        {
            id->idSetIsDspReloc();
        }

        id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
        id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;
        id->idAddr()->iiaAddrMode.amScale   = emitter::OPSZ1; // for completeness

        id->idInsFmt(emitMapFmtForIns(fmt, ins));

        // Absolute address must have already been set in the instrDesc constructor.
        assert(emitGetInsAmdAny(id) == memBase->AsIntConCommon()->IconValue());
    }
    else
    {
        regNumber amBaseReg = REG_NA;
        if (memBase != nullptr)
        {
            assert(!memBase->isContained());
            amBaseReg = memBase->GetRegNum();
            assert(amBaseReg != REG_NA);
        }

        regNumber amIndxReg = REG_NA;
        if (indir->HasIndex())
        {
            GenTree* index = indir->Index();
            assert(!index->isContained());
            amIndxReg = index->GetRegNum();
            assert(amIndxReg != REG_NA);
        }

        assert((amBaseReg != REG_NA) || (amIndxReg != REG_NA) || (indir->Offset() != 0)); // At least one should be set.
        id->idAddr()->iiaAddrMode.amBaseReg = amBaseReg;
        id->idAddr()->iiaAddrMode.amIndxReg = amIndxReg;
        id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(indir->Scale());

        id->idInsFmt(emitMapFmtForIns(fmt, ins));

        // disp must have already been set in the instrDesc constructor.
        assert(emitGetInsAmdAny(id) == indir->Offset()); // make sure "disp" is stored properly
    }

#ifdef DEBUG
    if ((memBase != nullptr) && memBase->IsIconHandle() && memBase->isContained())
    {
        id->idDebugOnlyInfo()->idFlags     = memBase->gtFlags;
        id->idDebugOnlyInfo()->idMemCookie = memBase->AsIntCon()->gtTargetHandle;
    }
#endif
}

// Takes care of storing all incoming register parameters
// into its corresponding shadow space (defined by the x64 ABI)
void emitter::spillIntArgRegsToShadowSlots()
{
    unsigned       argNum;
    instrDesc*     id;
    UNATIVE_OFFSET sz;

    assert(emitComp->compGeneratingProlog);

    for (argNum = 0; argNum < MAX_REG_ARG; ++argNum)
    {
        regNumber argReg = intArgRegs[argNum];

        // The offsets for the shadow space start at RSP + 8
        // (right before the caller return address)
        int offset = (argNum + 1) * EA_PTRSIZE;

        id = emitNewInstrAmd(EA_PTRSIZE, offset);
        id->idIns(INS_mov);
        id->idInsFmt(emitInsModeFormat(INS_mov, IF_ARD_RRD));
        id->idAddr()->iiaAddrMode.amBaseReg = REG_SPBASE;
        id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;
        id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(1);

        // The offset has already been set in the intrDsc ctor,
        // make sure we got it right.
        assert(emitGetInsAmdAny(id) == ssize_t(offset));

        id->idReg1(argReg);
        sz = emitInsSizeAM(id, insCodeMR(INS_mov));
        id->idCodeSize(sz);
        emitCurIGsize += sz;
    }
}

//------------------------------------------------------------------------
// emitInsLoadInd: Emits a "mov reg, [mem]" (or a variant such as "movzx" or "movss")
// instruction for a GT_IND node.
//
// Arguments:
//    ins - the instruction to emit
//    attr - the instruction operand size
//    dstReg - the destination register
//    mem - the GT_IND node
//
void emitter::emitInsLoadInd(instruction ins, emitAttr attr, regNumber dstReg, GenTreeIndir* mem)
{
    assert(mem->OperIs(GT_IND, GT_NULLCHECK));

    GenTree* addr = mem->Addr();

    if (addr->isContained() && addr->OperIs(GT_LCL_ADDR))
    {
        GenTreeLclVarCommon* varNode = addr->AsLclVarCommon();
        unsigned             offset  = varNode->GetLclOffs();
        emitIns_R_S(ins, attr, dstReg, varNode->GetLclNum(), offset);

        // Updating variable liveness after instruction was emitted.
        // TODO-Review: it appears that this call to genUpdateLife does nothing because it
        // returns quickly when passed GT_LCL_ADDR. Below, emitInsStoreInd had similar code
        // that replaced `varNode` with `mem` (to fix a GC hole). It might be appropriate to
        // do that here as well, but doing so showed no asm diffs, so it's not clear when
        // this scenario gets hit, at least for GC refs.
        codeGen->genUpdateLife(varNode);
        return;
    }

    assert(addr->OperIsAddrMode() || (addr->IsCnsIntOrI() && addr->isContained()) || !addr->isContained());
    ssize_t    offset = mem->Offset();
    instrDesc* id     = emitNewInstrAmd(attr, offset);
    id->idIns(ins);
    id->idReg1(dstReg);
    emitHandleMemOp(mem, id, emitInsModeFormat(ins, IF_RRD_ARD), ins);
    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);
    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitInsStoreInd: Emits a "mov [mem], reg/imm" (or a variant such as "movss")
// instruction for a GT_STOREIND node.
//
// Arguments:
//    ins - the instruction to emit
//    attr - the instruction operand size
//    mem - the GT_STOREIND node
//
void emitter::emitInsStoreInd(instruction ins, emitAttr attr, GenTreeStoreInd* mem, insOpts instOptions)
{
    assert(mem->OperIs(GT_STOREIND));

    GenTree* addr = mem->Addr();
    GenTree* data = mem->Data();

    if (data->OperIs(GT_BSWAP, GT_BSWAP16) && data->isContained())
    {
#ifdef TARGET_AMD64
        assert(ins == INS_movbe || ins == INS_movbe_apx);
#else
        assert(ins == INS_movbe);
#endif
        data = data->gtGetOp1();
    }

    if (addr->isContained() && addr->OperIs(GT_LCL_ADDR))
    {
        GenTreeLclVarCommon* varNode = addr->AsLclVarCommon();
        unsigned             offset  = varNode->GetLclOffs();

        if (data->isContainedIntOrIImmed())
        {
            assert(instOptions == INS_OPTS_NONE);
            emitIns_S_I(ins, attr, varNode->GetLclNum(), offset, (int)data->AsIntConCommon()->IconValue());
        }
#if defined(FEATURE_HW_INTRINSICS)
        else if (data->OperIsHWIntrinsic() && data->isContained())
        {
            GenTreeHWIntrinsic* hwintrinsic = data->AsHWIntrinsic();
            NamedIntrinsic      intrinsicId = hwintrinsic->GetHWIntrinsicId();
            size_t              numArgs     = hwintrinsic->GetOperandCount();
            GenTree*            op1         = hwintrinsic->Op(1);

            if (numArgs == 1)
            {
                emitIns_S_R(ins, attr, op1->GetRegNum(), varNode->GetLclNum(), offset, instOptions);
            }
            else
            {
                assert(numArgs == 2);
                assert(instOptions == INS_OPTS_NONE);

                int icon = static_cast<int>(hwintrinsic->Op(2)->AsIntConCommon()->IconValue());
                emitIns_S_R_I(ins, attr, varNode->GetLclNum(), offset, op1->GetRegNum(), icon);
            }
        }
#endif // FEATURE_HW_INTRINSICS
        else
        {
            assert(!data->isContained());
            emitIns_S_R(ins, attr, data->GetRegNum(), varNode->GetLclNum(), offset, instOptions);
        }

        // Updating variable liveness after instruction was emitted
        codeGen->genUpdateLife(mem);
        return;
    }

    ssize_t        offset = mem->Offset();
    UNATIVE_OFFSET sz;
    instrDesc*     id;

    if (data->isContainedIntOrIImmed())
    {
        assert(instOptions == INS_OPTS_NONE);

        int icon = (int)data->AsIntConCommon()->IconValue();
        id       = emitNewInstrAmdCns(attr, offset, icon);
        id->idIns(ins);
        emitHandleMemOp(mem, id, emitInsModeFormat(ins, IF_ARD_CNS), ins);
        sz = emitInsSizeAM(id, insCodeMI(ins), icon);
        id->idCodeSize(sz);
    }
#if defined(FEATURE_HW_INTRINSICS)
    else if (data->OperIsHWIntrinsic() && data->isContained())
    {
        GenTreeHWIntrinsic* hwintrinsic = data->AsHWIntrinsic();
        NamedIntrinsic      intrinsicId = hwintrinsic->GetHWIntrinsicId();
        size_t              numArgs     = hwintrinsic->GetOperandCount();
        GenTree*            op1         = hwintrinsic->Op(1);

        if (numArgs == 1)
        {
            id = emitNewInstrAmd(attr, offset);
            id->idIns(ins);
            emitHandleMemOp(mem, id, emitInsModeFormat(ins, IF_ARD_RRD), ins);
            id->idReg1(op1->GetRegNum());

            assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
            SetEvexEmbMaskIfNeeded(id, instOptions);

            sz = emitInsSizeAM(id, insCodeMR(ins));
            id->idCodeSize(sz);
        }
        else
        {
            assert(numArgs == 2);
            assert(instOptions == INS_OPTS_NONE);

            int icon = static_cast<int>(hwintrinsic->Op(2)->AsIntConCommon()->IconValue());

            id = emitNewInstrAmdCns(attr, offset, icon);
            id->idIns(ins);
            id->idReg1(op1->GetRegNum());
            emitHandleMemOp(mem, id, emitInsModeFormat(ins, IF_ARD_RRD_CNS), ins);
            sz = emitInsSizeAM(id, insCodeMR(ins), icon);
            id->idCodeSize(sz);
        }
    }
#endif // FEATURE_HW_INTRINSICS
    else
    {
        assert(!data->isContained());
        id = emitNewInstrAmd(attr, offset);
        id->idIns(ins);
        emitHandleMemOp(mem, id, emitInsModeFormat(ins, IF_ARD_RRD), ins);
        id->idReg1(data->GetRegNum());

        assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
        SetEvexEmbMaskIfNeeded(id, instOptions);

        sz = emitInsSizeAM(id, insCodeMR(ins));
        id->idCodeSize(sz);
    }

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitInsStoreLcl: Emits a "mov [mem], reg/imm" (or a variant such as "movss")
// instruction for a GT_STORE_LCL_VAR node.
//
// Arguments:
//    ins - the instruction to emit
//    attr - the instruction operand size
//    varNode - the GT_STORE_LCL_VAR node
//
void emitter::emitInsStoreLcl(instruction ins, emitAttr attr, GenTreeLclVarCommon* varNode)
{
    assert(varNode->OperIs(GT_STORE_LCL_VAR));
    assert(varNode->GetRegNum() == REG_NA); // stack store

    GenTree* data = varNode->gtGetOp1();
    codeGen->inst_set_SV_var(varNode);

    if (data->isContainedIntOrIImmed())
    {
        emitIns_S_I(ins, attr, varNode->GetLclNum(), 0, (int)data->AsIntConCommon()->IconValue());
    }
    else
    {
        assert(!data->isContained());
        emitIns_S_R(ins, attr, data->GetRegNum(), varNode->GetLclNum(), 0);
    }
}

//------------------------------------------------------------------------
// emitInsBinary: Emits an instruction for a node which takes two operands
//
// Arguments:
//    ins - the instruction to emit
//    attr - the instruction operand size
//    dst - the destination and first source operand
//    src - the second source operand
//    targetReg - target register of this binary node (only used for APX-NDD form)
//
// Assumptions:
//  i) caller of this routine needs to call genConsumeReg()
// ii) caller of this routine needs to call genProduceReg()
regNumber emitter::emitInsBinary(instruction ins, emitAttr attr, GenTree* dst, GenTree* src, regNumber targetReg)
{
    // We can only have one memory operand and only src can be a constant operand
    // However, the handling for a given operand type (mem, cns, or other) is fairly
    // consistent regardless of whether they are src or dst. As such, we will find
    // the type of each operand and only check them against src/dst where relevant.

    const bool useNDD = UsePromotedEVEXEncoding() && (targetReg != REG_NA);
#if !defined(TARGET_AMD64)
    // APX does not support 32-bit system.
    assert(!useNDD);
#else
    if (useNDD)
    {
        assert(IsApxNddEncodableInstruction(ins));
        // targetReg has to be an actual register if using NDD.
        assert(targetReg < REG_STK);
        // make sure target register is not either of the src registers.
        assert(dst->isUsedFromReg());
        regNumber dstreg = dst->GetRegNum();
        regNumber srcreg = src->isUsedFromReg() ? src->GetRegNum() : REG_NA;
        assert(targetReg != dstreg);
        assert(targetReg != srcreg);
    }
#endif

    GenTree* memOp   = nullptr;
    GenTree* cnsOp   = nullptr;
    GenTree* otherOp = nullptr;

    if (dst->isContained() || (dst->isLclField() && (dst->GetRegNum() == REG_NA)) || dst->isUsedFromSpillTemp())
    {
        // dst can only be a modrm
        // dst on 3opImul isn't really the dst
        assert(dst->isUsedFromMemory() || (dst->GetRegNum() == REG_NA) || instrIs3opImul(ins));
        assert(!src->isUsedFromMemory());

        // APX code cannot hit this path.
        assert(!useNDD);

        memOp = dst;

        if (src->isContained())
        {
            assert(src->IsCnsIntOrI());
            cnsOp = src;
        }
        else
        {
            otherOp = src;
        }
    }
    else if (src->isContained() || src->isUsedFromSpillTemp())
    {
        assert(!dst->isUsedFromMemory());
        otherOp = dst;

        if ((src->IsCnsIntOrI() || src->IsCnsFltOrDbl()) && !src->isUsedFromSpillTemp())
        {
            assert(!src->isUsedFromMemory() || src->IsCnsFltOrDbl());
            cnsOp = src;
        }
        else
        {
            assert(src->isUsedFromMemory());
            memOp = src;
        }
    }

    // At this point, we either have a memory operand or we don't.
    //
    // If we don't then the logic is very simple and  we will either be emitting a
    // `reg, immed` instruction (if src is a cns) or a `reg, reg` instruction otherwise.
    //
    // If we do have a memory operand, the logic is a bit more complicated as we need
    // to do different things depending on the type of memory operand. These types include:
    //  * Spill temp
    //  * Indirect access
    //    * Local variable
    //    * Class variable
    //    * Addressing mode [base + index * scale + offset]
    //  * Local field
    //  * Local variable
    //
    // Most of these types (except Indirect: Class variable and Indirect: Addressing mode)
    // give us a local variable number and an offset and access memory on the stack
    //
    // Indirect: Class variable is used for access static class variables and gives us a handle
    // to the memory location we read from
    //
    // Indirect: Addressing mode is used for the remaining memory accesses and will give us
    // a base address, an index, a scale, and an offset. These are combined to let us easily
    // access the given memory location.
    //
    // In all of the memory access cases, we determine which form to emit (e.g. `reg, [mem]`
    // or `[mem], reg`) by comparing memOp to src to determine which `emitIns_*` method needs
    // to be called. The exception is for the `[mem], immed` case (for Indirect: Class variable)
    // where only src can be the immediate.

    if (memOp != nullptr)
    {
        TempDsc* tmpDsc = nullptr;
        unsigned varNum = BAD_VAR_NUM;
        unsigned offset = (unsigned)-1;

        if (memOp->isUsedFromSpillTemp())
        {
            assert(memOp->IsRegOptional());

            tmpDsc = codeGen->getSpillTempDsc(memOp);
            varNum = tmpDsc->tdTempNum();
            offset = 0;

            codeGen->regSet.tmpRlsTemp(tmpDsc);
        }
        else if (memOp->isIndir())
        {
            GenTreeIndir* memIndir = memOp->AsIndir();
            GenTree*      memBase  = memIndir->gtOp1;

            switch (memBase->OperGet())
            {
                case GT_LCL_ADDR:
                    if (memBase->isContained())
                    {
                        varNum = memBase->AsLclFld()->GetLclNum();
                        offset = memBase->AsLclFld()->GetLclOffs();

                        // Ensure that all the GenTreeIndir values are set to their defaults.
                        assert(!memIndir->HasIndex());
                        assert(memIndir->Scale() == 1);
                        assert(memIndir->Offset() == 0);
                        break;
                    }
                    FALLTHROUGH;

                default: // Addressing mode [base + index * scale + offset]
                {
                    instrDesc* id = nullptr;

                    if (cnsOp != nullptr)
                    {
                        assert(memOp == dst);
                        assert(cnsOp == src);
                        assert(otherOp == nullptr);
                        assert(src->IsCnsIntOrI());

                        // APX code cannot hit this path.
                        assert(!useNDD);

                        id = emitNewInstrAmdCns(attr, memIndir->Offset(), (int)src->AsIntConCommon()->IconValue());
                    }
                    else
                    {
                        ssize_t offset = memIndir->Offset();
                        id             = emitNewInstrAmd(attr, offset);
                        id->idIns(ins);

                        GenTree* regTree = (memOp == src) ? dst : src;

                        // there must be one non-contained op
                        assert(!regTree->isContained());
                        id->idReg1(regTree->GetRegNum());
                    }
                    assert(id != nullptr);

                    id->idIns(ins); // Set the instruction.
                    if (useNDD)
                    {
                        assert(memOp == src);
                        id->idReg1(targetReg);
                        id->idReg2(dst->GetRegNum());
                        id->idSetEvexNdContext();
                    }

                    // Determine the instruction format
                    insFormat fmt = IF_NONE;

                    if (memOp == src)
                    {
                        assert(cnsOp == nullptr);
                        assert(otherOp == dst);

                        if (instrHasImplicitRegPairDest(ins))
                        {
                            fmt = emitInsModeFormat(ins, IF_ARD);
                        }
                        else
                        {
                            // NDD allow instructions have different register on dst and src1.
                            insFormat base = useNDD ? IF_RRD_RRD_ARD : IF_RRD_ARD;
                            fmt            = emitInsModeFormat(ins, base, useNDD);
                        }
                    }
                    else
                    {
                        assert(memOp == dst);
                        assert(!useNDD);

                        if (cnsOp != nullptr)
                        {
                            assert(cnsOp == src);
                            assert(otherOp == nullptr);
                            assert(src->IsCnsIntOrI());

                            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
                        }
                        else
                        {
                            assert(otherOp == src);
                            fmt = emitInsModeFormat(ins, IF_ARD_RRD);
                        }
                    }
                    assert(fmt != IF_NONE);
                    emitHandleMemOp(memIndir, id, fmt, ins);

                    // Determine the instruction size
                    UNATIVE_OFFSET sz = 0;

                    if (memOp == src)
                    {
                        assert(otherOp == dst);
                        assert(cnsOp == nullptr);

                        if (instrHasImplicitRegPairDest(ins))
                        {
                            sz = emitInsSizeAM(id, insCode(ins));
                        }
                        else
                        {
                            sz = emitInsSizeAM(id, insCodeRM(ins));
                        }
                    }
                    else
                    {
                        assert(memOp == dst);
                        assert(!useNDD);

                        if (cnsOp != nullptr)
                        {
                            assert(memOp == dst);
                            assert(cnsOp == src);
                            assert(otherOp == nullptr);

                            sz = emitInsSizeAM(id, insCodeMI(ins), (int)src->AsIntConCommon()->IconValue());
                        }
                        else
                        {
                            assert(otherOp == src);
                            sz = emitInsSizeAM(id, insCodeMR(ins));
                        }
                    }
                    assert(sz != 0);

                    id->idCodeSize(sz);

                    dispIns(id);
                    emitCurIGsize += sz;

                    return (memOp == src) ? (useNDD ? targetReg : dst->GetRegNum()) : REG_NA;
                }
            }
        }
        else
        {
            switch (memOp->OperGet())
            {
                case GT_LCL_FLD:
                case GT_STORE_LCL_FLD:
                    varNum = memOp->AsLclFld()->GetLclNum();
                    offset = memOp->AsLclFld()->GetLclOffs();
                    break;

                case GT_LCL_VAR:
                {
                    assert(memOp->IsRegOptional() ||
                           !emitComp->lvaTable[memOp->AsLclVar()->GetLclNum()].lvIsRegCandidate());
                    varNum = memOp->AsLclVar()->GetLclNum();
                    offset = 0;
                    break;
                }

                default:
                    unreached();
                    break;
            }
        }

        // Ensure we got a good varNum and offset.
        // We also need to check for `tmpDsc != nullptr` since spill temp numbers
        // are negative and start with -1, which also happens to be BAD_VAR_NUM.
        assert((varNum != BAD_VAR_NUM) || (tmpDsc != nullptr));
        assert(offset != (unsigned)-1);

        if (memOp == src)
        {
            assert(otherOp == dst);
            assert(cnsOp == nullptr);

            if (instrHasImplicitRegPairDest(ins))
            {
                // src is a stack based local variable
                // dst is implicit - RDX:RAX
                emitIns_S(ins, attr, varNum, offset);
            }
            else
            {
                if (useNDD)
                {
                    emitIns_R_R_S(ins, attr, targetReg, dst->GetRegNum(), varNum, offset, INS_OPTS_EVEX_nd);
                    return targetReg;
                }
                else
                {
                    // src is a stack based local variable
                    // dst is a register
                    emitIns_R_S(ins, attr, dst->GetRegNum(), varNum, offset);
                }
            }
        }
        else
        {
            assert(memOp == dst);
            assert((dst->GetRegNum() == REG_NA) || dst->IsRegOptional());
            assert(!useNDD);

            if (cnsOp != nullptr)
            {
                assert(cnsOp == src);
                assert(otherOp == nullptr);
                assert(src->IsCnsIntOrI());

                // src is an contained immediate
                // dst is a stack based local variable
                emitIns_S_I(ins, attr, varNum, offset, (int)src->AsIntConCommon()->IconValue());
            }
            else
            {
                assert(otherOp == src);
                assert(!src->isContained());

                // src is a register
                // dst is a stack based local variable
                emitIns_S_R(ins, attr, src->GetRegNum(), varNum, offset);
            }
        }
    }
    else if (cnsOp != nullptr) // reg, immed
    {
        assert(cnsOp == src);
        assert(otherOp == dst);

        if (src->IsCnsIntOrI())
        {
            assert(!dst->isContained());
            GenTreeIntConCommon* intCns = src->AsIntConCommon();

            if (useNDD)
            {
                emitIns_R_R_I(ins, attr, targetReg, dst->GetRegNum(), (int)intCns->IconValue(), INS_OPTS_EVEX_nd);
                return targetReg;
            }
            else
            {
                emitIns_R_I(ins, attr, dst->GetRegNum(), intCns->IconValue());
            }
        }
        else
        {
            assert(!useNDD);
            assert(src->IsCnsFltOrDbl());
            GenTreeDblCon* dblCns = src->AsDblCon();

            CORINFO_FIELD_HANDLE hnd = emitFltOrDblConst(dblCns->DconValue(), emitTypeSize(dblCns));
            emitIns_R_C(ins, attr, dst->GetRegNum(), hnd, 0);
        }
    }
    else // reg, reg
    {
        assert(otherOp == nullptr);
        assert(!src->isContained() && !dst->isContained());

        if (instrHasImplicitRegPairDest(ins))
        {
            emitIns_R(ins, attr, src->GetRegNum());
        }
        else
        {
            if (useNDD)
            {
                emitIns_R_R_R(ins, attr, targetReg, dst->GetRegNum(), src->GetRegNum(), INS_OPTS_EVEX_nd);
                return targetReg;
            }
            else
            {
                emitIns_R_R(ins, attr, dst->GetRegNum(), src->GetRegNum());
            }
        }
    }

    return dst->GetRegNum();
}

//------------------------------------------------------------------------
// emitInsRMW: Emit logic for Read-Modify-Write binary instructions.
//
// Responsible for emitting a single instruction that will perform an operation of the form:
//      *addr = *addr <BinOp> src
// For example:
//      ADD [RAX], RCX
//
// Arguments:
//    ins - instruction to generate
//    attr - emitter attribute for instruction
//    storeInd - indir for RMW addressing mode
//    src - source operand of instruction
//
// Assumptions:
//    Lowering has taken care of recognizing the StoreInd pattern of:
//          StoreInd( AddressTree, BinOp( Ind ( AddressTree ), Operand ) )
//    The address to store is already sitting in a register.
//
// Notes:
//    This is a no-produce operation, meaning that no register output will
//    be produced for future use in the code stream.
//
void emitter::emitInsRMW(instruction ins, emitAttr attr, GenTreeStoreInd* storeInd, GenTree* src)
{
    GenTree* addr = storeInd->Addr();
    addr          = addr->gtSkipReloadOrCopy();
    assert(addr->OperIs(GT_LCL_VAR, GT_LEA, GT_CNS_INT) || addr->IsLclVarAddr());

    instrDesc*     id = nullptr;
    UNATIVE_OFFSET sz;

    ssize_t offset = storeInd->Offset();

    if (src->isContainedIntOrIImmed())
    {
        GenTreeIntConCommon* intConst = src->AsIntConCommon();
        int                  iconVal  = (int)intConst->IconValue();
        switch (ins)
        {
            case INS_rcl_N:
            case INS_rcr_N:
            case INS_rol_N:
            case INS_ror_N:
            case INS_shl_N:
            case INS_shr_N:
            case INS_sar_N:
                iconVal &= 0x7F;
                break;
            default:
                break;
        }

        if (addr->isContained() && addr->OperIs(GT_LCL_ADDR))
        {
            GenTreeLclVarCommon* lclVar = addr->AsLclVarCommon();
            emitIns_S_I(ins, attr, lclVar->GetLclNum(), lclVar->GetLclOffs(), iconVal);
            return;
        }
        else
        {
            id = emitNewInstrAmdCns(attr, offset, iconVal);
            emitHandleMemOp(storeInd, id, emitInsModeFormat(ins, IF_ARD_CNS), ins);
            id->idIns(ins);
            sz = emitInsSizeAM(id, insCodeMI(ins), iconVal);
        }
    }
    else
    {
        assert(!src->isContained()); // there must be one non-contained src

        if (addr->isContained() && addr->OperIs(GT_LCL_ADDR))
        {
            GenTreeLclVarCommon* lclVar = addr->AsLclVarCommon();
            emitIns_S_R(ins, attr, src->GetRegNum(), lclVar->GetLclNum(), lclVar->GetLclOffs());
            return;
        }

        // ind, reg
        id = emitNewInstrAmd(attr, offset);
        emitHandleMemOp(storeInd, id, emitInsModeFormat(ins, IF_ARD_RRD), ins);
        id->idReg1(src->GetRegNum());
        id->idIns(ins);
        sz = emitInsSizeAM(id, insCodeMR(ins));
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitInsRMW: Emit logic for Read-Modify-Write unary instructions.
//
// Responsible for emitting a single instruction that will perform an operation of the form:
//      *addr = UnaryOp *addr
// For example:
//      NOT [RAX]
//
// Arguments:
//    ins - instruction to generate
//    attr - emitter attribute for instruction
//    storeInd - indir for RMW addressing mode
//
// Assumptions:
//    Lowering has taken care of recognizing the StoreInd pattern of:
//          StoreInd( AddressTree, UnaryOp( Ind ( AddressTree ) ) )
//    The address to store is already sitting in a register.
//
// Notes:
//    This is a no-produce operation, meaning that no register output will
//    be produced for future use in the code stream.
//
void emitter::emitInsRMW(instruction ins, emitAttr attr, GenTreeStoreInd* storeInd)
{
    GenTree* addr = storeInd->Addr();
    addr          = addr->gtSkipReloadOrCopy();
    assert(addr->OperIs(GT_LCL_VAR, GT_LEA, GT_CNS_INT) || addr->IsLclVarAddr());

    ssize_t offset = storeInd->Offset();

    if (addr->isContained() && addr->OperIs(GT_LCL_ADDR))
    {
        GenTreeLclVarCommon* lclVar = addr->AsLclVarCommon();
        emitIns_S(ins, attr, lclVar->GetLclNum(), lclVar->GetLclOffs());
        return;
    }

    instrDesc* id = emitNewInstrAmd(attr, offset);
    emitHandleMemOp(storeInd, id, emitInsModeFormat(ins, IF_ARD), ins);
    id->idIns(ins);
    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction referencing a single register.
 */

void emitter::emitIns_R(instruction ins, emitAttr attr, regNumber reg, insOpts instOptions /* = INS_OPTS_NONE */)
{
    emitAttr size = EA_SIZE(attr);

    assert(size <= EA_PTRSIZE);
    noway_assert(emitVerifyEncodable(ins, size, reg));

    UNATIVE_OFFSET sz;
    instrDesc*     id  = emitNewInstrSmall(attr);
    insFormat      fmt = emitInsModeFormat(ins, IF_RRD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(reg);

    switch (ins)
    {
        case INS_inc:
        case INS_dec:
#ifdef TARGET_AMD64

            sz = 2; // x64 has no 1-byte opcode (it is the same encoding as the REX prefix)

#else // !TARGET_AMD64

            if (size == EA_1BYTE)
                sz = 2; // Use the long form as the small one has no 'w' bit
            else
                sz = 1; // Use short form

#endif // !TARGET_AMD64

            break;

        case INS_pop:
        case INS_push:
            SetApxPpxIfNeeded(id, instOptions);
            __fallthrough;
        case INS_pop_hide:
        case INS_push_hide:

            /* We don't currently push/pop small values */

            assert(size == EA_PTRSIZE);

            sz = 1;
            break;

        default:

            /* All the sixteen INS_setCCs are contiguous. */

            if (INS_seto <= ins && ins <= INS_setg)
            {
                // Rough check that we used the endpoints for the range check

                assert(INS_seto + 0xF == INS_setg);

                // The caller must specify EA_1BYTE for 'attr'

                assert(attr == EA_1BYTE);

                /* We expect this to always be a 'big' opcode */

                assert(insEncodeMRreg(id, reg, attr, insCodeMR(ins)) & 0x00FF0000);

                size = attr;

                sz = 3;
                break;
            }
            else
            {
                sz = 2;
                break;
            }
    }

    SetEvexNfIfNeeded(id, instOptions);
    SetEvexZuIfNeeded(id, instOptions);

    // Vex bytes
    sz += emitGetAdjustedSize(id, insEncodeMRreg(id, reg, attr, insCodeMR(ins)));

    // REX byte
    if (IsExtendedReg(reg, attr) || TakesRexWPrefix(id))
    {
        sz += emitGetRexPrefixSize(id, ins);
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

#if defined(FEATURE_SIMD)
//-----------------------------------------------------------------------------------
// emitStoreSimd12ToLclOffset: store SIMD12 value from dataReg to varNum+offset.
//
// Arguments:
//     varNum         - the variable on the stack to use as a base;
//     offset         - the offset from the varNum;
//     dataReg        - the src reg with SIMD12 value;
//     tmpRegProvider - a tree to grab a tmp reg from if needed (can be null).
//
void emitter::emitStoreSimd12ToLclOffset(unsigned varNum, unsigned offset, regNumber dataReg, GenTree* tmpRegProvider)
{
    assert(varNum != BAD_VAR_NUM);
    assert(isFloatReg(dataReg));

    // Store lower 8 bytes
    emitIns_S_R(INS_movsd_simd, EA_8BYTE, dataReg, varNum, offset);

    if (emitComp->compOpportunisticallyDependsOn(InstructionSet_SSE42))
    {
        // Extract and store upper 4 bytes
        emitIns_S_R_I(INS_extractps, EA_16BYTE, varNum, offset + 8, dataReg, 2);
    }
    else if (tmpRegProvider != nullptr)
    {
        regNumber tmpReg = codeGen->internalRegisters.GetSingle(tmpRegProvider);
        assert(isFloatReg(tmpReg));

        // Extract upper 4 bytes from data
        emitIns_R_R(INS_movhlps, EA_16BYTE, tmpReg, dataReg);

        // Store upper 4 bytes
        emitIns_S_R(INS_movss, EA_4BYTE, tmpReg, varNum, offset + 8);
    }
    else
    {
        // We don't have temp regs - let's do two shuffles then

        // [0,1,2,3] -> [2,3,0,1]
        emitIns_R_R_I(INS_pshufd, EA_16BYTE, dataReg, dataReg, 78);

        //  Store upper 4 bytes
        emitIns_S_R(INS_movss, EA_4BYTE, dataReg, varNum, offset + 8);

        // Restore dataReg to its previous state: [2,3,0,1] -> [0,1,2,3]
        emitIns_R_R_I(INS_pshufd, EA_16BYTE, dataReg, dataReg, 78);
    }
}
#endif // FEATURE_SIMD

/*****************************************************************************
 *
 *  Add an instruction referencing a register and a constant.
 */

void emitter::emitIns_R_I(instruction         ins,
                          emitAttr            attr,
                          regNumber           reg,
                          ssize_t             val,
                          insOpts instOptions DEBUGARG(size_t targetHandle) DEBUGARG(GenTreeFlags gtFlags))
{
    emitAttr size = EA_SIZE(attr);

    // Allow emitting SSE2/AVX SIMD instructions of R_I form that can specify EA_16BYTE or EA_32BYTE
    assert(size <= EA_PTRSIZE || IsSimdInstruction(ins));

    noway_assert(emitVerifyEncodable(ins, size, reg));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(size < EA_8BYTE || ins == INS_mov || ((int)val == val && !EA_IS_CNS_RELOC(attr)));
#endif

    UNATIVE_OFFSET sz;
    instrDesc*     id;
    insFormat      fmt       = emitInsModeFormat(ins, IF_RRD_CNS);
    bool           valInByte = ((signed char)val == (target_ssize_t)val) && (ins != INS_mov) && (ins != INS_test);

    // BT reg,imm might be useful but it requires special handling of the immediate value
    // (it is always encoded in a byte). Let's not complicate things until this is needed.
    assert(ins != INS_bt);

    // TODO-Cleanup: This is used to track whether a call to emitInsSize is necessary. The call
    // has existed for quite some time, historically, but it is likely problematic in practice.
    // However, it is non-trivial to prove it is safe to remove at this time.
    bool isSimdInsAndValInByte = false;

    // Figure out the size of the instruction
    switch (ins)
    {
        case INS_mov:
#ifdef TARGET_AMD64
            // mov reg, imm64 is equivalent to mov reg, imm32 if the high order bits are all 0
            // and this isn't a reloc constant.
            if (((size > EA_4BYTE) && (0 == (val & 0xFFFFFFFF00000000LL))) && !EA_IS_CNS_RELOC(attr))
            {
                attr = size = EA_4BYTE;
            }

            if (size > EA_4BYTE)
            {
                sz = 9; // Really it is 10, but we'll add one more later
                break;
            }
#endif // TARGET_AMD64
            sz = 5;
            break;

        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_RRW_SHF;
            sz  = 3;
            val &= 0x7F;
            valInByte = true; // shift amount always placed in a byte
            break;

        default:

            if (EA_IS_CNS_RELOC(attr))
            {
                valInByte = false; // relocs can't be placed in a byte
            }

            if (valInByte)
            {
                if (IsSimdInstruction(ins))
                {
                    sz                    = 1;
                    isSimdInsAndValInByte = true;
                }
                else if (size == EA_1BYTE && reg == REG_EAX && !instrIs3opImul(ins))
                {
                    sz = 2;
                }
                else
                {
                    sz = 3;
                }
            }
            else
            {
                assert(!IsSimdInstruction(ins));

                if (reg == REG_EAX && !instrIs3opImul(ins))
                {
                    sz = 1;
                }
                else
                {
                    sz = 2;
                }

#ifdef TARGET_AMD64
                if (size > EA_4BYTE)
                {
                    // We special-case anything that takes a full 8-byte constant.
                    sz += 4;
                }
                else
#endif // TARGET_AMD64
                {
                    sz += EA_SIZE_IN_BYTES(attr);
                }
            }
            break;
    }

    if (emitComp->IsTargetAbi(CORINFO_NATIVEAOT_ABI))
    {
        if (EA_IS_CNS_SEC_RELOC(attr))
        {
            id                      = emitNewInstrCns(attr, val);
            id->idAddr()->iiaSecRel = true;
        }
        else
        {
            id = emitNewInstrSC(attr, val);
        }
    }
    else
    {
        id = emitNewInstrSC(attr, val);
    }
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(reg);

#ifdef DEBUG
    id->idDebugOnlyInfo()->idFlags     = gtFlags;
    id->idDebugOnlyInfo()->idMemCookie = targetHandle;
#endif

    SetEvexNfIfNeeded(id, instOptions);
    SetEvexDFVIfNeeded(id, instOptions);

    if (isSimdInsAndValInByte)
    {
        bool includeRexPrefixSize = true;

        // Do not get the RexSize() but just decide if it will be included down further and if yes,
        // do not include it again.
        if (IsExtendedReg(reg, attr) || TakesRexWPrefix(id) || instrIsExtendedReg3opImul(ins))
        {
            includeRexPrefixSize = false;
        }

        sz += emitInsSize(id, insCodeMI(ins), includeRexPrefixSize);
    }
    sz += emitGetAdjustedSize(id, insCodeMI(ins));
#ifdef TARGET_AMD64
    if (reg == REG_EAX && !instrIs3opImul(ins) && TakesApxExtendedEvexPrefix(id))
    {
        // ACC form is not promoted into EVEX space, need to emit with MI form.
        sz += 1;
    }
#endif // TARGET_AMD64

    // Do we need a REX prefix for AMD64? We need one if we are using any extended register (REX.R), or if we have a
    // 64-bit sized operand (REX.W). Note that IMUL in our encoding is special, with a "built-in", implicit, target
    // register. So we also need to check if that built-in register is an extended register.
    if (IsExtendedReg(reg, attr) || TakesRexWPrefix(id) || instrIsExtendedReg3opImul(ins))
    {
        sz += emitGetRexPrefixSize(id, ins);
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    if (reg == REG_ESP)
    {
        emitAdjustStackDepth(ins, val);
    }
}

/*****************************************************************************
 *
 *  Add an instruction referencing an integer constant.
 */

void emitter::emitIns_I(instruction ins, emitAttr attr, cnsval_ssize_t val)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id;
    bool           valInByte = ((signed char)val == (target_ssize_t)val);

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    if (EA_IS_CNS_RELOC(attr))
    {
        valInByte = false; // relocs can't be placed in a byte
    }

    switch (ins)
    {
        case INS_loop:
        case INS_jge:
            sz = 2;
            break;

        case INS_ret:
            sz = 3;
            break;

        case INS_push_hide:
        case INS_push:
            sz = valInByte ? 2 : 5;
            break;

        default:
            NO_WAY("unexpected instruction");
    }

    id = emitNewInstrSC(attr, val);
    id->idIns(ins);
    id->idInsFmt(IF_CNS);

    sz += emitGetAdjustedSize(id, insCodeMI(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

/*****************************************************************************
 *
 *  Add a "jump through a table" instruction.
 */

void emitter::emitIns_IJ(emitAttr attr, regNumber reg, unsigned base)
{
    assert(EA_SIZE(attr) == EA_4BYTE);

    UNATIVE_OFFSET    sz  = 3 + 4;
    const instruction ins = INS_i_jmp;

    if (IsExtendedReg(reg, attr))
    {
        sz += emitGetRexPrefixSize(ins);
    }

    instrDesc* id = emitNewInstrAmd(attr, base);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_ARD));
    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = reg;
    id->idAddr()->iiaAddrMode.amScale   = emitter::OPSZP;

    if (m_debugInfoSize > 0)
    {
        id->idDebugOnlyInfo()->idMemCookie = base;
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with a static data member operand. If 'size' is 0, the
 *  instruction operates on the address of the static member instead of its
 *  value (e.g. "push offset clsvar", rather than "push dword ptr [clsvar]").
 */

void emitter::emitIns_C(instruction ins, emitAttr attr, CORINFO_FIELD_HANDLE fldHnd, int offs)
{
    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id;

    /* Are we pushing the offset of the class variable? */

    if (EA_IS_OFFSET(attr))
    {
        assert(ins == INS_push);
        sz = 1 + TARGET_POINTER_SIZE;

        id = emitNewInstrDsp(EA_1BYTE, offs);
        id->idIns(ins);
        id->idInsFmt(IF_MRD_OFF);
    }
    else
    {
        insFormat fmt = emitInsModeFormat(ins, IF_MRD);

        id = emitNewInstrDsp(attr, offs);
        id->idIns(ins);
        id->idInsFmt(fmt);
        sz = emitInsSizeCV(id, insCodeMR(ins));
    }

    if (TakesRexWPrefix(id))
    {
        // REX.W prefix
        sz += emitGetRexPrefixSize(id, ins);
    }

    id->idAddr()->iiaFieldHnd = fldHnd;

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

//------------------------------------------------------------------------
// emitIns_A: Emit an instruction with one memory ("[address mode]") operand.
//
// Arguments:
//    ins   - The instruction to emit
//    attr  - The corresponding emit attribute
//    indir - The memory operand, represented as an indirection tree
//
void emitter::emitIns_A(instruction ins, emitAttr attr, GenTreeIndir* indir)
{
    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmd(attr, offs);
    insFormat  fmt  = emitInsModeFormat(ins, IF_ARD);

    id->idIns(ins);
    emitHandleMemOp(indir, id, fmt, ins);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

//------------------------------------------------------------------------
// IsMovInstruction: Determines whether a give instruction is a move instruction
//
// Arguments:
//    ins       -- The instruction being checked
//
// Return Value:
//    true if the instruction is a qualifying move instruction; otherwise, false
//
// Remarks:
//    This methods covers most kinds of two operand move instructions that copy a
//    value between two registers. It does not cover all move-like instructions
//    and so doesn't currently cover things like movsb/movsw/movsd/movsq or cmovcc
//    and doesn't currently cover cases where a value is read/written from memory.
//
//    The reason it doesn't cover all instructions was namely to limit the scope
//    of the initial change to that which was impactful to move elision so that
//    it could be centrally managed and optimized. It may be beneficial to support
//    the other move instructions in the future but that may require more extensive
//    changes to ensure relevant codegen/emit paths flow and check things correctly.
bool emitter::IsMovInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_mov:
        case INS_movapd:
        case INS_movaps:
        case INS_movd32:
        case INS_movd64:
        case INS_movdqa32:
        case INS_vmovdqa64:
        case INS_movdqu32:
        case INS_vmovdqu8:
        case INS_vmovdqu16:
        case INS_vmovdqu64:
        case INS_movq:
        case INS_movsd_simd:
        case INS_movss:
        case INS_movsx:
        case INS_movupd:
        case INS_movups:
        case INS_movzx:
        case INS_kmovb_msk:
        case INS_kmovw_msk:
        case INS_kmovd_msk:
        case INS_kmovq_msk:
        case INS_kmovb_gpr:
        case INS_kmovw_gpr:
        case INS_kmovd_gpr:
        case INS_kmovq_gpr:
        {
            return true;
        }

#if defined(TARGET_AMD64)
        case INS_movsxd:
        {
            return true;
        }
#endif // TARGET_AMD64

        default:
        {
            return false;
        }
    }
}

//------------------------------------------------------------------------
// IsJccInstruction: Determine if an instruction is a conditional jump instruction.
//
// Arguments:
//    ins       -- The instruction being checked
//
// Return Value:
//    true if the instruction qualifies; otherwise, false
//
bool emitter::IsJccInstruction(instruction ins)
{
    return ((ins >= INS_jo) && (ins <= INS_jg)) || ((ins >= INS_l_jo) && (ins <= INS_l_jg));
}

//------------------------------------------------------------------------
// IsJmpInstruction: Determine if an instruction is a jump instruction but NOT a conditional jump instruction.
//
// Arguments:
//    ins       -- The instruction being checked
//
// Return Value:
//    true if the instruction qualifies; otherwise, false
//
bool emitter::IsJmpInstruction(instruction ins)
{
    return (ins == INS_i_jmp) || (ins == INS_jmp) || (ins == INS_l_jmp) || (ins == INS_tail_i_jmp);
}

//------------------------------------------------------------------------
// IsBitwiseInstruction: Determine if an instruction is a bit-wise instruction.
//
// Arguments:
//    ins       -- The instruction being checked
//
// Return Value:
//    true if the instruction qualifies; otherwise, false
//
bool emitter::IsBitwiseInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_pandd:
        case INS_pandnd:
        case INS_pord:
        case INS_pxord:
            return true;

        default:
            return false;
    }
}

// TODO-XArch-CQ: There are places where the fact that an instruction zero-extends
// is not an important detail, such as when "regular" floating-point code is generated
//
// This differs from cases like HWIntrinsics that deal with the entire vector and so
// they need to be "aware" that a given move impacts the upper-bits.
//
// Ideally we can detect this difference, likely via canIgnoreSideEffects, and allow
// the below optimizations for those scenarios as well.

// Track whether the instruction has a zero/sign-extension or clearing of the upper-bits as a side-effect
bool emitter::HasSideEffect(instruction ins, emitAttr size)
{
    bool hasSideEffect = false;

    switch (ins)
    {
        case INS_mov:
        {
            // non EA_PTRSIZE moves may zero-extend the source
            hasSideEffect = (size != EA_PTRSIZE);
            break;
        }

        case INS_movapd:
        case INS_movaps:
        case INS_movdqa32:
        case INS_movdqu32:
        case INS_movupd:
        case INS_movups:
        {
            // TODO-XArch-AVX512 : Handle merge/masks scenarios once k-mask support is added for these.
            // non EA_32BYTE and EA_64BYTE moves clear the upper bits under VEX and EVEX encoding respectively.
            if (UseVEXEncoding())
            {
                if (UseEvexEncoding())
                {
                    hasSideEffect = (size != EA_64BYTE);
                }
                else
                {
                    hasSideEffect = (size != EA_32BYTE);
                }
            }
            else
            {
                hasSideEffect = false;
            }
            break;
        }

        case INS_vmovdqa64:
        case INS_vmovdqu8:
        case INS_vmovdqu16:
        case INS_vmovdqu64:
        {
            // These EVEX instructions merges/masks based on k-register
            // TODO-XArch-AVX512 : Handle merge/masks scenarios once k-mask support is added for these.
            assert(UseEvexEncoding());
            hasSideEffect = (size != EA_64BYTE);
            break;
        }

        case INS_movd32:
        case INS_movd64:
        {
            // Clears the upper bits
            hasSideEffect = true;
            break;
        }

        case INS_movsd_simd:
        case INS_movss:
        {
            // Clears the upper bits under VEX encoding
            hasSideEffect = UseVEXEncoding();
            break;
        }

        case INS_movsx:
        case INS_movzx:
        {
            // Sign/Zero-extends the source
            hasSideEffect = true;
            break;
        }

        case INS_movq:
        {
            // Clears the upper bits
            hasSideEffect = true;
            break;
        }

#if defined(TARGET_AMD64)
        case INS_movsxd:
        {
            // Sign-extends the source
            hasSideEffect = true;
            break;
        }
#endif // TARGET_AMD64

        case INS_kmovb_msk:
        case INS_kmovw_msk:
        case INS_kmovd_msk:
        {
            // Zero-extends the source
            hasSideEffect = true;
            break;
        }

        case INS_kmovq_msk:
        {
            // No side effect, register is 64-bits
            hasSideEffect = false;
            break;
        }

        case INS_kmovb_gpr:
        case INS_kmovw_gpr:
        case INS_kmovd_gpr:
        case INS_kmovq_gpr:
        {
            // Zero-extends the source
            hasSideEffect = true;
            break;
        }

        default:
        {
            unreached();
        }
    }

    return hasSideEffect;
}

//----------------------------------------------------------------------------------------
// IsRedundantMov:
//    Check if the current `mov` instruction is redundant and can be omitted.
//    A `mov` is redundant in following 3 cases:
//
//    1. Move to same register on TARGET_AMD64
//       (Except 4-byte movement like "mov eax, eax" which zeros out upper bits of eax register)
//
//         mov rax, rax
//
//    2. Move that is identical to last instruction emitted.
//
//         mov rax, rbx  # <-- last instruction
//         mov rax, rbx  # <-- current instruction can be omitted.
//
//    3. Opposite Move as that of last instruction emitted.
//
//         mov rax, rbx  # <-- last instruction
//         mov rbx, rax  # <-- current instruction can be omitted.
//
// Arguments:
//                 ins  - The current instruction
//                 fmt  - The current format
//                 size - Operand size of current instruction
//                 dst  - The current destination
//                 src  - The current source
// canIgnoreSideEffects - The move can be skipped as it doesn't represent special semantics
//
// Return Value:
//    true if the move instruction is redundant; otherwise, false.

bool emitter::IsRedundantMov(
    instruction ins, insFormat fmt, emitAttr size, regNumber dst, regNumber src, bool canIgnoreSideEffects)
{
    assert(IsMovInstruction(ins));

    if (canIgnoreSideEffects && (dst == src))
    {
        // These elisions used to be explicit even when optimizations were disabled

        // Some instructions have a side effect and shouldn't be skipped
        // however existing codepaths were skipping these instructions in
        // certain scenarios and so we skip them as well for back-compat
        // when canIgnoreSideEffects is true (see below for which have a
        // side effect).
        //
        // Long term, these paths should be audited and should likely be
        // replaced with copies rather than extensions.
        return true;
    }

    if (!emitComp->opts.OptimizationEnabled())
    {
        // The remaining move elisions should only happen if optimizations are enabled
        return false;
    }

    // Skip optimization if current instruction creates a GC live value.
    if (EA_IS_GCREF_OR_BYREF(size))
    {
        return false;
    }

    bool hasSideEffect = HasSideEffect(ins, size);

    // Peephole optimization to eliminate redundant 'mov' instructions.
    if (dst == src)
    {
        // Check if we are already in the correct register and don't have a side effect
        if (!hasSideEffect)
        {
            JITDUMP("\n -- suppressing mov because src and dst is same register and the mov has no side-effects.\n");
            return true;
        }

#ifdef TARGET_64BIT
        switch (ins)
        {
            case INS_movzx:
                if (AreUpperBitsZero(src, size))
                {
                    JITDUMP("\n -- suppressing movzx because upper bits are zero.\n");
                    return true;
                }
                break;

            case INS_movsx:
            case INS_movsxd:
                if (AreUpperBitsSignExtended(src, size))
                {
                    JITDUMP("\n -- suppressing movsx or movsxd because upper bits are sign-extended.\n");
                    return true;
                }
                break;

            case INS_mov:
                if ((size == EA_4BYTE) && AreUpperBitsZero(src, size))
                {
                    JITDUMP("\n -- suppressing mov because upper bits are zero.\n");
                    return true;
                }
                break;

            default:
                break;
        }
#endif // TARGET_64BIT
    }

    // TODO-XArch-CQ: Certain instructions, such as movaps vs movups, are equivalent in
    // functionality even if their actual identifier differs and we should optimize these

    if (!emitCanPeepholeLastIns() ||         // Don't optimize if unsafe
        (emitLastIns->idIns() != ins) ||     // or if the instruction is different from the last instruction
        (emitLastIns->idOpSize() != size) || // or if the operand size is different from the last instruction
        (emitLastIns->idInsFmt() != fmt))    // or if the format is different from the last instruction
    {
        return false;
    }

    regNumber lastDst = emitLastIns->idReg1();
    regNumber lastSrc = emitLastIns->idReg2();

    // Check if we did same move in last instruction, side effects don't matter since they already happened
    if ((lastDst == dst) && (lastSrc == src))
    {
        JITDUMP("\n -- suppressing mov because last instruction already moved from src to dst register.\n");
        return true;
    }

    // Check if we did a switched mov in the last instruction  and don't have a side effect
    if ((lastDst == src) && (lastSrc == dst) && !hasSideEffect)
    {
        JITDUMP("\n -- suppressing mov because last instruction already moved from dst to src register and the mov has "
                "no side-effects.\n");
        return true;
    }

    return false;
}

//------------------------------------------------------------------------
// EmitMovsxAsCwde: try to emit "movsxd rax, eax" and "movsx eax, ax" as
//                  "cdqe" and "cwde" as a code size optimization.
//
// Arguments:
//    ins  - The instruction for the original mov
//    size - The size of the original mov
//    dst  - The destination register for the original mov
//    src  - The source register for the original mov
//
// Return Value:
//    "true" if the optimization succeeded, in which case the instruction can be
//    counted as emitted, "false" otherwise.
//
bool emitter::EmitMovsxAsCwde(instruction ins, emitAttr size, regNumber dst, regNumber src)
{
    if ((src == REG_EAX) && (src == dst))
    {
#ifdef TARGET_64BIT
        // "movsxd rax, eax".
        if ((ins == INS_movsxd) && (size == EA_4BYTE))
        {
            // "cdqe".
            emitIns(INS_cwde, EA_8BYTE);
            return true;
        }
#endif
        // "movsx eax, ax".
        if ((ins == INS_movsx) && (size == EA_2BYTE))
        {
            // "cwde".
            emitIns(INS_cwde, EA_4BYTE);
            return true;
        }
    }

    return false;
}

//------------------------------------------------------------------------
// emitIns_Mov: Emits a move instruction
//
// Arguments:
//    ins       -- The instruction being emitted
//    attr      -- The emit attribute
//    dstReg    -- The destination register
//    srcReg    -- The source register
//    canSkip   -- true if the move can be elided when dstReg == srcReg, otherwise false
//
bool emitter::emitIns_Mov(
    instruction ins, emitAttr attr, regNumber dstReg, regNumber srcReg, bool canSkip, bool useApxNdd)
{
    // Only move instructions can use emitIns_Mov
    assert(IsMovInstruction(ins));

#if DEBUG
    switch (ins)
    {
        case INS_mov:
        case INS_movsx:
        case INS_movzx:
        {
            assert(isGeneralRegister(dstReg) && isGeneralRegister(srcReg));
            break;
        }

        case INS_movapd:
        case INS_movaps:
        case INS_movdqa32:
        case INS_vmovdqa64:
        case INS_movdqu32:
        case INS_vmovdqu8:
        case INS_vmovdqu16:
        case INS_vmovdqu64:
        case INS_movsd_simd:
        case INS_movss:
        case INS_movupd:
        case INS_movups:
        {
            assert(isFloatReg(dstReg) && isFloatReg(srcReg));
            break;
        }

        case INS_movd32:
        case INS_movd64:
        {
            assert(isFloatReg(dstReg) != isFloatReg(srcReg));
            break;
        }

        case INS_movq:
        {
            assert(isFloatReg(dstReg) && isFloatReg(srcReg));
            break;
        }

#if defined(TARGET_AMD64)
        case INS_movsxd:
        {
            assert(isGeneralRegister(dstReg) && isGeneralRegister(srcReg));
            break;
        }
#endif // TARGET_AMD64

        case INS_kmovb_msk:
        case INS_kmovw_msk:
        case INS_kmovd_msk:
        case INS_kmovq_msk:
        {
            assert((isMaskReg(dstReg) || isMaskReg(srcReg)) && !isGeneralRegister(dstReg) &&
                   !isGeneralRegister(srcReg));
            break;
        }

        case INS_kmovb_gpr:
        case INS_kmovw_gpr:
        case INS_kmovd_gpr:
        case INS_kmovq_gpr:
        {
            assert(isGeneralRegister(dstReg) || isGeneralRegister(srcReg));
            break;
        }

        default:
        {
            unreached();
        }
    }
#endif

    emitAttr size = EA_SIZE(attr);

    assert(size <= EA_64BYTE);
    noway_assert(emitVerifyEncodable(ins, size, dstReg, srcReg));

    insFormat fmt = emitInsModeFormat(ins, IF_RRD_RRD);

    if (IsRedundantMov(ins, fmt, attr, dstReg, srcReg, canSkip))
    {
        // Move is redundant, no need to emit anything
        return false;
    }

    if (EmitMovsxAsCwde(ins, size, dstReg, srcReg))
    {
        // Move is redundant, no need to emit anything
        return false;
    }

#ifdef TARGET_AMD64
    if (useApxNdd)
    {
        // Move is required, but the caller is APX NDD aware
        return true;
    }
#endif // TARGET_AMD64

    instrDesc* id = emitNewInstrSmall(attr);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(dstReg);
    id->idReg2(srcReg);

    UNATIVE_OFFSET sz = emitInsSizeRR(id);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    // Move is required and the caller is not APX NDD aware, we emitted the move
    return true;
}

/*****************************************************************************
 *
 *  Add an instruction with two register operands.
 */

void emitter::emitIns_R_R(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, insOpts instOptions)
{
    if (IsMovInstruction(ins))
    {
        assert(!"Please use emitIns_Mov() to correctly handle move elision");
        emitIns_Mov(ins, attr, reg1, reg2, /* canSkip */ false);
    }

    // Checking EVEX.ND and NDD compatibility together in case the ND slot is overridden by other features.
    bool useNDD = ((instOptions & INS_OPTS_EVEX_nd_MASK) != 0) && IsApxNddEncodableInstruction(ins);

    emitAttr size = EA_SIZE(attr);

    assert(size <= EA_64BYTE);
    noway_assert(emitVerifyEncodable(ins, size, reg1, reg2));

    /* Special case: "XCHG" uses a different format */
    insFormat fmt = (ins == INS_xchg) ? IF_RRW_RRW : emitInsModeFormat(ins, IF_RRD_RRD, useNDD);

    instrDesc* id = emitNewInstrSmall(attr);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(reg1);
    id->idReg2(reg2);

    SetEvexNdIfNeeded(id, instOptions);
    SetEvexNfIfNeeded(id, instOptions);
    SetEvexDFVIfNeeded(id, instOptions);
    SetApxPpxIfNeeded(id, instOptions);
    SetEvexEmbRoundIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeRR(id);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with two register operands and an integer constant.
 */

void emitter::emitIns_R_R_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, int ival, insOpts instOptions)
{
#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    instrDesc* id = emitNewInstrSC(attr, ival);

    // Checking EVEX.ND and NDD compatibility together in case the ND slot is overridden by other features.
    bool useNDD = ((instOptions & INS_OPTS_EVEX_nd_MASK) != 0) && IsApxNddEncodableInstruction(ins);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_RRD_RRD_CNS, useNDD));
    id->idReg1(reg1);
    id->idReg2(reg2);

    code_t code = 0;

    if (hasCodeMR(ins))
    {
        code = insCodeMR(ins);
    }
    else if (hasCodeMI(ins))
    {
        code = insCodeMI(ins);
    }
    else
    {
        code = insCodeRM(ins);
    }

    assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
    SetEvexEmbMaskIfNeeded(id, instOptions);
    SetEvexNdIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeRR(id, code, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_AR(instruction ins, emitAttr attr, regNumber base, int offs, insOpts instOptions)
{
    assert(ins == INS_prefetcht0 || ins == INS_prefetcht1 || ins == INS_prefetcht2 || ins == INS_prefetchnta ||
           ins == INS_inc || ins == INS_dec);

    instrDesc* id = emitNewInstrAmd(attr, offs);

    id->idIns(ins);

    id->idInsFmt(emitInsModeFormat(ins, IF_ARD));
    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    if ((instOptions & INS_OPTS_EVEX_NoApxPromotion) != 0)
    {
        id->idSetNoApxEvexPromotion();
    }

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_AR_R_R: emits the code for an instruction that takes a base memory register, two register operands
//                 and that does not return a value
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op2Reg      -- The register of the second operand
//    op3Reg      -- The register of the third operand
//    base        -- The base register used for the memory address (first operand)
//    offs        -- The offset from base
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_AR_R_R(
    instruction ins, emitAttr attr, regNumber op2Reg, regNumber op3Reg, regNumber base, int offs, insOpts instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    instrDesc* id = emitNewInstrAmd(attr, offs);

    id->idIns(ins);
    id->idReg1(op2Reg);
    id->idReg2(op3Reg);

    id->idInsFmt(IF_AWR_RRD_RRD);
    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_A(instruction ins, emitAttr attr, regNumber reg1, GenTreeIndir* indir, insOpts instOptions)
{
    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmd(attr, offs);

    id->idIns(ins);
    id->idReg1(reg1);

    emitHandleMemOp(indir, id, emitInsModeFormat(ins, IF_RRD_ARD), ins);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_A_I(
    instruction ins, emitAttr attr, regNumber reg1, GenTreeIndir* indir, int ival, insOpts instOptions)
{
    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), reg1));
    assert(IsSimdInstruction(ins));

    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmdCns(attr, offs, ival);

    id->idIns(ins);
    id->idReg1(reg1);

    emitHandleMemOp(indir, id, emitInsModeFormat(ins, IF_RRD_ARD_CNS), ins);

    code_t code = 0;

    if (hasCodeMI(ins))
    {
        code = insCodeMI(ins);
    }
    else
    {
        code = insCodeRM(ins);
    }

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, code, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_C_I(instruction          ins,
                            emitAttr             attr,
                            regNumber            reg1,
                            CORINFO_FIELD_HANDLE fldHnd,
                            int                  offs,
                            int                  ival,
                            insOpts              instOptions)
{
    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), reg1));
    assert(IsSimdInstruction(ins));

    instrDesc* id = emitNewInstrCnsDsp(attr, ival, offs);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_RRD_MRD_CNS));
    id->idReg1(reg1);
    id->idAddr()->iiaFieldHnd = fldHnd;

    code_t code = 0;

    if (hasCodeMI(ins))
    {
        code = insCodeMI(ins);
    }
    else
    {
        code = insCodeRM(ins);
    }

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeCV(id, code, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_S_I(
    instruction ins, emitAttr attr, regNumber reg1, int varx, int offs, int ival, insOpts instOptions)
{
    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), reg1));
    assert(IsSimdInstruction(ins));

    instrDesc* id = emitNewInstrCns(attr, ival);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_RRD_SRD_CNS));
    id->idReg1(reg1);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif

    code_t code = 0;

    if (hasCodeMI(ins))
    {
        code = insCodeMI(ins);
    }
    else
    {
        code = insCodeRM(ins);
    }

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeSV(id, code, varx, offs, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_A(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, GenTreeIndir* indir, insOpts instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmd(attr, offs);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);

    emitHandleMemOp(indir, id, (ins == INS_mulx) ? IF_RWR_RWR_ARD : emitInsModeFormat(ins, IF_RRD_RRD_ARD), ins);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_AR(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber base, int offs)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    instrDesc* id = emitNewInstrAmd(attr, offs);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);

    id->idInsFmt(emitInsModeFormat(ins, IF_RRD_RRD_ARD));
    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// IsAVX2GatherInstruction: return true if the instruction is AVX2 Gather
//
// Arguments:
//    ins - the instruction to check
// Return Value:
//    true if the instruction is AVX2 Gather
//
bool IsAVX2GatherInstruction(instruction ins)
{
    switch (ins)
    {
        case INS_vpgatherdd:
        case INS_vpgatherdq:
        case INS_vpgatherqd:
        case INS_vpgatherqq:
        case INS_vgatherdps:
        case INS_vgatherdpd:
        case INS_vgatherqps:
        case INS_vgatherqpd:
            return true;
        default:
            return false;
    }
}

//------------------------------------------------------------------------
// emitIns_R_AR_R: Emits an AVX2 Gather instructions
//
// Arguments:
//    ins - the instruction to emit
//    attr - the instruction operand size
//    reg1 - the destination and first source operand
//    reg2 - the mask operand (encoded in VEX.vvvv)
//    base - the base register of address to load
//    index - the index register of VSIB
//    scale - the scale number of VSIB
//    offs - the offset added to the memory address from base
//
void emitter::emitIns_R_AR_R(instruction ins,
                             emitAttr    attr,
                             regNumber   reg1,
                             regNumber   reg2,
                             regNumber   base,
                             regNumber   index,
                             int         scale,
                             int         offs)
{
    assert(IsAVX2GatherInstruction(ins));

    instrDesc* id = emitNewInstrAmd(attr, offs);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);

    id->idInsFmt(emitInsModeFormat(ins, IF_RRD_ARD_RRD));
    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = index;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeSize((emitAttr)scale);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_C(instruction          ins,
                            emitAttr             attr,
                            regNumber            reg1,
                            regNumber            reg2,
                            CORINFO_FIELD_HANDLE fldHnd,
                            int                  offs,
                            insOpts              instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    instrDesc* id = emitNewInstrDsp(attr, offs);

    id->idIns(ins);
    id->idInsFmt((ins == INS_mulx) ? IF_RWR_RWR_MRD : emitInsModeFormat(ins, IF_RRD_RRD_MRD));
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idAddr()->iiaFieldHnd = fldHnd;

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeCV(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with three register operands.
 */

void emitter::emitIns_R_R_R(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber reg1, regNumber reg2, insOpts instOptions)
{
    assert(IsSimdInstruction(ins) || IsApxExtendedEvexInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins) || IsKInstruction(ins) || IsApxExtendedEvexInstruction(ins));

    // Checking EVEX.ND and NDD compatibility together in case the ND slot is overridden by other features.
    bool useNDD = ((instOptions & INS_OPTS_EVEX_nd_MASK) != 0) && IsApxNddEncodableInstruction(ins);

    instrDesc* id = emitNewInstr(attr);
    id->idIns(ins);
    id->idInsFmt((ins == INS_mulx) ? IF_RWR_RWR_RRD : emitInsModeFormat(ins, IF_RRD_RRD_RRD, useNDD));
    id->idReg1(targetReg);
    id->idReg2(reg1);
    id->idReg3(reg2);

    SetEvexEmbRoundIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);
    SetEvexNdIfNeeded(id, instOptions);
    SetEvexNfIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeRR(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_S(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, int varx, int offs, insOpts instOptions)
{
    assert(IsSimdInstruction(ins) || IsApxExtendedEvexInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins) || IsApxExtendedEvexInstruction(ins));

    instrDesc* id = emitNewInstr(attr);

    // Checking EVEX.ND and NDD compatibility together in case the ND slot is overridden by other features.
    bool useNDD = ((instOptions & INS_OPTS_EVEX_nd_MASK) != 0) && IsApxNddEncodableInstruction(ins);

    id->idIns(ins);
    id->idInsFmt((ins == INS_mulx) ? IF_RWR_RWR_SRD : emitInsModeFormat(ins, IF_RRD_RRD_SRD, useNDD));
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);
    SetEvexNdIfNeeded(id, instOptions);

#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeRM(ins), varx, offs);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_A_I(instruction   ins,
                              emitAttr      attr,
                              regNumber     reg1,
                              regNumber     reg2,
                              GenTreeIndir* indir,
                              int           ival,
                              insFormat     fmt,
                              insOpts       instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmdCns(attr, offs, ival);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);

    emitHandleMemOp(indir, id, fmt, ins);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_AR_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber base, int offs, int ival)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    instrDesc* id = emitNewInstrAmdCns(attr, offs, ival);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);

    id->idInsFmt(IF_RWR_RRD_ARD_CNS);
    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_C_I(instruction          ins,
                              emitAttr             attr,
                              regNumber            reg1,
                              regNumber            reg2,
                              CORINFO_FIELD_HANDLE fldHnd,
                              int                  offs,
                              int                  ival,
                              insOpts              instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    instrDesc* id = emitNewInstrCnsDsp(attr, ival, offs);

    id->idIns(ins);
    id->idInsFmt(IF_RWR_RRD_MRD_CNS);
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idAddr()->iiaFieldHnd = fldHnd;

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeCV(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/**********************************************************************************
 * emitIns_R_R_R_I: Add an instruction with three register operands and an immediate.
 *
 * Arguments:
 *    ins         - the instruction to add
 *    attr        - the emitter attribute for instruction
 *    targetReg   - the target (destination) register
 *    reg1        - the first source register
 *    reg2        - the second source register
 *    ival        - the immediate value
 *    instOptions - the options that modify how the instruction is generated
 */

void emitter::emitIns_R_R_R_I(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber reg1, regNumber reg2, int ival, insOpts instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    instrDesc* id = emitNewInstrCns(attr, ival);
    id->idIns(ins);
    id->idInsFmt(IF_RWR_RRD_RRD_CNS);
    id->idReg1(targetReg);
    id->idReg2(reg1);
    id->idReg3(reg2);

    assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeRR(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_S_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, int varx, int offs, int ival, insOpts instOptions)
{
    assert(IsSimdInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins));

    instrDesc* id = emitNewInstrCns(attr, ival);

    id->idIns(ins);
    id->idInsFmt(IF_RWR_RRD_SRD_CNS);
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeRM(ins), varx, offs, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_R_R_A_R: emits the code for an instruction that takes a register operand, a GenTreeIndir address,
//                  another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    indir       -- The GenTreeIndir used for the memory address
//    instOptions -- The options that modify how the instruction is generated
//
// Remarks:
//    op2 is built from indir
//
void emitter::emitIns_R_R_A_R(instruction   ins,
                              emitAttr      attr,
                              regNumber     targetReg,
                              regNumber     op1Reg,
                              regNumber     op3Reg,
                              GenTreeIndir* indir,
                              insOpts       instOptions)
{
    assert(isAvxBlendv(ins) || isAvx512Blendv(ins));
    assert(UseSimdEncoding());

    int8_t     ival = encodeRegAsIval(op3Reg);
    ssize_t    offs = indir->Offset();
    instrDesc* id   = emitNewInstrAmdCns(attr, offs, ival);

    id->idIns(ins);
    id->idReg1(targetReg);
    id->idReg2(op1Reg);

    emitHandleMemOp(indir, id, IF_RWR_RRD_ARD_RRD, ins);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_R_R_C_R: emits the code for an instruction that takes a register operand, a field handle +
//                  offset,  another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    instOptions -- The options that modify how the instruction is generated
//
// Remarks:
//    op2 is built from fldHnd + offs
//
void emitter::emitIns_R_R_C_R(instruction          ins,
                              emitAttr             attr,
                              regNumber            targetReg,
                              regNumber            op1Reg,
                              regNumber            op3Reg,
                              CORINFO_FIELD_HANDLE fldHnd,
                              int                  offs,
                              insOpts              instOptions)
{
    assert(isAvxBlendv(ins) || isAvx512Blendv(ins));
    assert(UseSimdEncoding());

    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    int8_t     ival = encodeRegAsIval(op3Reg);
    instrDesc* id   = emitNewInstrCnsDsp(attr, ival, offs);

    id->idIns(ins);
    id->idReg1(targetReg);
    id->idReg2(op1Reg);

    id->idInsFmt(IF_RWR_RRD_MRD_RRD);
    id->idAddr()->iiaFieldHnd = fldHnd;

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeCV(id, insCodeRM(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_R_R_S_R: emits the code for a instruction that takes a register operand, a variable index +
//                  offset, another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    instOptions -- The options that modify how the instruction is generated
//
// Remarks:
//    op2 is built from varx + offs
//
void emitter::emitIns_R_R_S_R(instruction ins,
                              emitAttr    attr,
                              regNumber   targetReg,
                              regNumber   op1Reg,
                              regNumber   op3Reg,
                              int         varx,
                              int         offs,
                              insOpts     instOptions)
{
    assert(isAvxBlendv(ins) || isAvx512Blendv(ins));
    assert(UseSimdEncoding());

    int8_t     ival = encodeRegAsIval(op3Reg);
    instrDesc* id   = emitNewInstrCns(attr, ival);

    id->idIns(ins);
    id->idReg1(targetReg);
    id->idReg2(op1Reg);

    id->idInsFmt(IF_RWR_RRD_SRD_RRD);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeRM(ins), varx, offs, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_R_R_R(instruction ins,
                              emitAttr    attr,
                              regNumber   targetReg,
                              regNumber   reg1,
                              regNumber   reg2,
                              regNumber   reg3,
                              insOpts     instOptions)
{
    assert(isAvxBlendv(ins) || isAvx512Blendv(ins));
    assert(UseSimdEncoding());

    instrDesc* id = emitNewInstr(attr);

    id->idIns(ins);
    id->idInsFmt(IF_RWR_RRD_RRD_RRD);
    id->idReg1(targetReg);
    id->idReg2(reg1);
    id->idReg3(reg2);
    id->idReg4(reg3);

    assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeRR(id, insCodeRM(ins));

    if (!isMaskReg(reg3))
    {
        // The 4th register is encoded as an 8-bit ival
        sz += 1;
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with a register + static member operands.
 */
void emitter::emitIns_R_C(
    instruction ins, emitAttr attr, regNumber reg, CORINFO_FIELD_HANDLE fldHnd, int offs, insOpts instOptions)
{
    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    emitAttr size = EA_SIZE(attr);

    assert(size <= EA_64BYTE);
    noway_assert(emitVerifyEncodable(ins, size, reg));

    UNATIVE_OFFSET sz;
    instrDesc*     id;

    // Are we MOV'ing the offset of the class variable into EAX?
    if (EA_IS_OFFSET(attr))
    {
        id = emitNewInstrDsp(EA_1BYTE, offs);
        id->idIns(ins);
        id->idInsFmt(IF_RWR_MRD_OFF);
        id->idReg1(reg);

        assert(ins == INS_mov && reg == REG_EAX);

        // Special case: "mov eax, [addr]" is smaller
        sz = 1 + TARGET_POINTER_SIZE;
    }
    else
    {
        insFormat fmt = emitInsModeFormat(ins, IF_RRD_MRD);

        id = emitNewInstrDsp(attr, offs);
        id->idIns(ins);
        id->idInsFmt(fmt);
        id->idReg1(reg);

#ifdef TARGET_X86
        // Special case: "mov eax, [addr]" is smaller.
        // This case is not enabled for amd64 as it always uses RIP relative addressing
        // and it results in smaller instruction size than encoding 64-bit addr in the
        // instruction.
        if (ins == INS_mov && reg == REG_EAX)
        {
            sz = 1 + TARGET_POINTER_SIZE;
            if (size == EA_2BYTE)
                sz += 1;
        }
        else
#endif // TARGET_X86
        {
            SetEvexBroadcastIfNeeded(id, instOptions);
            SetEvexEmbMaskIfNeeded(id, instOptions);
            SetEvexDFVIfNeeded(id, instOptions);

            sz = emitInsSizeCV(id, insCodeRM(ins));
        }

        // Special case: mov reg, fs:[ddd]
        if (fldHnd == FLD_GLOBAL_FS)
        {
            sz += 1;
        }
        else if (fldHnd == FLD_GLOBAL_GS)
        {
            sz += 2; // Needs SIB byte as well.
        }
    }

    id->idCodeSize(sz);

    id->idAddr()->iiaFieldHnd = fldHnd;

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with a static member + register operands.
 */

void emitter::emitIns_C_R(instruction ins, emitAttr attr, CORINFO_FIELD_HANDLE fldHnd, regNumber reg, int offs)
{
    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    emitAttr size = EA_SIZE(attr);

#if defined(TARGET_X86)
    // For x86 it is valid to storeind a double sized operand in an xmm reg to memory
    assert(size <= EA_8BYTE);
#else
    assert(size <= EA_PTRSIZE);
#endif

    noway_assert(emitVerifyEncodable(ins, size, reg));

    instrDesc* id  = emitNewInstrDsp(attr, offs);
    insFormat  fmt = (ins == INS_xchg) ? IF_MRW_RRW : emitInsModeFormat(ins, IF_MRD_RRD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(reg);

    UNATIVE_OFFSET sz;

#ifdef TARGET_X86
    // Special case: "mov [addr], EAX" is smaller.
    // This case is not enable for amd64 as it always uses RIP relative addressing
    // and it will result in smaller instruction size than encoding 64-bit addr in
    // the instruction.
    if (ins == INS_mov && reg == REG_EAX)
    {
        sz = 1 + TARGET_POINTER_SIZE;

        if (size == EA_2BYTE)
            sz += 1;

        // REX prefix
        if (TakesRexWPrefix(id) || IsExtendedReg(reg, attr))
        {
            sz += emitGetRexPrefixSize(id, ins);
        }
    }
    else
#endif // TARGET_X86
    {
        sz = emitInsSizeCV(id, insCodeMR(ins));
    }

    // Special case: mov reg, fs:[ddd]
    if ((fldHnd == FLD_GLOBAL_FS) || (fldHnd == FLD_GLOBAL_GS))
    {
        sz += 1;
    }

    id->idCodeSize(sz);

    id->idAddr()->iiaFieldHnd = fldHnd;

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add an instruction with a static member + constant.
 */

void emitter::emitIns_C_I(instruction ins, emitAttr attr, CORINFO_FIELD_HANDLE fldHnd, int offs, int val)
{
    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_MRW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_MRD_CNS);
            break;
    }

    instrDesc* id = emitNewInstrCnsDsp(attr, val, offs);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idAddr()->iiaFieldHnd = fldHnd;

    code_t         code = insCodeMI(ins);
    UNATIVE_OFFSET sz   = emitInsSizeCV(id, code, val);

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_J_S(instruction ins, emitAttr attr, BasicBlock* dst, int varx, int offs)
{
    assert(ins == INS_mov);
    assert(dst->HasFlag(BBF_HAS_LABEL));

    instrDescLbl* id = emitNewInstrLbl();

    id->idIns(ins);
    id->idInsFmt(IF_SWR_LABEL);
    id->idAddr()->iiaBBlabel = dst;

    /* The label reference is always long */

    id->idjShort    = 0;
    id->idjKeepLong = 1;

    /* Record the current IG and offset within it */

    id->idjIG   = emitCurIG;
    id->idjOffs = emitCurIGsize;

    /* Append this instruction to this IG's jump list */

    id->idjNext      = emitCurIGjmpList;
    emitCurIGjmpList = id;

    UNATIVE_OFFSET sz = sizeof(INT32) + emitInsSizeSV(id, insCodeMI(ins), varx, offs);
    id->dstLclVar.initLclVarAddr(varx, offs);
#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif

#if EMITTER_STATS
    emitTotalIGjmps++;
#endif

#ifndef TARGET_AMD64
    // Storing the address of a basicBlock will need a reloc
    // as the instruction uses the absolute address,
    // not a relative address.
    //
    // On Amd64, Absolute code addresses should always go through a reloc to
    // to be encoded as RIP rel32 offset.
    if (emitComp->opts.compReloc)
#endif
    {
        id->idSetIsDspReloc();
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Add a label instruction.
 */
void emitter::emitIns_R_L(instruction ins, emitAttr attr, BasicBlock* dst, regNumber reg)
{
    assert(ins == INS_lea);
    assert(dst->HasFlag(BBF_HAS_LABEL));

    instrDescJmp* id = emitNewInstrJmp();

    id->idIns(ins);
    id->idReg1(reg);
    id->idInsFmt(IF_RWR_LABEL);
    id->idOpSize(EA_SIZE(attr)); // emitNewInstrJmp() sets the size (incorrectly) to EA_1BYTE
    id->idAddr()->iiaBBlabel = dst;

    /* The label reference is always long */

    id->idjShort    = 0;
    id->idjKeepLong = 1;

    /* Record the current IG and offset within it */

    id->idjIG   = emitCurIG;
    id->idjOffs = emitCurIGsize;

    /* Append this instruction to this IG's jump list */

    id->idjNext      = emitCurIGjmpList;
    emitCurIGjmpList = id;

#ifdef DEBUG
    // Mark the catch return
    if (emitComp->compCurBB->KindIs(BBJ_EHCATCHRET))
    {
        id->idDebugOnlyInfo()->idCatchRet = true;
    }
#endif // DEBUG

#if EMITTER_STATS
    emitTotalIGjmps++;
#endif

    // Set the relocation flags - these give hint to zap to perform
    // relocation of the specified 32bit address.
    //
    // Note the relocation flags influence the size estimate.
    id->idSetRelocFlags(attr);

    UNATIVE_OFFSET sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  The following adds instructions referencing address modes.
 */

void emitter::emitIns_I_AR(instruction ins, emitAttr attr, int val, regNumber reg, int disp, insOpts instOptions)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_ARW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
            break;
    }

    /*
    Useful if you want to trap moves with 0 constant
    if (ins == INS_mov && val == 0 && EA_SIZE(attr) >= EA_4BYTE)
    {
        printf("MOV 0\n");
    }
    */

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmdCns(attr, disp, val);
    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = reg;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;
    if ((instOptions & INS_OPTS_EVEX_NoApxPromotion) != 0)
    {
        id->idSetNoApxEvexPromotion();
    }

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMI(ins), val);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_I_AI(instruction ins, emitAttr attr, int val, ssize_t disp)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_ARW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
            break;
    }

    /*
    Useful if you want to trap moves with 0 constant
    if (ins == INS_mov && val == 0 && EA_SIZE(attr) >= EA_4BYTE)
    {
        printf("MOV 0\n");
    }
    */

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmdCns(attr, disp, val);
    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMI(ins), val);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_AR(instruction ins, emitAttr attr, regNumber reg, regNumber base, int disp)
{
    emitIns_R_ARX(ins, attr, reg, base, REG_NA, 1, disp);
}

void emitter::emitIns_R_AI(instruction  ins,
                           emitAttr     attr,
                           regNumber    ireg,
                           ssize_t disp DEBUGARG(size_t targetHandle) DEBUGARG(GenTreeFlags gtFlags))
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE) && (ireg != REG_NA));
    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), ireg));

    UNATIVE_OFFSET sz;
    instrDesc*     id  = emitNewInstrAmd(attr, disp);
    insFormat      fmt = emitInsModeFormat(ins, IF_RRD_ARD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(ireg);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;
    if (EA_IS_CNS_TLSGD_RELOC(attr))
    {
        id->idSetTlsGD();
    }

#ifdef DEBUG
    id->idDebugOnlyInfo()->idFlags     = gtFlags;
    id->idDebugOnlyInfo()->idMemCookie = targetHandle;
#endif

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_AR_R(
    instruction ins, emitAttr attr, regNumber reg, regNumber base, cnsval_ssize_t disp, insOpts instOptions)
{
    emitIns_ARX_R(ins, attr, reg, base, REG_NA, 1, disp, instOptions);
}

//------------------------------------------------------------------------
// emitIns_C_R_I: emits the code for an instruction that takes a static member,
//                a register operand, and an immediate.
//
// Arguments:
//    ins       - The instruction being emitted
//    attr      - The emit attribute
//    fldHnd    - The CORINFO_FIELD_HANDLE used for the memory address
//    offs      - The offset for the stack operand
//    reg       - The register operand
//    ival      - The immediate value
//
void emitter::emitIns_C_R_I(
    instruction ins, emitAttr attr, CORINFO_FIELD_HANDLE fldHnd, int offs, regNumber reg, int ival)
{
    assert(IsSimdInstruction(ins));
    assert(reg != REG_NA);

    // Static always need relocs
    if (!jitStaticFldIsGlobAddr(fldHnd))
    {
        attr = EA_SET_FLG(attr, EA_DSP_RELOC_FLG);
    }

    instrDesc* id = emitNewInstrCnsDsp(attr, ival, offs);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_MRD_RRD_CNS));
    id->idReg1(reg);
    id->idAddr()->iiaFieldHnd = fldHnd;

    UNATIVE_OFFSET sz = emitInsSizeCV(id, insCodeMR(ins), ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_S_R_I: emits the code for an instruction that takes a stack operand,
//                a register operand, and an immediate.
//
// Arguments:
//    ins       - The instruction being emitted
//    attr      - The emit attribute
//    varNum    - The varNum of the stack operand
//    offs      - The offset for the stack operand
//    reg       - The register operand
//    ival      - The immediate value
//
void emitter::emitIns_S_R_I(instruction ins, emitAttr attr, int varNum, int offs, regNumber reg, int ival)
{
    assert(IsSimdInstruction(ins));
    assert(reg != REG_NA);

    instrDesc* id = emitNewInstrAmdCns(attr, 0, ival);

    id->idIns(ins);
    id->idInsFmt(emitInsModeFormat(ins, IF_SRD_RRD_CNS));
    id->idReg1(reg);
    id->idAddr()->iiaLclVar.initLclVarAddr(varNum, offs);
#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeMR(ins), varNum, offs, ival);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

//------------------------------------------------------------------------
// emitIns_A_R_I: emits the code for an instruction that takes an address,
//                a register operand, and an immediate.
//
// Arguments:
//    ins       - The instruction being emitted
//    attr      - The emit attribute
//    indir     - The GenTreeIndir used for the memory address
//    reg       - The register operand
//    ival      - The immediate value
//
void emitter::emitIns_A_R_I(instruction ins, emitAttr attr, GenTreeIndir* indir, regNumber reg, int imm)
{
    assert(IsSimdInstruction(ins));
    assert(reg != REG_NA);

    instrDesc* id = emitNewInstrAmdCns(attr, indir->Offset(), imm);
    id->idIns(ins);
    id->idReg1(reg);
    emitHandleMemOp(indir, id, emitInsModeFormat(ins, IF_ARD_RRD_CNS), ins);
    UNATIVE_OFFSET size = emitInsSizeAM(id, insCodeMR(ins), imm);
    id->idCodeSize(size);
    dispIns(id);
    emitCurIGsize += size;
}

void emitter::emitIns_AI_R(instruction ins, emitAttr attr, regNumber ireg, ssize_t disp)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmd(attr, disp);
    insFormat      fmt;

    if (ireg == REG_NA)
    {
        fmt = emitInsModeFormat(ins, IF_ARD);
    }
    else
    {
        fmt = emitInsModeFormat(ins, IF_ARD_RRD);

        assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));
        noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), ireg));

        id->idReg1(ireg);
    }

    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = REG_NA;

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

void emitter::emitIns_I_ARR(instruction ins, emitAttr attr, int val, regNumber reg, regNumber rg2, int disp)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_ARW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
            break;
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmdCns(attr, disp, val);
    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = reg;
    id->idAddr()->iiaAddrMode.amIndxReg = rg2;
    id->idAddr()->iiaAddrMode.amScale   = emitter::OPSZ1;

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMI(ins), val);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_ARR(instruction ins, emitAttr attr, regNumber reg, regNumber base, regNumber index, int disp)
{
    emitIns_R_ARX(ins, attr, reg, base, index, 1, disp);
}

void emitter::emitIns_ARR_R(instruction ins, emitAttr attr, regNumber reg, regNumber base, regNumber index, int disp)
{
    emitIns_ARX_R(ins, attr, reg, base, index, 1, disp);
}

void emitter::emitIns_I_ARX(
    instruction ins, emitAttr attr, int val, regNumber reg, regNumber rg2, unsigned mul, int disp)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_ARW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
            break;
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmdCns(attr, disp, val);

    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = reg;
    id->idAddr()->iiaAddrMode.amIndxReg = rg2;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(mul);

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMI(ins), val);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_ARX(
    instruction ins, emitAttr attr, regNumber reg, regNumber base, regNumber index, unsigned scale, int disp)
{
    assert(!CodeGen::instIsFP(ins) && (EA_SIZE(attr) <= EA_64BYTE) && (reg != REG_NA));
    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), reg));

    if ((ins == INS_lea) && (reg == base) && (index == REG_NA) && (disp == 0))
    {
        // Maybe the emitter is not the common place for this optimization, but it's a better choke point
        // for all the emitIns(ins, tree), we would have to be analyzing at each call site
        //
        return;
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id  = emitNewInstrAmd(attr, disp);
    insFormat      fmt = emitInsModeFormat(ins, IF_RRD_ARD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(reg);

    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = index;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(scale);

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_ARX_R(instruction    ins,
                            emitAttr       attr,
                            regNumber      reg,
                            regNumber      base,
                            regNumber      index,
                            unsigned       scale,
                            cnsval_ssize_t disp,
                            insOpts        instOptions)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmd(attr, disp);
    insFormat      fmt;

    if (reg == REG_NA)
    {
        fmt = emitInsModeFormat(ins, IF_ARD);
    }
    else
    {
        fmt = (ins == INS_xchg) ? IF_ARW_RRW : emitInsModeFormat(ins, IF_ARD_RRD);

        noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), reg));
        assert(!CodeGen::instIsFP(ins) && (EA_SIZE(attr) <= EA_64BYTE));

        id->idReg1(reg);
    }

    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = base;
    id->idAddr()->iiaAddrMode.amIndxReg = index;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(scale);
    if ((instOptions & INS_OPTS_EVEX_NoApxPromotion) != 0)
    {
        id->idSetNoApxEvexPromotion();
    }

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

void emitter::emitIns_I_AX(instruction ins, emitAttr attr, int val, regNumber reg, unsigned mul, int disp)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_ARW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_ARD_CNS);
            break;
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmdCns(attr, disp, val);
    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = reg;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(mul);

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMI(ins), val);
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_AX(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, unsigned mul, int disp)
{
    assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE) && (ireg != REG_NA));
    noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), ireg));

    UNATIVE_OFFSET sz;
    instrDesc*     id  = emitNewInstrAmd(attr, disp);
    insFormat      fmt = emitInsModeFormat(ins, IF_RRD_ARD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(ireg);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = reg;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(mul);

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeRM(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_AX_R(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, unsigned mul, int disp)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstrAmd(attr, disp);
    insFormat      fmt;

    if (ireg == REG_NA)
    {
        fmt = emitInsModeFormat(ins, IF_ARD);
    }
    else
    {
        fmt = (ins == INS_xchg) ? IF_ARW_RRW : emitInsModeFormat(ins, IF_ARD_RRD);
        noway_assert(emitVerifyEncodable(ins, EA_SIZE(attr), ireg));
        assert((CodeGen::instIsFP(ins) == false) && (EA_SIZE(attr) <= EA_8BYTE));

        id->idReg1(ireg);
    }

    id->idIns(ins);
    id->idInsFmt(fmt);

    id->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
    id->idAddr()->iiaAddrMode.amIndxReg = reg;
    id->idAddr()->iiaAddrMode.amScale   = emitEncodeScale(mul);

    assert(emitGetInsAmdAny(id) == disp); // make sure "disp" is stored properly

    sz = emitInsSizeAM(id, insCodeMR(ins));
    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_I: emits the code for an instruction that takes a register operand, an immediate operand
//                     and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
// Notes:
//    This will handle the required register copy if 'op1Reg' and 'targetReg' are not the same, and
//    the 3-operand format is not available.
//    This is not really SIMD-specific, but is currently only used in that context, as that's
//    where we frequently need to handle the case of generating 3-operand or 2-operand forms
//    depending on what target ISA is supported.
//
void emitter::emitIns_SIMD_R_R_I(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber op1Reg, int ival, insOpts instOptions)
{
    if (UseSimdEncoding() || IsDstSrcImmAvxInstruction(ins))
    {
        emitIns_R_R_I(ins, attr, targetReg, op1Reg, ival, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_I(ins, attr, targetReg, ival);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_A: emits the code for a SIMD instruction that takes a register operand, a GenTreeIndir address,
//                     and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    indir       -- The GenTreeIndir used for the memory address
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_A(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber op1Reg, GenTreeIndir* indir, insOpts instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_A(ins, attr, targetReg, op1Reg, indir, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_A(ins, attr, targetReg, indir);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_C: emits the code for a SIMD instruction that takes a register operand, a field handle + offset,
//                     and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_C(instruction          ins,
                                 emitAttr             attr,
                                 regNumber            targetReg,
                                 regNumber            op1Reg,
                                 CORINFO_FIELD_HANDLE fldHnd,
                                 int                  offs,
                                 insOpts              instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_C(ins, attr, targetReg, op1Reg, fldHnd, offs, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_C(ins, attr, targetReg, fldHnd, offs);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R: emits the code for a SIMD instruction that takes two register operands, and that returns a
//                     value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber op1Reg, regNumber op2Reg, insOpts instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_R(ins, attr, targetReg, op1Reg, op2Reg, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op2
        assert((op2Reg != targetReg) || (op1Reg == targetReg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);

        if (IsMovInstruction(ins))
        {
            emitIns_Mov(ins, attr, targetReg, op2Reg, /* canSkip */ false);
        }
        else
        {
            emitIns_R_R(ins, attr, targetReg, op2Reg);
        }
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_S: emits the code for a SIMD instruction that takes a register operand, a variable index + offset,
//                     and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_S(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber op1Reg, int varx, int offs, insOpts instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_S(ins, attr, targetReg, op1Reg, varx, offs, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_S(ins, attr, targetReg, varx, offs);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_A_I: emits the code for a SIMD instruction that takes a register operand, a GenTreeIndir address,
//                       an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    indir       -- The GenTreeIndir used for the memory address
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_A_I(instruction   ins,
                                   emitAttr      attr,
                                   regNumber     targetReg,
                                   regNumber     op1Reg,
                                   GenTreeIndir* indir,
                                   int           ival,
                                   insOpts       instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_A_I(ins, attr, targetReg, op1Reg, indir, ival, IF_RWR_RRD_ARD_CNS, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_A_I(ins, attr, targetReg, indir, ival);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_C_I: emits the code for a SIMD instruction that takes a register operand, a field handle + offset,
//                       an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_C_I(instruction          ins,
                                   emitAttr             attr,
                                   regNumber            targetReg,
                                   regNumber            op1Reg,
                                   CORINFO_FIELD_HANDLE fldHnd,
                                   int                  offs,
                                   int                  ival,
                                   insOpts              instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_C_I(ins, attr, targetReg, op1Reg, fldHnd, offs, ival, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_C_I(ins, attr, targetReg, fldHnd, offs, ival);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_I: emits the code for a SIMD instruction that takes two register operands, an immediate operand,
//                       and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_I(instruction ins,
                                   emitAttr    attr,
                                   regNumber   targetReg,
                                   regNumber   op1Reg,
                                   regNumber   op2Reg,
                                   int         ival,
                                   insOpts     instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_R_I(ins, attr, targetReg, op1Reg, op2Reg, ival, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op2
        assert((op2Reg != targetReg) || (op1Reg == targetReg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_R_I(ins, attr, targetReg, op2Reg, ival);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_S_I: emits the code for a SIMD instruction that takes a register operand, a variable index + offset,
//                       an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_S_I(instruction ins,
                                   emitAttr    attr,
                                   regNumber   targetReg,
                                   regNumber   op1Reg,
                                   int         varx,
                                   int         offs,
                                   int         ival,
                                   insOpts     instOptions)
{
    if (UseSimdEncoding())
    {
        emitIns_R_R_S_I(ins, attr, targetReg, op1Reg, varx, offs, ival, instOptions);
    }
    else
    {
        assert(instOptions == INS_OPTS_NONE);
        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_S_I(ins, attr, targetReg, varx, offs, ival);
    }
}

#ifdef FEATURE_HW_INTRINSICS
//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_A: emits the code for a SIMD instruction that takes two register operands, a GenTreeIndir address,
//                       and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    indir       -- The GenTreeIndir used for the memory address
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_A(instruction   ins,
                                   emitAttr      attr,
                                   regNumber     targetReg,
                                   regNumber     op1Reg,
                                   regNumber     op2Reg,
                                   GenTreeIndir* indir,
                                   insOpts       instOptions)
{
    assert(Is3OpRmwInstruction(ins));
    assert(UseSimdEncoding());

    // Ensure we aren't overwriting op2
    assert((op2Reg != targetReg) || (op1Reg == targetReg));

    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_A(ins, attr, targetReg, op2Reg, indir, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_C: emits the code for a SIMD instruction that takes two register operands, a field handle +
//                       offset, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_C(instruction          ins,
                                   emitAttr             attr,
                                   regNumber            targetReg,
                                   regNumber            op1Reg,
                                   regNumber            op2Reg,
                                   CORINFO_FIELD_HANDLE fldHnd,
                                   int                  offs,
                                   insOpts              instOptions)
{
    assert(Is3OpRmwInstruction(ins));
    assert(UseSimdEncoding());

    // Ensure we aren't overwriting op2
    assert((op2Reg != targetReg) || (op1Reg == targetReg));

    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_C(ins, attr, targetReg, op2Reg, fldHnd, offs, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_R: emits the code for a SIMD instruction that takes three register operands, and that returns a
//                     value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    op3Reg      -- The register of the second operand
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_R(instruction ins,
                                   emitAttr    attr,
                                   regNumber   targetReg,
                                   regNumber   op1Reg,
                                   regNumber   op2Reg,
                                   regNumber   op3Reg,
                                   insOpts     instOptions)
{
    if (Is3OpRmwInstruction(ins))
    {
        assert(UseSimdEncoding());

        if (instOptions != INS_OPTS_NONE)
        {
            // insOpts is currently available only in EVEX encoding.
            assert(UseEvexEncoding());
        }

        // Ensure we aren't overwriting op2 or op3
        assert((op2Reg != targetReg) || (op1Reg == targetReg));
        assert((op3Reg != targetReg) || (op1Reg == targetReg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_R_R(ins, attr, targetReg, op2Reg, op3Reg, instOptions);
    }
    else if (UseSimdEncoding())
    {
        assert(isSse41Blendv(ins) || isAvxBlendv(ins) || isAvx512Blendv(ins));

        // convert SSE encoding of SSE4.1 instructions to VEX encoding
        switch (ins)
        {
            case INS_blendvps:
                ins = INS_vblendvps;
                break;
            case INS_blendvpd:
                ins = INS_vblendvpd;
                break;
            case INS_pblendvb:
                ins = INS_vpblendvb;
                break;
            default:
                break;
        }
        emitIns_R_R_R_R(ins, attr, targetReg, op1Reg, op2Reg, op3Reg, instOptions);
    }
    else
    {
        assert(isSse41Blendv(ins));
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op1 or op2
        assert((op1Reg != REG_XMM0) || (op3Reg == REG_XMM0));
        assert((op2Reg != REG_XMM0) || (op3Reg == REG_XMM0));

        // SSE4.1 blendv* hardcode the mask vector (op3) in XMM0
        emitIns_Mov(INS_movaps, attr, REG_XMM0, op3Reg, /* canSkip */ true);

        // Ensure we aren't overwriting op2 or op3 (which should be REG_XMM0)
        assert((op2Reg != targetReg) || (op1Reg == targetReg));

        // If targetReg == REG_XMM0, it means that op3 was last use and we decided to
        // reuse REG_XMM0 for destination i.e. targetReg. In such case, make sure
        // that XMM0 value after the (op3Reg -> XMM0) move done above is not
        // overwritten by op1Reg.
        assert((targetReg != REG_XMM0) || (op1Reg == op3Reg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_R(ins, attr, targetReg, op2Reg);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_S: emits the code for a SIMD instruction that takes two register operands, a variable index +
//                       offset, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_S(instruction ins,
                                   emitAttr    attr,
                                   regNumber   targetReg,
                                   regNumber   op1Reg,
                                   regNumber   op2Reg,
                                   int         varx,
                                   int         offs,
                                   insOpts     instOptions)
{
    assert(Is3OpRmwInstruction(ins));
    assert(UseSimdEncoding());

    // Ensure we aren't overwriting op2
    assert((op2Reg != targetReg) || (op1Reg == targetReg));

    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_S(ins, attr, targetReg, op2Reg, varx, offs, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_A_R: emits the code for a SIMD instruction that takes a register operand, a GenTreeIndir address,
//                       another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    indir       -- The GenTreeIndir used for the memory address
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_A_R(instruction   ins,
                                   emitAttr      attr,
                                   regNumber     targetReg,
                                   regNumber     op1Reg,
                                   regNumber     op3Reg,
                                   GenTreeIndir* indir,
                                   insOpts       instOptions)
{
    if (UseSimdEncoding())
    {
        assert(isSse41Blendv(ins) || isAvxBlendv(ins) || isAvx512Blendv(ins));

        // convert SSE encoding of SSE4.1 instructions to VEX encoding
        switch (ins)
        {
            case INS_blendvps:
            {
                ins = INS_vblendvps;
                break;
            }

            case INS_blendvpd:
            {
                ins = INS_vblendvpd;
                break;
            }

            case INS_pblendvb:
            {
                ins = INS_vpblendvb;
                break;
            }

            default:
            {
                break;
            }
        }

        emitIns_R_R_A_R(ins, attr, targetReg, op1Reg, op3Reg, indir, instOptions);
    }
    else
    {
        assert(isSse41Blendv(ins));
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op1
        assert(op1Reg != REG_XMM0);

        // SSE4.1 blendv* hardcode the mask vector (op3) in XMM0
        emitIns_Mov(INS_movaps, attr, REG_XMM0, op3Reg, /* canSkip */ true);

        // If targetReg == REG_XMM0, it means that op3 was last use and we decided to
        // reuse REG_XMM0 for destination i.e. targetReg. In such case, make sure
        // that XMM0 value after the (op3Reg -> XMM0) move done above is not
        // overwritten by op1Reg.
        assert((targetReg != REG_XMM0) || (op1Reg == op3Reg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_A(ins, attr, targetReg, indir);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_C_R: emits the code for a SIMD instruction that takes a register operand, a field handle +
//                       offset,  another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_C_R(instruction          ins,
                                   emitAttr             attr,
                                   regNumber            targetReg,
                                   regNumber            op1Reg,
                                   regNumber            op3Reg,
                                   CORINFO_FIELD_HANDLE fldHnd,
                                   int                  offs,
                                   insOpts              instOptions)
{
    if (UseSimdEncoding())
    {
        assert(isSse41Blendv(ins) || isAvxBlendv(ins) || isAvx512Blendv(ins));

        // convert SSE encoding of SSE4.1 instructions to VEX encoding
        switch (ins)
        {
            case INS_blendvps:
            {
                ins = INS_vblendvps;
                break;
            }

            case INS_blendvpd:
            {
                ins = INS_vblendvpd;
                break;
            }

            case INS_pblendvb:
            {
                ins = INS_vpblendvb;
                break;
            }

            default:
            {
                break;
            }
        }

        emitIns_R_R_C_R(ins, attr, targetReg, op1Reg, op3Reg, fldHnd, offs, instOptions);
    }
    else
    {
        assert(isSse41Blendv(ins));
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op1
        assert(op1Reg != REG_XMM0);

        // SSE4.1 blendv* hardcode the mask vector (op3) in XMM0
        emitIns_Mov(INS_movaps, attr, REG_XMM0, op3Reg, /* canSkip */ true);

        // If targetReg == REG_XMM0, it means that op3 was last use and we decided to
        // reuse REG_XMM0 for destination i.e. targetReg. In such case, make sure
        // that XMM0 value after the (op3Reg -> XMM0) move done above is not
        // overwritten by op1Reg.
        assert((targetReg != REG_XMM0) || (op1Reg == op3Reg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_C(ins, attr, targetReg, fldHnd, offs);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_S_R: emits the code for a SIMD instruction that takes a register operand, a variable index +
//                       offset, another register operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op3Reg      -- The register of the third operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_S_R(instruction ins,
                                   emitAttr    attr,
                                   regNumber   targetReg,
                                   regNumber   op1Reg,
                                   regNumber   op3Reg,
                                   int         varx,
                                   int         offs,
                                   insOpts     instOptions)
{
    if (UseSimdEncoding())
    {
        assert(isSse41Blendv(ins) || isAvxBlendv(ins) || isAvx512Blendv(ins));

        // convert SSE encoding of SSE4.1 instructions to VEX encoding
        switch (ins)
        {
            case INS_blendvps:
            {
                ins = INS_vblendvps;
                break;
            }

            case INS_blendvpd:
            {
                ins = INS_vblendvpd;
                break;
            }

            case INS_pblendvb:
            {
                ins = INS_vpblendvb;
                break;
            }

            default:
            {
                break;
            }
        }

        emitIns_R_R_S_R(ins, attr, targetReg, op1Reg, op3Reg, varx, offs, instOptions);
    }
    else
    {
        assert(isSse41Blendv(ins));
        assert(instOptions == INS_OPTS_NONE);

        // Ensure we aren't overwriting op1
        assert(op1Reg != REG_XMM0);

        // SSE4.1 blendv* hardcode the mask vector (op3) in XMM0
        emitIns_Mov(INS_movaps, attr, REG_XMM0, op3Reg, /* canSkip */ true);

        // If targetReg == REG_XMM0, it means that op3 was last use and we decided to
        // reuse REG_XMM0 for destination i.e. targetReg. In such case, make sure
        // that XMM0 value after the (op3Reg -> XMM0) move done above is not
        // overwritten by op1Reg.
        assert((targetReg != REG_XMM0) || (op1Reg == op3Reg));

        emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
        emitIns_R_S(ins, attr, targetReg, varx, offs);
    }
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_A_I: emits the code for a SIMD instruction that takes two register operands, a GenTreeIndir
//                         address, an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    indir       -- The GenTreeIndir used for the memory address
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_A_I(instruction   ins,
                                     emitAttr      attr,
                                     regNumber     targetReg,
                                     regNumber     op1Reg,
                                     regNumber     op2Reg,
                                     GenTreeIndir* indir,
                                     int           ival,
                                     insOpts       instOptions)
{
    assert(UseSimdEncoding());
    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_A_I(ins, attr, targetReg, op2Reg, indir, ival, IF_RWR_RRD_ARD_CNS, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_C_I: emits the code for a SIMD instruction that takes two register operands, a field handle +
//                         offset, an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    fldHnd      -- The CORINFO_FIELD_HANDLE used for the memory address
//    offs        -- The offset added to the memory address from fldHnd
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_C_I(instruction          ins,
                                     emitAttr             attr,
                                     regNumber            targetReg,
                                     regNumber            op1Reg,
                                     regNumber            op2Reg,
                                     CORINFO_FIELD_HANDLE fldHnd,
                                     int                  offs,
                                     int                  ival,
                                     insOpts              instOptions)
{
    assert(UseSimdEncoding());
    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_C_I(ins, attr, targetReg, op2Reg, fldHnd, offs, ival, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_R_I: emits the code for a SIMD instruction that takes three register operands, an immediate
//                         operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    op3Reg      -- The register of the third operand
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_R_I(instruction ins,
                                     emitAttr    attr,
                                     regNumber   targetReg,
                                     regNumber   op1Reg,
                                     regNumber   op2Reg,
                                     regNumber   op3Reg,
                                     int         ival,
                                     insOpts     instOptions)
{
    assert(UseSimdEncoding());
    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_R_I(ins, attr, targetReg, op2Reg, op3Reg, ival, instOptions);
}

//------------------------------------------------------------------------
// emitIns_SIMD_R_R_R_S_I: emits the code for a SIMD instruction that takes two register operands, a variable index +
//                         offset, an immediate operand, and that returns a value in register
//
// Arguments:
//    ins         -- The instruction being emitted
//    attr        -- The emit attribute
//    targetReg   -- The target register
//    op1Reg      -- The register of the first operand
//    op2Reg      -- The register of the second operand
//    varx        -- The variable index used for the memory address
//    offs        -- The offset added to the memory address from varx
//    ival        -- The immediate value
//    instOptions -- The options that modify how the instruction is generated
//
void emitter::emitIns_SIMD_R_R_R_S_I(instruction ins,
                                     emitAttr    attr,
                                     regNumber   targetReg,
                                     regNumber   op1Reg,
                                     regNumber   op2Reg,
                                     int         varx,
                                     int         offs,
                                     int         ival,
                                     insOpts     instOptions)
{
    assert(UseSimdEncoding());
    emitIns_Mov(INS_movaps, attr, targetReg, op1Reg, /* canSkip */ true);
    emitIns_R_R_S_I(ins, attr, targetReg, op2Reg, varx, offs, ival, instOptions);
}
#endif // FEATURE_HW_INTRINSICS

/*****************************************************************************
 *
 *  The following add instructions referencing stack-based local variables.
 */

void emitter::emitIns_S(instruction ins, emitAttr attr, int varx, int offs)
{
    UNATIVE_OFFSET sz;
    instrDesc*     id  = emitNewInstr(attr);
    insFormat      fmt = emitInsModeFormat(ins, IF_SRD);

    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    sz = emitInsSizeSV(id, insCodeMR(ins), varx, offs);
    id->idCodeSize(sz);

#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif
    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

void emitter::emitIns_BASE_R_R(instruction ins, emitAttr attr, regNumber op1Reg, regNumber op2Reg)
{
    if (DoJitUseApxNDD(ins) && (op1Reg != op2Reg))
    {
        // If APX-EVEX-NDD is available and needed, emit instructions in:
        // ins dst, src
        emitIns_R_R(ins, attr, op1Reg, op2Reg, INS_OPTS_EVEX_nd);
    }
    else
    {
        // mov dst, src
        // ins dst
        emitIns_Mov(INS_mov, attr, op1Reg, op2Reg, /*canSkip*/ true);
        emitIns_R(ins, attr, op1Reg);
    }
}

void emitter::emitIns_BASE_R_R_I(instruction ins, emitAttr attr, regNumber op1Reg, regNumber op2Reg, int ival)
{
    if (DoJitUseApxNDD(ins) && (op1Reg != op2Reg))
    {
        // If APX-EVEX-NDD is available and needed, emit instructions in:
        // ins dst, src, cns
        if (IsShiftInstruction(ins) && ival == 1)
        {
            emitIns_R_R(ins, attr, op1Reg, op2Reg, INS_OPTS_EVEX_nd);
        }
        else
        {
            emitIns_R_R_I(ins, attr, op1Reg, op2Reg, ival, INS_OPTS_EVEX_nd);
        }
    }
    else
    {
        // mov dst, src
        // ins dst, cns
        emitIns_Mov(INS_mov, attr, op1Reg, op2Reg, /*canSkip*/ true);
        if (IsShiftInstruction(ins) && ival == 1)
        {
            emitIns_R(ins, attr, op1Reg);
        }
        else
        {
            emitIns_R_I(ins, attr, op1Reg, ival);
        }
    }
}

regNumber emitter::emitIns_BASE_R_R_RM(
    instruction ins, emitAttr attr, regNumber targetReg, GenTree* treeNode, GenTree* regOp, GenTree* rmOp)
{
    bool      requiresOverflowCheck = treeNode->gtOverflowEx();
    regNumber r                     = REG_NA;
    assert(regOp->isUsedFromReg());

    bool useApxNdd = DoJitUseApxNDD(ins);

    if (emitIns_Mov(INS_mov, attr, targetReg, regOp->GetRegNum(), true, useApxNdd) && useApxNdd)
    {
        return emitInsBinary(ins, attr, regOp, rmOp, targetReg);
    }

    return emitInsBinary(ins, attr, treeNode, rmOp);
    ;
}

//----------------------------------------------------------------------------------------
// IsRedundantStackMov:
//    Check if the current `mov` instruction is redundant and can be omitted when dealing with Load/Store from stack.
//    A `mov` is redundant in following 2 cases:
//
//    1. Move that is identical to last instruction emitted.
//
//         vmovapd  xmmword ptr [V01 rbp-20H], xmm0  # <-- last instruction
//         vmovapd  xmmword ptr [V01 rbp-20H], xmm0  # <-- current instruction can be omitted.
//
//    2. Opposite Move as that of last instruction emitted.
//
//         vmovupd  ymmword ptr[V01 rbp-50H], ymm0  # <-- last instruction
//         vmovupd  ymm0, ymmword ptr[V01 rbp-50H]  # <-- current instruction can be omitted.
//
// Arguments:
//                 ins  - The current instruction
//                 fmt  - The current format
//                 size - Operand size of current instruction
//                 ireg - The current source/destination register
//                 varx - The variable index used for the memory address
//                 offs - The offset added to the memory address from varx
//
// Return Value:
//    true if the move instruction is redundant; otherwise, false.

bool emitter::IsRedundantStackMov(instruction ins, insFormat fmt, emitAttr size, regNumber ireg, int varx, int offs)
{
    assert(IsMovInstruction(ins));
    assert((fmt == IF_SWR_RRD) || (fmt == IF_RWR_SRD));
    if (!emitComp->opts.OptimizationEnabled())
    {
        // The remaining move elisions should only happen if optimizations are enabled
        return false;
    }

    // Skip optimization if current instruction creates a GC live value.
    if (EA_IS_GCREF_OR_BYREF(size))
    {
        return false;
    }

    // TODO-XArch-CQ: Certain instructions, such as movaps vs movups, are equivalent in
    // functionality even if their actual identifier differs and we should optimize these

    if (!emitCanPeepholeLastIns() ||       // Don't optimize if unsafe
        (emitLastIns->idIns() != ins) ||   // or if the instruction is different from the last instruction
        (emitLastIns->idOpSize() != size)) // or if the operand size is different from the last instruction
    {
        return false;
    }

    // Don't optimize if the last instruction is also not a Load/Store.
    if (!((emitLastIns->idInsFmt() == IF_SWR_RRD) || (emitLastIns->idInsFmt() == IF_RWR_SRD)))
    {
        return false;
    }

    regNumber lastReg1 = emitLastIns->idReg1();
    int       varNum   = emitLastIns->idAddr()->iiaLclVar.lvaVarNum();
    int       lastOffs = emitLastIns->idAddr()->iiaLclVar.lvaOffset();

    const bool hasSideEffect = HasSideEffect(ins, size);

    // Check if the last instruction and current instructions use the same register and local memory.
    if (varNum == varx && lastReg1 == ireg && lastOffs == offs)
    {
        // Check if we did a switched mov in the last instruction  and don't have a side effect
        if ((((emitLastIns->idInsFmt() == IF_RWR_SRD) && (fmt == IF_SWR_RRD)) ||
             ((emitLastIns->idInsFmt() == IF_SWR_RRD) && (fmt == IF_RWR_SRD))) &&
            !hasSideEffect) // or if the format is different from the last instruction
        {
            JITDUMP("\n -- suppressing mov because last instruction already moved from dst to src and the mov has "
                    "no side-effects.\n");
            return true;
        }
        // Check if we did same move in last instruction, side effects don't matter since they already happened
        if (emitLastIns->idInsFmt() == fmt)
        {
            JITDUMP("\n -- suppressing mov because last instruction already moved from src to dst.\n");
            return true;
        }
    }
    return false;
}

void emitter::emitIns_S_R(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs, insOpts instOptions)
{
    insFormat fmt = (ins == INS_xchg) ? IF_SRW_RRW : emitInsModeFormat(ins, IF_SRD_RRD);
    if (IsMovInstruction(ins) && IsRedundantStackMov(ins, fmt, attr, ireg, varx, offs))
    {
        return;
    }

    UNATIVE_OFFSET sz;
    instrDesc*     id = emitNewInstr(attr);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(ireg);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    assert((instOptions & INS_OPTS_EVEX_b_MASK) == 0);
    SetEvexEmbMaskIfNeeded(id, instOptions);

    sz = emitInsSizeSV(id, insCodeMR(ins), varx, offs);

#ifdef TARGET_X86
    if (attr == EA_1BYTE)
    {
        assert(isByteReg(ireg));
    }
#endif

    id->idCodeSize(sz);
#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif
    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_R_S(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs, insOpts instOptions)
{
    emitAttr size = EA_SIZE(attr);
    noway_assert(emitVerifyEncodable(ins, size, ireg));
    insFormat fmt = emitInsModeFormat(ins, IF_RRD_SRD);

    if (IsMovInstruction(ins) && IsRedundantStackMov(ins, fmt, attr, ireg, varx, offs))
    {
        return;
    }

    instrDesc* id = emitNewInstr(attr);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idReg1(ireg);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    SetEvexBroadcastIfNeeded(id, instOptions);
    SetEvexEmbMaskIfNeeded(id, instOptions);
    SetEvexNfIfNeeded(id, instOptions);
    SetEvexDFVIfNeeded(id, instOptions);

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeRM(ins), varx, offs);
    id->idCodeSize(sz);
#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif
    dispIns(id);
    emitCurIGsize += sz;
}

void emitter::emitIns_S_I(instruction ins, emitAttr attr, int varx, int offs, int val)
{
#ifdef TARGET_AMD64
    // mov reg, imm64 is the only opcode which takes a full 8 byte immediate
    // all other opcodes take a sign-extended 4-byte immediate
    noway_assert(EA_SIZE(attr) < EA_8BYTE || !EA_IS_CNS_RELOC(attr));
#endif

    insFormat fmt;

    switch (ins)
    {
        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            assert(val != 1);
            fmt = IF_SRW_SHF;
            val &= 0x7F;
            break;

        default:
            fmt = emitInsModeFormat(ins, IF_SRD_CNS);
            break;
    }

    instrDesc* id = emitNewInstrCns(attr, val);
    id->idIns(ins);
    id->idInsFmt(fmt);
    id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);

    UNATIVE_OFFSET sz = emitInsSizeSV(id, insCodeMI(ins), varx, offs, val);
    id->idCodeSize(sz);
#ifdef DEBUG
    id->idDebugOnlyInfo()->idVarRefOffs = emitVarRefOffs;
#endif
    dispIns(id);
    emitCurIGsize += sz;
}

/*****************************************************************************
 *
 *  Record that a jump instruction uses the short encoding
 *
 */
void emitter::emitSetShortJump(instrDescJmp* id)
{
    if (id->idjKeepLong)
    {
        return;
    }

    id->idjShort = true;
}

/*****************************************************************************
 *
 *  Add a jmp instruction.
 *  When dst is NULL, instrCount specifies number of instructions
 *       to jump: positive is forward, negative is backward.
 */

void emitter::emitIns_J(instruction ins,
                        BasicBlock* dst,
                        int         instrCount /* = 0 */,
                        bool        isRemovableJmpCandidate /* = false */)
{
#ifdef TARGET_AMD64
    // Check emitter::emitLastIns before it is updated
    const bool lastInsIsCall = emitIsLastInsCall();
#endif // TARGET_AMD64

    UNATIVE_OFFSET sz;
    instrDescJmp*  id = emitNewInstrJmp();

    if (dst != nullptr)
    {
        assert(dst->HasFlag(BBF_HAS_LABEL));
        assert(instrCount == 0);
    }
    else
    {
        /* Only allow non-label jmps in prolog */
        assert(emitPrologIG);
        assert(emitPrologIG == emitCurIG);
        assert(instrCount != 0);
    }

    id->idIns(ins);
    id->idInsFmt(IF_LABEL);

#ifdef DEBUG
    // Mark the finally call
    if (ins == INS_call && emitComp->compCurBB->KindIs(BBJ_CALLFINALLY))
    {
        id->idDebugOnlyInfo()->idFinallyCall = true;
    }
#endif // DEBUG

    if (isRemovableJmpCandidate)
    {
        emitContainsRemovableJmpCandidates = true;
        id->idjIsRemovableJmpCandidate     = 1;
#ifdef TARGET_AMD64
        // If this jump is after a call instruction, we might need to insert a nop after it's removed,
        // but only if the jump is before an OS epilog.
        // We'll check for the OS epilog in emitter::emitRemoveJumpToNextInst().
        id->idjIsAfterCallBeforeEpilog = lastInsIsCall ? 1 : 0;
#endif // TARGET_AMD64
    }
    else
    {
        id->idjIsRemovableJmpCandidate = 0;
    }

    id->idjShort = 0;
    if (dst != nullptr)
    {
        /* Assume the jump will be long */
        id->idAddr()->iiaBBlabel = dst;
        id->idjKeepLong          = emitComp->fgInDifferentRegions(emitComp->compCurBB, dst);
    }
    else
    {
        id->idAddr()->iiaSetInstrCount(instrCount);
        id->idjKeepLong = false;
        /* This jump must be short */
        emitSetShortJump(id);
        id->idSetIsBound();
    }

    /* Record the jump's IG and offset within it */

    id->idjIG   = emitCurIG;
    id->idjOffs = emitCurIGsize;

    /* Append this jump to this IG's jump list */

    id->idjNext      = emitCurIGjmpList;
    emitCurIGjmpList = id;

#if EMITTER_STATS
    emitTotalIGjmps++;
#endif

    /* Figure out the max. size of the jump/call instruction */

    if (ins == INS_call)
    {
        sz = CALL_INST_SIZE;
    }
    else if (ins == INS_push || ins == INS_push_hide)
    {
        // Pushing the address of a basicBlock will need a reloc
        // as the instruction uses the absolute address,
        // not a relative address
        if (emitComp->opts.compReloc)
        {
            id->idSetIsDspReloc();
        }
        sz = PUSH_INST_SIZE;
    }
    else
    {
        insGroup* tgt = nullptr;

        if (dst != nullptr)
        {
            /* This is a jump - assume the worst */
            sz = (ins == INS_jmp) ? JMP_SIZE_LARGE : JCC_SIZE_LARGE;
            /* Can we guess at the jump distance? */
            tgt = (insGroup*)emitCodeGetCookie(dst);
        }
        else
        {
            sz = JMP_SIZE_SMALL;
        }

        if (tgt)
        {
            int            extra;
            UNATIVE_OFFSET srcOffs;
            int            jmpDist;

            assert(JMP_SIZE_SMALL == JCC_SIZE_SMALL);

            /* This is a backward jump - figure out the distance */

            srcOffs = emitCurCodeOffset + emitCurIGsize + JMP_SIZE_SMALL;

            /* Compute the distance estimate */

            jmpDist = srcOffs - tgt->igOffs;
            assert((int)jmpDist > 0);

            /* How much beyond the max. short distance does the jump go? */

            extra = jmpDist + JMP_DIST_SMALL_MAX_NEG;

#if DEBUG_EMIT
            if (id->idDebugOnlyInfo()->idNum == (unsigned)INTERESTING_JUMP_NUM || INTERESTING_JUMP_NUM == 0)
            {
                if (INTERESTING_JUMP_NUM == 0)
                {
                    printf("[0] Jump %u:\n", id->idDebugOnlyInfo()->idNum);
                }
                printf("[0] Jump source is at %08X\n", srcOffs);
                printf("[0] Label block is at %08X\n", tgt->igOffs);
                printf("[0] Jump  distance  - %04X\n", jmpDist);
                if (extra > 0)
                {
                    printf("[0] Distance excess = %d  \n", extra);
                }
            }
#endif

            if (extra <= 0 && !id->idjKeepLong)
            {
                /* Wonderful - this jump surely will be short */

                emitSetShortJump(id);
                sz = JMP_SIZE_SMALL;
            }
        }
#if DEBUG_EMIT
        else
        {
            if (id->idDebugOnlyInfo()->idNum == (unsigned)INTERESTING_JUMP_NUM || INTERESTING_JUMP_NUM == 0)
            {
                if (INTERESTING_JUMP_NUM == 0)
                {
                    printf("[0] Jump %u:\n", id->idDebugOnlyInfo()->idNum);
                }
                printf("[0] Jump source is at %04X/%08X\n", emitCurIGsize,
                       emitCurCodeOffset + emitCurIGsize + JMP_SIZE_SMALL);
                printf("[0] Label block is unknown\n");
            }
        }
#endif
    }

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

    emitAdjustStackDepthPushPop(ins);
}

#if !FEATURE_FIXED_OUT_ARGS

//------------------------------------------------------------------------
// emitAdjustStackDepthPushPop: Adjust the current and maximum stack depth.
//
// Arguments:
//    ins - the instruction. Only INS_push and INS_pop adjust the stack depth.
//
// Notes:
//    1. Alters emitCurStackLvl and possibly emitMaxStackDepth.
//    2. emitCntStackDepth must be set (0 in prolog/epilog, one DWORD elsewhere)
//
void emitter::emitAdjustStackDepthPushPop(instruction ins)
{
    if (ins == INS_push)
    {
        emitCurStackLvl += emitCntStackDepth;

        if (emitMaxStackDepth < emitCurStackLvl)
        {
            JITDUMP("Upping emitMaxStackDepth from %d to %d\n", emitMaxStackDepth, emitCurStackLvl);
            emitMaxStackDepth = emitCurStackLvl;
        }
    }
    else if (ins == INS_pop)
    {
        emitCurStackLvl -= emitCntStackDepth;
        assert((int)emitCurStackLvl >= 0);
    }
}

//------------------------------------------------------------------------
// emitAdjustStackDepth: Adjust the current and maximum stack depth.
//
// Arguments:
//    ins - the instruction. Only INS_add and INS_sub adjust the stack depth.
//          It is assumed that the add/sub is on the stack pointer.
//    val - the number of bytes to add to or subtract from the stack pointer.
//
// Notes:
//    1. Alters emitCurStackLvl and possibly emitMaxStackDepth.
//    2. emitCntStackDepth must be set (0 in prolog/epilog, one DWORD elsewhere)
//
void emitter::emitAdjustStackDepth(instruction ins, ssize_t val)
{
    // If we're in the prolog or epilog, or otherwise not tracking the stack depth, just return.
    if (emitCntStackDepth == 0)
        return;

    if (ins == INS_sub)
    {
        S_UINT32 newStackLvl(emitCurStackLvl);
        newStackLvl += S_UINT32(val);
        noway_assert(!newStackLvl.IsOverflow());

        emitCurStackLvl = newStackLvl.Value();

        if (emitMaxStackDepth < emitCurStackLvl)
        {
            JITDUMP("Upping emitMaxStackDepth from %d to %d\n", emitMaxStackDepth, emitCurStackLvl);
            emitMaxStackDepth = emitCurStackLvl;
        }
    }
    else if (ins == INS_add)
    {
        S_UINT32 newStackLvl = S_UINT32(emitCurStackLvl) - S_UINT32(val);
        noway_assert(!newStackLvl.IsOverflow());

        emitCurStackLvl = newStackLvl.Value();
    }
}

#endif // EMIT_TRACK_STACK_DEPTH

/*****************************************************************************
 *
 *  Add a call instruction (direct or indirect).
 *      argSize<0 means that the caller will pop the arguments
 *
 * The other arguments are interpreted depending on callType as shown:
 * Unless otherwise specified, ireg,xreg,xmul,disp should have default values.
 *
 * EC_FUNC_TOKEN       : addr is the method address
 * EC_FUNC_TOKEN_INDIR : addr is the indirect method address
 * EC_FUNC_ADDR        : addr is the absolute address of the function
 * EC_FUNC_VIRTUAL     : "call [ireg+disp]"
 *
 * If callType is one of these emitCallTypes, addr has to be NULL.
 * EC_INDIR_R          : "call ireg".
 * EC_INDIR_SR         : "call lcl<disp>" (eg. call [ebp-8]).
 * EC_INDIR_C          : "call clsVar<disp>" (eg. call [clsVarAddr])
 * EC_INDIR_ARD        : "call [ireg+xreg*xmul+disp]"
 *
 * noSafePoint - force not making this call a safe point in partially interruptible code
 *
 */

// clang-format off
void emitter::emitIns_Call(const EmitCallParams& params)
// clang-format on
{
    /* Sanity check the arguments depending on callType */

    assert(params.callType < EC_COUNT);
    if (!emitComp->IsTargetAbi(CORINFO_NATIVEAOT_ABI))
    {
        assert((params.callType != EC_FUNC_TOKEN && params.callType != EC_FUNC_TOKEN_INDIR) ||
               (params.addr != nullptr && params.ireg == REG_NA && params.xreg == REG_NA && params.xmul == 0 &&
                params.disp == 0));
    }
    assert(params.callType != EC_INDIR_R || (params.addr == nullptr && params.ireg < REG_COUNT &&
                                             params.xreg == REG_NA && params.xmul == 0 && params.disp == 0));
    assert(params.callType != EC_INDIR_ARD || (params.addr == nullptr));

    // Our stack level should be always greater than the bytes of arguments we push. Just
    // a sanity test.
    assert((unsigned)abs((signed)params.argSize) <= codeGen->genStackLevel);

    // Trim out any callee-trashed registers from the live set.
    regMaskTP savedSet  = emitGetGCRegsSavedOrModified(params.methHnd);
    regMaskTP gcrefRegs = params.gcrefRegs & savedSet;
    regMaskTP byrefRegs = params.byrefRegs & savedSet;

#ifdef DEBUG
    if (EMIT_GC_VERBOSE)
    {
        printf("\t\t\t\t\t\t\tCall: GCvars=%s ", VarSetOps::ToString(emitComp, params.ptrVars));
        dumpConvertedVarSet(emitComp, params.ptrVars);
        printf(", gcrefRegs=");
        printRegMaskInt(gcrefRegs);
        emitDispRegSet(gcrefRegs);
        printf(", byrefRegs=");
        printRegMaskInt(byrefRegs);
        emitDispRegSet(byrefRegs);
        printf("\n");
    }
#endif

    /* Managed RetVal: emit sequence point for the call */
    if (emitComp->opts.compDbgInfo && params.debugInfo.IsValid())
    {
        codeGen->genIPmappingAdd(IPmappingDscKind::Normal, params.debugInfo, false);
    }

    /*
        We need to allocate the appropriate instruction descriptor based
        on whether this is a direct/indirect call, and whether we need to
        record an updated set of live GC variables.

        The stats for a ton of classes is as follows:

            Direct call w/o  GC vars        220,216
            Indir. call w/o  GC vars        144,781

            Direct call with GC vars          9,440
            Indir. call with GC vars          5,768
     */

    instrDesc* id;

    assert(params.argSize % REGSIZE_BYTES == 0);
    int argCnt = (int)(params.argSize / (int)REGSIZE_BYTES); // we need a signed-divide

    if ((params.callType == EC_INDIR_R) || (params.callType == EC_INDIR_ARD))
    {
        /* Indirect call, virtual calls */

        id = emitNewInstrCallInd(argCnt, params.disp, params.ptrVars, gcrefRegs, byrefRegs,
                                 params.retSize MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(params.secondRetSize),
                                 params.hasAsyncRet);
    }
    else
    {
        // Helper/static/nonvirtual/function calls (direct or through handle),
        // and calls to an absolute addr.

        assert(params.callType == EC_FUNC_TOKEN || params.callType == EC_FUNC_TOKEN_INDIR);

        id = emitNewInstrCallDir(argCnt, params.ptrVars, gcrefRegs, byrefRegs,
                                 params.retSize MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(params.secondRetSize),
                                 params.hasAsyncRet);
    }

    /* Update the emitter's live GC ref sets */

    // If the method returns a GC ref, mark EAX appropriately
    if (params.retSize == EA_GCREF)
    {
        gcrefRegs |= RBM_EAX;
    }
    else if (params.retSize == EA_BYREF)
    {
        byrefRegs |= RBM_EAX;
    }

#ifdef UNIX_AMD64_ABI
    // If is a multi-register return method is called, mark RDX appropriately (for System V AMD64).
    if (params.secondRetSize == EA_GCREF)
    {
        gcrefRegs |= RBM_RDX;
    }
    else if (params.secondRetSize == EA_BYREF)
    {
        byrefRegs |= RBM_RDX;
    }
#endif // UNIX_AMD64_ABI

    VarSetOps::Assign(emitComp, emitThisGCrefVars, params.ptrVars);
    emitThisGCrefRegs = gcrefRegs;
    emitThisByrefRegs = byrefRegs;

    /* Set the instruction - special case jumping a function (tail call) */
    instruction ins = INS_call;

    if (params.isJump)
    {
        if (params.callType == EC_FUNC_TOKEN)
        {
            ins = INS_l_jmp;
        }
        else
        {
            ins = INS_tail_i_jmp;
        }
    }
    id->idIns(ins);

    // for the purpose of GC safepointing tail-calls are not real calls
    id->idSetIsNoGC(params.isJump || params.noSafePoint || emitNoGChelper(params.methHnd));

    UNATIVE_OFFSET sz;

    // Record the address: method, indirection, or funcptr
    if ((params.callType == EC_INDIR_R) || (params.callType == EC_INDIR_ARD))
    {
        // This is an indirect call/jmp (either a virtual call or func ptr call)

        if (params.callType == EC_INDIR_R) // call reg
        {
            id->idSetIsCallRegPtr();
        }

        // The function is "ireg" if id->idIsCallRegPtr(),
        // else [ireg+xmul*xreg+disp]

        id->idInsFmt(emitInsModeFormat(ins, IF_ARD));

        id->idAddr()->iiaAddrMode.amBaseReg = params.ireg;
        id->idAddr()->iiaAddrMode.amIndxReg = params.xreg;
        id->idAddr()->iiaAddrMode.amScale   = params.xmul ? emitEncodeScale(params.xmul) : emitter::OPSZ1;

        code_t code = insCodeMR(ins);
        if (ins == INS_tail_i_jmp)
        {
            // Tailcall with addressing mode/register needs to be rex.w
            // prefixed to be recognized as part of epilog by unwinder.
            code = AddRexWPrefix(id, code);
        }

        sz = emitInsSizeAM(id, code);

        if (params.ireg == REG_NA && params.xreg == REG_NA)
        {
            if (codeGen->genCodeIndirAddrNeedsReloc(params.disp))
            {
                id->idSetIsDspReloc();
            }
#ifdef TARGET_AMD64
            else
            {
                // An absolute indir address that doesn't need reloc should fit within 32-bits
                // to be encoded as offset relative to zero.  This addr mode requires an extra
                // SIB byte
                noway_assert((size_t) static_cast<int>(reinterpret_cast<intptr_t>(params.addr)) == (size_t)params.addr);
                sz++;
            }
#endif // TARGET_AMD64
        }
    }
    else if (params.callType == EC_FUNC_TOKEN_INDIR)
    {
        // call/jmp [method_addr]

        assert(params.addr != nullptr);

        id->idInsFmt(IF_METHPTR);
        id->idAddr()->iiaAddr = (BYTE*)params.addr;
        sz                    = 6;

        if (TakesRex2Prefix(id))
        {
            sz += 2;
        }

        // Since this is an indirect call through a pointer and we don't
        // currently pass in emitAttr into this function, we query codegen
        // whether addr needs a reloc.
        if (codeGen->genCodeIndirAddrNeedsReloc((size_t)params.addr))
        {
            id->idSetIsDspReloc();
        }
#ifdef TARGET_AMD64
        else
        {
            // An absolute indir address that doesn't need reloc should fit within 32-bits
            // to be encoded as offset relative to zero.  This addr mode requires an extra
            // SIB byte
            noway_assert((size_t) static_cast<int>(reinterpret_cast<intptr_t>(params.addr)) == (size_t)params.addr);
            sz++;
        }
#endif // TARGET_AMD64
    }
    else
    {
        // This is a simple direct call/jmp: call/jmp helper/method/addr

        assert(params.callType == EC_FUNC_TOKEN);

        assert(params.addr != nullptr || emitComp->IsTargetAbi(CORINFO_NATIVEAOT_ABI));

        id->idInsFmt(IF_METHOD);
        sz = 5;

        id->idAddr()->iiaAddr = (BYTE*)params.addr;

        // Direct call to a method and no addr indirection is needed.
        if (codeGen->genCodeAddrNeedsReloc((size_t)params.addr))
        {
            id->idSetIsDspReloc();

            if ((size_t)params.methHnd == 1)
            {
                id->idSetTlsGD();
                sz += 1; // For REX.W prefix
            }
        }
    }

    if (m_debugInfoSize > 0)
    {
        INDEBUG(id->idDebugOnlyInfo()->idCallSig = params.sigInfo);
        id->idDebugOnlyInfo()->idMemCookie = (size_t)params.methHnd; // method token
    }

#ifdef LATE_DISASM
    if (params.addr != nullptr)
    {
        codeGen->getDisAssembler().disSetMethod((size_t)params.addr, params.methHnd);
    }
#endif // LATE_DISASM

    id->idCodeSize(sz);

    dispIns(id);
    emitCurIGsize += sz;

#if !FEATURE_FIXED_OUT_ARGS

    /* The call will pop the arguments */

    if (emitCntStackDepth && params.argSize > 0)
    {
        noway_assert((ssize_t)emitCurStackLvl >= params.argSize);
        emitCurStackLvl -= (int)params.argSize;
        assert((int)emitCurStackLvl >= 0);
    }

#endif // !FEATURE_FIXED_OUT_ARGS
}

#ifdef DEBUG
/*****************************************************************************
 *
 *  The following called for each recorded instruction -- use for debugging.
 */
void emitter::emitInsSanityCheck(instrDesc* id)
{
    // make certain you only try to put relocs on things that can have them.
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    if ((idOp == ID_OP_SCNS) && id->idIsLargeCns())
    {
        idOp = ID_OP_CNS;
    }

    if (id->idIsDspReloc())
    {
        assert(idOp == ID_OP_NONE || idOp == ID_OP_AMD || idOp == ID_OP_DSP || idOp == ID_OP_DSP_CNS ||
               idOp == ID_OP_AMD_CNS || idOp == ID_OP_SPEC || idOp == ID_OP_CALL || idOp == ID_OP_JMP ||
               idOp == ID_OP_LBL);
    }

    if (id->idIsCnsReloc())
    {
        assert(idOp == ID_OP_CNS || idOp == ID_OP_AMD_CNS || idOp == ID_OP_DSP_CNS || idOp == ID_OP_SPEC ||
               idOp == ID_OP_CALL || idOp == ID_OP_JMP);
    }
}
#endif

//------------------------------------------------------------------------
// emitSizeOfInsDsc_AMD: The allocated size, in bytes, of the AMD or AMD_CNS instrDesc
//
// Arguments:
//    id - The instrDesc for which to get the size
//
// Returns:
//    The allocated size, in bytes, of id
//
size_t emitter::emitSizeOfInsDsc_AMD(instrDesc* id) const
{
    assert(!emitIsSmallInsDsc(id));

#if defined(DEBUG)
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    assert((idOp == ID_OP_AMD) || (idOp == ID_OP_AMD_CNS));
#endif // DEBUG

    if (id->idIsLargeCns())
    {
        if (id->idIsLargeDsp())
        {
            return sizeof(instrDescCnsAmd);
        }
        else
        {
            return sizeof(instrDescCns);
        }
    }
    else if (id->idIsLargeDsp())
    {
        return sizeof(instrDescAmd);
    }
    else
    {
        return sizeof(instrDesc);
    }
}

//------------------------------------------------------------------------
// emitSizeOfInsDsc_CNS: The allocated size, in bytes, of the CNS or SCNS instrDesc
//
// Arguments:
//    id - The instrDesc for which to get the size
//
// Returns:
//    The allocated size, in bytes, of id
//
size_t emitter::emitSizeOfInsDsc_CNS(instrDesc* id) const
{
#if defined(DEBUG)
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    assert((idOp == ID_OP_CNS) || (idOp == ID_OP_SCNS));
#endif // DEBUG

    if (emitIsSmallInsDsc(id))
    {
        return SMALL_IDSC_SIZE;
    }
    else if (id->idIsLargeCns())
    {
        return sizeof(instrDescCns);
    }
    else
    {
        return sizeof(instrDesc);
    }
}

//------------------------------------------------------------------------
// emitSizeOfInsDsc_NONE: The allocated size, in bytes, of the NONE instrDesc
//
// Arguments:
//    id - The instrDesc for which to get the size
//
// Returns:
//    The allocated size, in bytes, of id
//
size_t emitter::emitSizeOfInsDsc_NONE(instrDesc* id) const
{
#if defined(DEBUG)
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    assert(idOp == ID_OP_NONE);
#endif // DEBUG

    if (emitIsSmallInsDsc(id))
    {
        return SMALL_IDSC_SIZE;
    }
#if FEATURE_LOOP_ALIGN
    else if (id->idIns() == INS_align)
    {
        return sizeof(instrDescAlign);
    }
#endif
    else
    {
        return sizeof(instrDesc);
    }
}

//------------------------------------------------------------------------
// emitSizeOfInsDsc_SPEC: The allocated size, in bytes, of the CALL or SPEC instrDesc
//
// Arguments:
//    id - The instrDesc for which to get the size
//
// Returns:
//    The allocated size, in bytes, of id
//
size_t emitter::emitSizeOfInsDsc_SPEC(instrDesc* id) const
{
    assert(!emitIsSmallInsDsc(id));

#if defined(DEBUG)
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    assert((idOp == ID_OP_CALL) || (idOp == ID_OP_SPEC));
#endif // DEBUG

    if (id->idIsLargeCall())
    {
        /* Must be a "fat" indirect call descriptor */
        return sizeof(instrDescCGCA);
    }
    else if (id->idIsLargeCns())
    {
        if (id->idIsLargeDsp())
        {
            return sizeof(instrDescCnsDsp);
        }
        else
        {
            return sizeof(instrDescCns);
        }
    }
    else if (id->idIsLargeDsp())
    {
        return sizeof(instrDescDsp);
    }
    else
    {
        return sizeof(instrDesc);
    }
}

//------------------------------------------------------------------------
// emitSizeOfInsDsc_DSP: The allocated size, in bytes, of the DSP or DSP_CNS instrDesc
//
// Arguments:
//    id - The instrDesc for which to get the size
//
// Returns:
//    The allocated size, in bytes, of id
//
size_t emitter::emitSizeOfInsDsc_DSP(instrDesc* id) const
{
    assert(!emitIsSmallInsDsc(id));

#if defined(DEBUG)
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];
    assert((idOp == ID_OP_DSP) || (idOp == ID_OP_DSP_CNS));
#endif // DEBUG

    if (id->idIsLargeCns())
    {
        if (id->idIsLargeDsp())
        {
            return sizeof(instrDescCnsDsp);
        }
        else
        {
            return sizeof(instrDescCns);
        }
    }
    else if (id->idIsLargeDsp())
    {
        return sizeof(instrDescDsp);
    }
    else
    {
        return sizeof(instrDesc);
    }
}

/*****************************************************************************
 *
 *  Return the allocated size (in bytes) of the given instruction descriptor.
 */
size_t emitter::emitSizeOfInsDsc(instrDesc* id) const
{
    assert((unsigned)id->idInsFmt() < emitFmtCount);
    ID_OPS idOp = (ID_OPS)emitFmtToOps[id->idInsFmt()];

    // An INS_call instruction may use a "fat" direct/indirect call descriptor
    // except for a local call to a label (i.e. call to a finally)
    // Only ID_OP_CALL and ID_OP_SPEC check for this, so we enforce that the
    //  INS_call instruction always uses one of these idOps

    if (id->idIns() == INS_call)
    {
        assert((idOp == ID_OP_CALL) || // is a direct   call
               (idOp == ID_OP_SPEC) || // is a indirect call
               (idOp == ID_OP_JMP));   // is a local call to finally clause
    }

    switch (idOp)
    {
        case ID_OP_NONE:
        {
            return emitSizeOfInsDsc_NONE(id);
        }

        case ID_OP_LBL:
        {
            return sizeof(instrDescLbl);
        }

        case ID_OP_JMP:
        {
            return sizeof(instrDescJmp);
        }

        case ID_OP_CALL:
        case ID_OP_SPEC:
        {
            return emitSizeOfInsDsc_SPEC(id);
        }

        case ID_OP_SCNS:
        case ID_OP_CNS:
        {
            return emitSizeOfInsDsc_CNS(id);
        }

        case ID_OP_DSP:
        case ID_OP_DSP_CNS:
        {
            return emitSizeOfInsDsc_DSP(id);
        }

        case ID_OP_AMD:
        case ID_OP_AMD_CNS:
        {
            return emitSizeOfInsDsc_AMD(id);
        }

        default:
        {
            NO_WAY("unexpected instruction descriptor format");
            return sizeof(instrDesc);
        }
    }
}

/*****************************************************************************
 *
 *  Return a string that represents the given register.
 */

const char* emitter::emitRegName(regNumber reg, emitAttr attr, bool varName) const
{
    static char          rb[2][128];
    static unsigned char rbc = 0;

    const char* rn = emitComp->compRegVarName(reg, varName);

    char suffix = '\0';

    if (isMaskReg(reg))
    {
        return rn;
    }

#ifdef TARGET_X86
    assert(strlen(rn) >= 3);
#endif // TARGET_X86

    switch (EA_SIZE(attr))
    {
        case EA_64BYTE:
        {
            if (IsXMMReg(reg))
            {
                return emitZMMregName(reg);
            }
            break;
        }

        case EA_32BYTE:
        {
            if (IsXMMReg(reg))
            {
                return emitYMMregName(reg);
            }
            break;
        }

        case EA_16BYTE:
        {
            if (IsXMMReg(reg))
            {
                return emitXMMregName(reg);
            }
            break;
        }

        case EA_8BYTE:
        {
            if (IsXMMReg(reg))
            {
                return emitXMMregName(reg);
            }
            break;
        }

        case EA_4BYTE:
        {
            if (IsXMMReg(reg))
            {
                return emitXMMregName(reg);
            }
            assert(isGeneralRegister(reg));
#if defined(TARGET_AMD64)
            if (reg > REG_RDI)
            {
                suffix = 'd';
                goto APPEND_SUFFIX;
            }
            rbc ^= 1;
            rb[rbc][0] = 'e';
            rb[rbc][1] = rn[1];
            rb[rbc][2] = rn[2];
            rb[rbc][3] = 0;
            rn         = rb[rbc];
#endif // TARGET_AMD64
            break;
        }

        case EA_2BYTE:
        {
#if defined(TARGET_AMD64)
            if (reg > REG_RDI)
            {
                suffix = 'w';
                goto APPEND_SUFFIX;
            }
#endif // TARGET_AMD64

            rn++;
            break;
        }

        case EA_1BYTE:
        {
#if defined(TARGET_AMD64)
            if (reg > REG_RDI)
            {
                suffix = 'b';
            APPEND_SUFFIX:
                rbc ^= 1;
                rb[rbc][0] = rn[0];
                rb[rbc][1] = rn[1];
                if (rn[2])
                {
                    assert(rn[3] == 0);
                    rb[rbc][2] = rn[2];
                    rb[rbc][3] = suffix;
                    rb[rbc][4] = 0;
                }
                else
                {
                    rb[rbc][2] = suffix;
                    rb[rbc][3] = 0;
                }
            }
            else
            {
                rbc ^= 1;
                rb[rbc][0] = rn[1];
                if (reg < 4)
                {
                    rb[rbc][1] = 'l';
                    rb[rbc][2] = 0;
                }
                else
                {
                    rb[rbc][1] = rn[2];
                    rb[rbc][2] = 'l';
                    rb[rbc][3] = 0;
                }
            }
#endif // TARGET_AMD64

#if defined(TARGET_X86)
            rbc ^= 1;
            rb[rbc][0] = rn[1];
            rb[rbc][1] = 'l';
            strcpy_s(&rb[rbc][2], sizeof(rb[0]) - 2, rn + 3);
#endif // TARGET_X86

            rn = rb[rbc];
            break;
        }

        default:
        {
            break;
        }
    }

#if 0
    // The following is useful if you want register names to be tagged with * or ^ representing gcref or byref, respectively,
    // however it's possibly not interesting most of the time.
    if (EA_IS_GCREF(attr) || EA_IS_BYREF(attr))
    {
        if (rn != rb[rbc])
        {
            rbc = (rbc+1)%2;
            strcpy_s(rb[rbc], sizeof(rb[rbc]), rn);
            rn = rb[rbc];
        }

        if (EA_IS_GCREF(attr))
        {
            strcat_s(rb[rbc], sizeof(rb[rbc]), "*");
        }
        else if (EA_IS_BYREF(attr))
        {
            strcat_s(rb[rbc], sizeof(rb[rbc]), "^");
        }
    }
#endif // 0

    return rn;
}

/*****************************************************************************
 *
 *  Return a string that represents the given XMM register.
 */

const char* emitter::emitXMMregName(unsigned reg) const
{
    static const char* const regNames[] = {
#define REGDEF(name, rnum, mask, sname) "x" sname,
#include "register.h"
    };

    assert(reg < REG_COUNT);
    assert(reg < ArrLen(regNames));

    return regNames[reg];
}

/*****************************************************************************
 *
 *  Return a string that represents the given YMM register.
 */

const char* emitter::emitYMMregName(unsigned reg) const
{
    static const char* const regNames[] = {
#define REGDEF(name, rnum, mask, sname) "y" sname,
#include "register.h"
    };

    assert(reg < REG_COUNT);
    assert(reg < ArrLen(regNames));

    return regNames[reg];
}

/*****************************************************************************
 *
 *  Return a string that represents the given ZMM register.
 */

const char* emitter::emitZMMregName(unsigned reg) const
{
    static const char* const regNames[] = {
#define REGDEF(name, rnum, mask, sname) "z" sname,
#include "register.h"
    };

    assert(reg < REG_COUNT);
    assert(reg < ArrLen(regNames));

    return regNames[reg];
}

/*****************************************************************************
 *
 *  Display a static data member reference.
 */

void emitter::emitDispClsVar(CORINFO_FIELD_HANDLE fldHnd, ssize_t offs, bool reloc /* = false */)
{
    int doffs;

    /* Filter out the special case of fs:[offs] */

    // Munge any pointers if we want diff-able disassembly
    if (emitComp->opts.disDiffable)
    {
        ssize_t top12bits = (offs >> 20);
        if ((top12bits != 0) && (top12bits != -1))
        {
            offs = 0xD1FFAB1E;
        }
    }

    if (fldHnd == FLD_GLOBAL_FS)
    {
        printf("FS:[0x%04X]", (unsigned)offs);
        return;
    }

    if (fldHnd == FLD_GLOBAL_GS)
    {
        printf("GS:[0x%04X]", (unsigned)offs);
        return;
    }

    if (fldHnd == FLD_GLOBAL_DS)
    {
        printf("[0x%04X]", (unsigned)offs);
        return;
    }

    printf("[");

    doffs = Compiler::eeGetJitDataOffs(fldHnd);

    if (reloc)
    {
        printf("reloc ");
    }

    if (doffs >= 0)
    {
        if (doffs & 1)
        {
            printf("@CNS%02u", doffs - 1);
        }
        else
        {
            printf("@RWD%02u", doffs);
        }

        if (offs)
        {
            printf("%+Id", offs);
        }
    }
    else
    {
        printf("classVar[%#p]", (void*)emitComp->dspPtr(fldHnd));

        if (offs)
        {
            printf("%+Id", offs);
        }
    }

    printf("]");

#ifdef DEBUG
    if (emitComp->opts.varNames && offs < 0)
    {
        char buffer[128];
        printf("'%s", emitComp->eeGetFieldName(fldHnd, true, buffer, sizeof(buffer)));
        if (offs)
        {
            printf("%+Id", offs);
        }
        printf("'");
    }
#endif
}

/*****************************************************************************
 *
 *  Display a stack frame reference.
 */

void emitter::emitDispFrameRef(int varx, int disp, int offs, bool asmfm)
{
    int  addr;
    bool bEBP;

    printf("[");

    if (!asmfm || emitComp->lvaDoneFrameLayout == Compiler::NO_FRAME_LAYOUT)
    {
        if (varx < 0)
        {
            printf("TEMP_%02u", -varx);
        }
        else
        {
            printf("V%02u", +varx);
        }

        if (disp < 0)
        {
            printf("-0x%X", -disp);
        }
        else if (disp > 0)
        {
            printf("+0x%X", +disp);
        }
    }

    if (emitComp->lvaDoneFrameLayout == Compiler::FINAL_FRAME_LAYOUT)
    {
        if (!asmfm)
        {
            printf(" ");
        }

        addr = emitComp->lvaFrameAddress(varx, &bEBP) + disp;

        if (bEBP)
        {
            printf(STR_FPBASE);

            if (addr < 0)
            {
                printf("-0x%02X", -addr);
            }
            else if (addr > 0)
            {
                printf("+0x%02X", addr);
            }
        }
        else
        {
            /* Adjust the offset by amount currently pushed on the stack */

            printf(STR_SPBASE);

            if (addr < 0)
            {
                printf("-0x%02X", -addr);
            }
            else if (addr > 0)
            {
                printf("+0x%02X", addr);
            }

#if !FEATURE_FIXED_OUT_ARGS

            if (emitCurStackLvl)
                printf("+0x%02X", emitCurStackLvl);

#endif // !FEATURE_FIXED_OUT_ARGS
        }
    }

    printf("]");
#ifdef DEBUG
    if ((varx >= 0) && emitComp->opts.varNames && (((IL_OFFSET)offs) != BAD_IL_OFFSET))
    {
        const char* varName = emitComp->compLocalVarName(varx, offs);

        if (varName)
        {
            printf("'%s", varName);

            if (disp < 0)
            {
                printf("-%d", -disp);
            }
            else if (disp > 0)
            {
                printf("+%d", +disp);
            }

            printf("'");
        }
    }
#endif
}

/*****************************************************************************
 *
 *  Display the mask for the instruction
 */
void emitter::emitDispMask(const instrDesc* id, regNumber reg) const
{
    printf(" {%s}", emitRegName(reg));

    if (id->idIsEvexZContextSet())
    {
        printf("{z}");
    }
}

/*****************************************************************************
 *
 *  Display a reloc value
 *  If we are formatting for a diffable assembly listing don't print the hex value
 *  since it will prevent us from doing assembly diffs
 */
void emitter::emitDispReloc(ssize_t value) const
{
    if (emitComp->opts.disAsm && emitComp->opts.disDiffable)
    {
        printf("(reloc)");
    }
    else
    {
        printf("(reloc 0x%zx)", emitComp->dspPtr(value));
    }
}

/*****************************************************************************
 *
 *  Display an address mode.
 */

void emitter::emitDispAddrMode(instrDesc* id, bool noDetail) const
{
    bool    nsep = false;
    ssize_t disp;

    unsigned     jtno = 0;
    dataSection* jdsc = nullptr;

    /* The displacement field is in an unusual place for calls */

    disp = (id->idIns() == INS_call) || (id->idIns() == INS_tail_i_jmp) ? emitGetInsCIdisp(id) : emitGetInsAmdAny(id);

    /* Display a jump table label if this is a switch table jump */

    if (id->idIns() == INS_i_jmp)
    {
        UNATIVE_OFFSET offs = 0;

        /* Find the appropriate entry in the data section list */

        for (jdsc = emitConsDsc.dsdList, jtno = 0; jdsc; jdsc = jdsc->dsNext)
        {
            UNATIVE_OFFSET size = jdsc->dsSize;

            /* Is this a label table? */

            if (size & 1)
            {
                size--;
                jtno++;

                if (offs == id->idDebugOnlyInfo()->idMemCookie)
                {
                    break;
                }
            }

            offs += size;
        }

        /* If we've found a matching entry then is a table jump */

        if (jdsc)
        {
            if (id->idIsDspReloc())
            {
                printf("reloc ");
            }
            printf("J_M%03u_DS%02u", emitComp->compMethodID, (unsigned)id->idDebugOnlyInfo()->idMemCookie);

            disp -= id->idDebugOnlyInfo()->idMemCookie;
        }
    }

    bool frameRef = false;

    printf("[");

    if (id->idAddr()->iiaAddrMode.amBaseReg != REG_NA)
    {
        printf("%s", emitRegName(id->idAddr()->iiaAddrMode.amBaseReg));
        nsep = true;
        if (id->idAddr()->iiaAddrMode.amBaseReg == REG_ESP)
        {
            frameRef = true;
        }
        else if (emitComp->isFramePointerUsed() && id->idAddr()->iiaAddrMode.amBaseReg == REG_EBP)
        {
            frameRef = true;
        }
    }

    if (id->idAddr()->iiaAddrMode.amIndxReg != REG_NA)
    {
        size_t scale = emitDecodeScale(id->idAddr()->iiaAddrMode.amScale);

        if (nsep)
        {
            printf("+");
        }
        if (scale > 1)
        {
            printf("%u*", (unsigned)scale);
        }
        printf("%s", emitRegName(id->idAddr()->iiaAddrMode.amIndxReg));
        nsep = true;
    }

    if (id->idIsDspReloc() && (id->idIns() != INS_i_jmp))
    {
        if (nsep)
        {
            printf("+");
        }
        emitDispReloc(disp);
    }
    else
    {
        // Munge any pointers if we want diff-able disassembly
        // It's assumed to be a pointer when disp is outside of the range (-1M, +1M); top bits are not 0 or -1
        if (!frameRef && emitComp->opts.disDiffable && (static_cast<size_t>((disp >> 20) + 1) > 1))
        {
            if (nsep)
            {
                printf("+");
            }
            printf("D1FFAB1EH");
        }
        else if (disp > 0)
        {
            if (nsep)
            {
                printf("+");
            }
            if (frameRef)
            {
                printf("0x%02X", (unsigned)disp);
            }
            else if (disp < 1000)
            {
                printf("0x%02X", (unsigned)disp);
            }
            else if (disp <= 0xFFFF)
            {
                printf("0x%04X", (unsigned)disp);
            }
            else
            {
                printf("0x%08X", (unsigned)disp);
            }
        }
        else if (disp < 0)
        {
            if (frameRef)
            {
                printf("-0x%02X", (unsigned)-disp);
            }
            else if (disp > -1000)
            {
                printf("-0x%02X", (unsigned)-disp);
            }
            else if (disp >= -0xFFFF)
            {
                printf("-0x%04X", (unsigned)-disp);
            }
            else if (disp < -0xFFFFFF)
            {
                if (nsep)
                {
                    printf("+");
                }
                printf("0x%08X", (unsigned)disp);
            }
            else
            {
                printf("-0x%08X", (unsigned)-disp);
            }
        }
        else if (!nsep)
        {
            printf("0x%04X", (unsigned)disp);
        }
    }

    printf("]");

    if (jdsc && !noDetail)
    {
        unsigned     cnt = (jdsc->dsSize - 1) / TARGET_POINTER_SIZE;
        BasicBlock** bbp = (BasicBlock**)jdsc->dsCont;

#ifdef TARGET_AMD64
#define SIZE_LETTER "Q"
#else
#define SIZE_LETTER "D"
#endif
        printf("\n\n    J_M%03u_DS%02u LABEL   " SIZE_LETTER "WORD", emitComp->compMethodID, jtno);

        /* Display the label table (it's stored as "BasicBlock*" values) */

        do
        {
            insGroup* lab;

            /* Convert the BasicBlock* value to an IG address */

            lab = (insGroup*)emitCodeGetCookie(*bbp++);
            assert(lab);

            printf("\n            D" SIZE_LETTER "      %s", emitLabelString(lab));
        } while (--cnt);
    }
}

/*****************************************************************************
 *
 *  If the given instruction is a shift, display the 2nd operand.
 */

void emitter::emitDispShift(instruction ins, int cnt) const
{
    switch (ins)
    {
        case INS_rcl_1:
        case INS_rcr_1:
        case INS_rol_1:
        case INS_ror_1:
        case INS_shl_1:
        case INS_shr_1:
        case INS_sar_1:
            printf(", 1");
            break;

        case INS_rcl:
        case INS_rcr:
        case INS_rol:
        case INS_ror:
        case INS_shl:
        case INS_shr:
        case INS_sar:
            printf(", cl");
            break;

        case INS_rcl_N:
        case INS_rcr_N:
        case INS_rol_N:
        case INS_ror_N:
        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
            printf(", %d", cnt);
            break;

        default:
            break;
    }
}

/*****************************************************************************
 *
 *  Display (optionally) the bytes for the instruction encoding in hex
 */

void emitter::emitDispInsHex(instrDesc* id, BYTE* code, size_t sz)
{
    if (!emitComp->opts.disCodeBytes)
    {
        return;
    }

    // We do not display the instruction hex if we want diff-able disassembly
    if (!emitComp->opts.disDiffable)
    {
#ifdef TARGET_AMD64
        // how many bytes per instruction we format for
        const size_t digits = 10;
#else // TARGET_X86
        const size_t digits = 6;
#endif
        printf(" ");
        for (unsigned i = 0; i < sz; i++)
        {
            printf("%02X", (*((BYTE*)(code + i))));
        }

        if (sz < digits)
        {
            printf("%.*s", (int)(2 * (digits - sz)), "                         ");
        }
    }
}

// emitDispEmbBroadcastCount: Display the tag where embedded broadcast is activated to show how many elements are
// broadcasted.
//
// Arguments:
//   id - The instruction descriptor
//
void emitter::emitDispEmbBroadcastCount(instrDesc* id) const
{
    if (!IsEvexEncodableInstruction(id->idIns()) || !HasEmbeddedBroadcast(id))
    {
        return;
    }
    ssize_t baseSize   = GetInputSizeInBytes(id);
    ssize_t vectorSize = (ssize_t)emitGetMemOpSize(id, /* ignoreEmbeddedBroadcast */ true);
    printf(" {1to%d}", vectorSize / baseSize);
}

// emitDispEmbRounding: Display the tag where embedded rounding is activated
//
// Arguments:
//   id - The instruction descriptor
//
void emitter::emitDispEmbRounding(instrDesc* id) const
{
    if (!id->idIsEvexbContextSet())
    {
        return;
    }

    if (IsApxExtendedEvexInstruction(id->idIns()))
    {
        // Apx-Evex.nd shared the same bit(s) with Evex.b,
        // for ndd case, we don't need to display any thing special.
        return;
    }

    assert(!id->idHasMem());
    unsigned roundingMode = id->idGetEvexbContext();

    if (roundingMode == 1)
    {
        printf(" {rd-sae}");
    }
    else if (roundingMode == 2)
    {
        printf(" {ru-sae}");
    }
    else if (roundingMode == 3)
    {
        printf(" {rz-sae}");
    }
    else
    {
        unreached();
    }
}

// emitDispEmbMasking: Display the tag where embedded masking is activated
//
// Arguments:
//   id - The instruction descriptor
//
void emitter::emitDispEmbMasking(instrDesc* id) const
{
    if (!IsEvexEncodableInstruction(id->idIns()))
    {
        return;
    }

    regNumber maskReg = static_cast<regNumber>(id->idGetEvexAaaContext() + KBASE);

    if (maskReg == REG_K0)
    {
        return;
    }

    emitDispMask(id, maskReg);
}

//--------------------------------------------------------------------
// emitDispConstant: Display the constant for an instruction
//
// Arguments:
//   ins       - The instruction
//   skipComma - true if the comma separator should be skipped; otherwise false
//
void emitter::emitDispConstant(const instrDesc* id, bool skipComma) const
{
    instruction ins = id->idIns();

    if (CodeGenInterface::instHasPseudoName(ins))
    {
        switch (ins)
        {
            case INS_roundpd:
            case INS_roundps:
            case INS_roundsd:
            case INS_roundss:
            {
                // These instructions have pseudo-names, but still need to display the immediate
                break;
            }

            default:
            {
                // These instructions have pseudo-names for each possible immediate value
                return;
            }
        }
    }

    CnsVal cnsVal;

    if (id->idHasMemGen())
    {
        emitGetInsDcmCns(id, &cnsVal);
    }
    else if (id->idHasMemAdr())
    {
        emitGetInsAmdCns(id, &cnsVal);
    }
    else
    {
        emitGetInsCns(id, &cnsVal);
    }

    switch (id->idInsFmt())
    {
        case IF_RRW_SHF:
        case IF_RWR_RRD_SHF:
        case IF_MRW_SHF:
        case IF_SRW_SHF:
        case IF_ARW_SHF:
        {
            emitDispShift(ins, static_cast<BYTE>(cnsVal.cnsVal));
            return;
        }

        default:
        {
            break;
        }
    }

    if (!skipComma)
    {
        printf(", ");
    }

    if (cnsVal.cnsReloc)
    {
        emitDispReloc(cnsVal.cnsVal);
        return;
    }

    ssize_t val = cnsVal.cnsVal;

    // Munge any pointers if we want diff-able disassembly
    if (emitComp->opts.disDiffable)
    {
        ssize_t top14bits = (val >> 18);

        if ((top14bits != 0) && (top14bits != -1))
        {
            val = 0xD1FFAB1E;
        }
    }

    if ((val > -1000) && (val < 1000))
    {
        printf("%d", (int)val);
    }
    else if ((val > 0) || (val < -0xFFFFFF))
    {
        printf("0x%zX", (ssize_t)val);
    }
    else
    {
        // (val < 0)
        printf("-0x%zX", (ssize_t)-val);
    }

    emitDispCommentForHandle(cnsVal.cnsVal, id->idDebugOnlyInfo()->idMemCookie, id->idDebugOnlyInfo()->idFlags);
}

//--------------------------------------------------------------------
// emitDispIns: Dump the given instruction to jitstdout.
//
// Arguments:
//   id - The instruction
//   isNew - Whether the instruction is newly generated (before encoding).
//   doffs - If true, always display the passed-in offset.
//   asmfm - Whether the instruction should be displayed in assembly format.
//           If false some additional information may be printed for the instruction.
//   offset - The offset of the instruction. Only displayed if doffs is true or if
//            !isNew && !asmfm.
//   code - Pointer to the actual code, used for displaying the address and encoded bytes
//          if turned on.
//   sz - The size of the instruction, used to display the encoded bytes.
//   ig - The instruction group containing the instruction. Not used on xarch.
//
void emitter::emitDispIns(
    instrDesc* id, bool isNew, bool doffs, bool asmfm, unsigned offset, BYTE* code, size_t sz, insGroup* ig)
{
    emitAttr    attr;
    const char* sstr;

    instruction ins = id->idIns();

#ifdef DEBUG
    if (emitComp->verbose)
    {
        unsigned idNum = id->idDebugOnlyInfo()->idNum;
        printf("IN%04x: ", idNum);
    }
#endif

#define ID_INFO_DSP_RELOC ((bool)(id->idIsDspReloc()))

    /* Display a constant value if the instruction references one */

    if (!isNew && id->idHasMemGen())
    {
        /* Is this actually a reference to a data section? */
        int offs = Compiler::eeGetJitDataOffs(id->idAddr()->iiaFieldHnd);

        if (offs >= 0)
        {
            void* addr;

            /* Display a data section reference */

            assert((unsigned)offs < emitConsDsc.dsdOffs);
            addr = emitConsBlock ? emitConsBlock + offs : nullptr;

#if 0
            // TODO-XArch-Cleanup: Fix or remove this code.
            /* Is the operand an integer or floating-point value? */

            bool isFP = false;

            if  (CodeGen::instIsFP(id->idIns()))
            {
                switch (id->idIns())
                {
                case INS_fild:
                case INS_fildl:
                    break;

                default:
                    isFP = true;
                    break;
                }
            }

            if (offs & 1)
                printf("@CNS%02u", offs);
            else
                printf("@RWD%02u", offs);

            printf("      ");

            if  (addr)
            {
                addr = 0;
                // TODO-XArch-Bug?:
                //          This was busted by switching the order
                //          in which we output the code block vs.
                //          the data blocks -- when we get here,
                //          the data block has not been filled in
                //          yet, so we'll display garbage.

                if  (isFP)
                {
                    if  (id->idOpSize() == EA_4BYTE)
                        printf("DF      %f \n", addr ? *(float   *)addr : 0);
                    else
                        printf("DQ      %lf\n", addr ? *(double  *)addr : 0);
                }
                else
                {
                    if  (id->idOpSize() <= EA_4BYTE)
                        printf("DD      %d \n", addr ? *(int     *)addr : 0);
                    else
                        printf("DQ      %D \n", addr ? *(int64_t *)addr : 0);
                }
            }
#endif
        }
    }

    // printf("[F=%s] "   , emitIfName(id->idInsFmt()));
    // printf("INS#%03u: ", id->idDebugOnlyInfo()->idNum);
    // printf("[S=%02u] " , emitCurStackLvl); if (isNew) printf("[M=%02u] ", emitMaxStackDepth);
    // printf("[S=%02u] " , emitCurStackLvl/sizeof(INT32));
    // printf("[A=%08X] " , emitSimpleStkMask);
    // printf("[A=%08X] " , emitSimpleByrefStkMask);
    // printf("[L=%02u] " , id->idCodeSize());

    if (!isNew && !asmfm)
    {
        doffs = true;
    }

    /* Display the instruction address */

    emitDispInsAddr(code);

    /* Display the instruction offset */

    emitDispInsOffs(offset, doffs);

    if (code != nullptr)
    {
        /* Display the instruction hex code */
        assert(((code >= emitCodeBlock) && (code < emitCodeBlock + emitTotalHotCodeSize)) ||
               ((code >= emitColdCodeBlock) && (code < emitColdCodeBlock + emitTotalColdCodeSize)));

        emitDispInsHex(id, code + writeableOffset, sz);
    }

    /* Display the instruction name */

#ifdef TARGET_AMD64
    if (IsApxNfEncodableInstruction(id->idIns()) && id->idIsEvexNfContextSet())
    {
        // print the EVEX.NF indication in psudeo prefix style.
        printf("{nf}    ");
    }
#endif // TARGET_AMD64

    sstr = codeGen->genInsDisplayName(id);
    printf(" %-9s", sstr);

#ifdef TARGET_AMD64
    if (IsCCMP(id->idIns()))
    {
        // print finite set notation for DFV
        unsigned dfv        = id->idGetEvexDFV();
        char     dfvstr[20] = {0};
        int      len        = 0;
        if (dfv & INS_FLAGS_OF)
            len += snprintf(dfvstr + len, 4, "of,");
        if (dfv & INS_FLAGS_SF)
            len += snprintf(dfvstr + len, 4, "sf,");
        if (dfv & INS_FLAGS_ZF)
            len += snprintf(dfvstr + len, 4, "zf,");
        if (dfv & INS_FLAGS_CF)
            len += snprintf(dfvstr + len, 4, "cf,");
        if (len)
            dfvstr[len - 1] = 0;
        printf("{dfv=%s}    ", dfvstr);
    }
#endif // TARGET_AMD64

#ifndef HOST_UNIX
    if (strnlen_s(sstr, 10) >= 9)
#else  // HOST_UNIX
    if (strnlen(sstr, 10) >= 9)
#endif // HOST_UNIX
    {
        // Make sure there's at least one space after the instruction name, for very long instruction names.
        printf(" ");
    }

    /* By now the size better be set to something */

    assert(id->idCodeSize() || emitInstHasNoCode(id));

    /* Figure out the operand size */

    if (id->idGCref() == GCT_GCREF)
    {
        attr = EA_GCREF;
        sstr = "gword ptr ";
    }
    else if (id->idGCref() == GCT_BYREF)
    {
        attr = EA_BYREF;
        sstr = "bword ptr ";
    }
    else
    {
        attr = id->idOpSize();
        sstr = codeGen->genSizeStr(emitGetMemOpSize(id, !id->idHasMem()));

        if (ins == INS_lea)
        {
#ifdef TARGET_AMD64
            assert((attr == EA_4BYTE) || (attr == EA_8BYTE));
#else
            assert(attr == EA_4BYTE);
#endif
            sstr = "";
        }
    }

    /* Now see what instruction format we've got */

    // First print the implicit register usage
    if (instrHasImplicitRegPairDest(ins))
    {
        printf("%s:%s, ", emitRegName(REG_EDX, id->idOpSize()), emitRegName(REG_EAX, id->idOpSize()));
    }
    else if (instrIs3opImul(ins))
    {
        regNumber tgtReg = inst3opImulReg(ins);
        printf("%s, ", emitRegName(tgtReg, id->idOpSize()));
    }

    switch (id->idInsFmt())
    {
        ssize_t     offs;
        const char* methodName;

        case IF_CNS:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            emitDispConstant(id, /* skipComma */ true);
            break;
        }

        case IF_ARD:
        case IF_AWR:
        case IF_ARW:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));

            if (((ins == INS_call) || (ins == INS_tail_i_jmp)) && id->idIsCallRegPtr())
            {
                printf("%s", emitRegName(id->idAddr()->iiaAddrMode.amBaseReg));
            }
            else
            {
                // GC ref bit is for the return value for calls, do not print it before the address mode
                if ((ins != INS_call) && (ins != INS_tail_i_jmp))
                {
                    printf("%s", sstr);
                }

                emitDispAddrMode(id, isNew);
                emitDispShift(ins);
            }

            if ((ins == INS_call) || (ins == INS_tail_i_jmp))
            {
                assert(id->idInsFmt() == IF_ARD);

                /* Ignore indirect calls */

                if (id->idDebugOnlyInfo()->idMemCookie == 0)
                {
                    break;
                }

                assert(id->idDebugOnlyInfo()->idMemCookie);

                if (id->idIsCallRegPtr())
                {
                    printf(" ; ");
                }

                /* This is a virtual call */

                methodName = emitComp->eeGetMethodFullName((CORINFO_METHOD_HANDLE)id->idDebugOnlyInfo()->idMemCookie);
                printf("%s", methodName);
            }
            break;
        }

        case IF_RRD_ARD:
        case IF_RWR_ARD:
        case IF_RRW_ARD:
        {
#ifdef TARGET_AMD64
            if (ins == INS_movsxd)
            {
                attr = EA_8BYTE;
            }
            else
#endif
                if (ins == INS_movsx || ins == INS_movzx)
            {
                attr = EA_PTRSIZE;
            }
            else if ((ins == INS_crc32) && (attr != EA_8BYTE))
            {
                // The idReg1 is always 4 bytes, but the size of idReg2 can vary.
                // This logic ensures that we print `crc32 eax, bx` instead of `crc32 ax, bx`
                attr = EA_4BYTE;
            }
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);

            emitDispCommentForHandle(id->idDebugOnlyInfo()->idMemCookie, 0, id->idDebugOnlyInfo()->idFlags);
            break;
        }

        case IF_RRD_ARD_CNS:
        case IF_RRW_ARD_CNS:
        case IF_RWR_ARD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_ARD_RRD_CNS:
        case IF_AWR_RRD_CNS:
        case IF_ARW_RRD_CNS:
        {
            switch (ins)
            {
                case INS_vextractf32x4:
                case INS_vextractf64x2:
                case INS_vextracti32x4:
                case INS_vextracti64x2:
                {
                    // vextracti/f128 extracts 128-bit data, so we fix sstr as "xmm ptr"
                    sstr = codeGen->genSizeStr(EA_ATTR(16));
                    break;
                }

                case INS_vextractf32x8:
                case INS_vextractf64x4:
                case INS_vextracti32x8:
                case INS_vextracti64x4:
                {
                    // vextracti/f*x* extracts 256-bit data, so we fix sstr as "ymm ptr"
                    sstr = codeGen->genSizeStr(EA_ATTR(32));
                    break;
                }

                default:
                {
                    break;
                }
            }

            printf(sstr);
            emitDispAddrMode(id);
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg1(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RRD_RRD_ARD:
        case IF_RWR_RRD_ARD:
        case IF_RRW_RRD_ARD:
        case IF_RWR_RWR_ARD:
        {
            if ((ins == INS_bextr) || (ins == INS_bzhi) || (ins == INS_sarx) || (ins == INS_shlx) || (ins == INS_shrx))
            {
                // These instructions have their operands swapped to simplify the emitter implementation.
                // They will appear here as IF_RWR_RRD_ARD but should actually
                // display as if they were  IF_RWR_ARD_RRD.

                printf("%s", emitRegName(id->idReg1(), attr));
                printf(", %s", sstr);
                emitDispAddrMode(id);
                printf(", %s", emitRegName(id->idReg2(), attr));
                break;
            }

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);
            break;
        }

        case IF_RRD_ARD_RRD:
        case IF_RWR_ARD_RRD:
        case IF_RRW_ARD_RRD:
        {
            if (ins == INS_vpgatherqd || ins == INS_vgatherqps)
            {
                attr = EA_16BYTE;
            }
            sstr = codeGen->genSizeStr(EA_ATTR(4));
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);
            printf(", %s", emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_RWR_RRD_ARD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_RWR_RRD_ARD_RRD:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);

            CnsVal cnsVal;
            emitGetInsAmdCns(id, &cnsVal);
            regNumber op3Reg     = decodeRegFromIval(cnsVal.cnsVal);
            bool      hasMaskReg = isMaskReg(op3Reg);

            if (hasMaskReg)
            {
                emitDispMask(id, op3Reg);
            }

            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispAddrMode(id);
            emitDispEmbBroadcastCount(id);

            if (!hasMaskReg)
            {
                printf(", %s", emitRegName(op3Reg, attr));
            }
            break;
        }

        case IF_ARD_RRD:
        case IF_AWR_RRD:
        case IF_ARW_RRD:
        case IF_ARW_RRW:
        {
            printf("%s", sstr);
            emitDispAddrMode(id);
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg1(), attr));
            break;
        }

        case IF_AWR_RRD_RRD:
        {
            printf("%s", sstr);
            emitDispAddrMode(id);
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg1(), attr));
            printf(", %s", emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_ARD_CNS:
        case IF_AWR_CNS:
        case IF_ARW_CNS:
        case IF_ARW_SHF:
        {
            printf("%s", sstr);
            emitDispAddrMode(id);
            emitDispEmbMasking(id);
            emitDispConstant(id);
            break;
        }

        case IF_SRD:
        case IF_SWR:
        case IF_SRW:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            printf("%s", sstr);

#if !FEATURE_FIXED_OUT_ARGS
            if (ins == INS_pop)
                emitCurStackLvl -= sizeof(int);
#endif

            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);

#if !FEATURE_FIXED_OUT_ARGS
            if (ins == INS_pop)
                emitCurStackLvl += sizeof(int);
#endif

            emitDispShift(ins);
            break;
        }

        case IF_SRD_RRD:
        case IF_SWR_RRD:
        case IF_SRW_RRD:
        case IF_SRW_RRW:
        {
            printf("%s", sstr);

            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbMasking(id);

            printf(", %s", emitRegName(id->idReg1(), attr));
            break;
        }

        case IF_SRD_CNS:
        case IF_SWR_CNS:
        case IF_SRW_CNS:
        case IF_SRW_SHF:
        {
            printf("%s", sstr);

            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbMasking(id);
            emitDispConstant(id);
            break;
        }

        case IF_SRD_RRD_CNS:
        case IF_SWR_RRD_CNS:
        case IF_SRW_RRD_CNS:
        {
            assert(IsSSEOrAVXInstruction(ins));
            printf("%s", sstr);

            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbMasking(id);

            printf(", %s", emitRegName(id->idReg1(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RRD_SRD:
        case IF_RWR_SRD:
        case IF_RRW_SRD:
        {
#ifdef TARGET_AMD64
            if (ins == INS_movsxd)
            {
                attr = EA_8BYTE;
            }
            else
#endif
                if (ins == INS_movsx || ins == INS_movzx)
            {
                attr = EA_PTRSIZE;
            }
            else if ((ins == INS_crc32) && (attr != EA_8BYTE))
            {
                // The idReg1 is always 4 bytes, but the size of idReg2 can vary.
                // This logic ensures that we print `crc32 eax, bx` instead of `crc32 ax, bx`
                attr = EA_4BYTE;
            }

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);

            break;
        }

        case IF_RRD_SRD_CNS:
        case IF_RWR_SRD_CNS:
        case IF_RRW_SRD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_RRD_RRD_SRD:
        case IF_RWR_RRD_SRD:
        case IF_RRW_RRD_SRD:
        case IF_RWR_RWR_SRD:
        {
            if ((ins == INS_bextr) || (ins == INS_bzhi) || (ins == INS_sarx) || (ins == INS_shlx) || (ins == INS_shrx))
            {
                // These instructions have their operands swapped to simplify the emitter implementation.
                // They will appear here as IF_RWR_RRD_SRD but should actually
                // display as if they were  IF_RWR_SRD_RRD.

                printf("%s", emitRegName(id->idReg1(), attr));
                printf(", %s", sstr);
                emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                                 id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
                printf(", %s", emitRegName(id->idReg2(), attr));
                break;
            }

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);
            break;
        }

        case IF_RWR_RRD_SRD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_RWR_RRD_SRD_RRD:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);

            CnsVal cnsVal;
            emitGetInsCns(id, &cnsVal);
            regNumber op3Reg     = decodeRegFromIval(cnsVal.cnsVal);
            bool      hasMaskReg = isMaskReg(op3Reg);

            if (hasMaskReg)
            {
                emitDispMask(id, op3Reg);
            }

            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);

            if (!hasMaskReg)
            {
                printf(", %s", emitRegName(op3Reg, attr));
            }
            break;
        }

        case IF_RRD_SRD_RRD:
        case IF_RWR_SRD_RRD:
        case IF_RRW_SRD_RRD:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);

            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbBroadcastCount(id);
            printf(", %s", emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_SWR_RRD_RRD:
        {
            printf("%s", sstr);
            emitDispFrameRef(id->idAddr()->iiaLclVar.lvaVarNum(), id->idAddr()->iiaLclVar.lvaOffset(),
                             id->idDebugOnlyInfo()->idVarRefOffs, asmfm);
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg1(), attr), emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_RRD_RRD:
        case IF_RWR_RRD:
        case IF_RRW_RRD:
        case IF_RRW_RRW:
        {
            switch (ins)
            {
                case INS_pmovmskb:
                {
                    assert(!id->idIsEvexAaaContextSet());
                    printf("%s, %s", emitRegName(id->idReg1(), EA_4BYTE), emitRegName(id->idReg2(), attr));
                    break;
                }

                case INS_cvtsi2ss32:
                case INS_cvtsi2sd32:
                case INS_cvtsi2ss64:
                case INS_cvtsi2sd64:
                {
                    assert(!id->idIsEvexAaaContextSet());
                    printf("%s, %s", emitRegName(id->idReg1(), EA_16BYTE), emitRegName(id->idReg2(), attr));
                    break;
                }

                case INS_cvttsd2si32:
                case INS_cvttsd2si64:
                case INS_cvtsd2si32:
                case INS_cvtsd2si64:
                case INS_cvtss2si32:
                case INS_cvtss2si64:
                case INS_cvttss2si32:
                case INS_cvttss2si64:
                case INS_vcvtsd2usi32:
                case INS_vcvtsd2usi64:
                case INS_vcvtss2usi32:
                case INS_vcvtss2usi64:
                case INS_vcvttsd2usi32:
                case INS_vcvttsd2usi64:
                case INS_vcvttss2usi32:
                case INS_vcvttss2usi64:
                case INS_vcvttsd2sis32:
                case INS_vcvttsd2sis64:
                case INS_vcvttss2sis32:
                case INS_vcvttss2sis64:
                case INS_vcvttsd2usis32:
                case INS_vcvttsd2usis64:
                case INS_vcvttss2usis32:
                case INS_vcvttss2usis64:
                {
                    assert(!id->idIsEvexAaaContextSet());
                    printf("%s, %s", emitRegName(id->idReg1(), attr), emitRegName(id->idReg2(), EA_16BYTE));
                    break;
                }

#ifdef TARGET_AMD64
                case INS_movsxd:
                {
                    printf("%s, %s", emitRegName(id->idReg1(), EA_8BYTE), emitRegName(id->idReg2(), EA_4BYTE));
                    break;
                }
#endif // TARGET_AMD64

                case INS_movsx:
                case INS_movzx:
                {
                    printf("%s, %s", emitRegName(id->idReg1(), EA_PTRSIZE), emitRegName(id->idReg2(), attr));
                    break;
                }

                case INS_bt:
                {
                    // INS_bt operands are reversed. Display them in the normal order.
                    printf("%s, %s", emitRegName(id->idReg2(), attr), emitRegName(id->idReg1(), attr));
                    break;
                }

                case INS_crc32:
                {
                    if (attr != EA_8BYTE)
                    {
                        // The idReg1 is always 4 bytes, but the size of idReg2 can vary.
                        // This logic ensures that we print `crc32 eax, bx` instead of `crc32 ax, bx`
                        printf("%s, %s", emitRegName(id->idReg1(), EA_4BYTE), emitRegName(id->idReg2(), attr));
                    }
                    else
                    {
                        printf("%s, %s", emitRegName(id->idReg1(), attr), emitRegName(id->idReg2(), attr));
                    }
                    break;
                }

                case INS_vpbroadcastb_gpr:
                case INS_vpbroadcastd_gpr:
                case INS_vpbroadcastw_gpr:
                {
                    printf("%s", emitRegName(id->idReg1(), attr));
                    emitDispEmbMasking(id);
                    printf(", %s", emitRegName(id->idReg2(), EA_4BYTE));
                    break;
                }

                case INS_vpbroadcastq_gpr:
                {
                    printf("%s", emitRegName(id->idReg1(), attr));
                    emitDispEmbMasking(id);
                    printf(", %s", emitRegName(id->idReg2(), EA_8BYTE));
                    break;
                }

                case INS_rol:
                case INS_ror:
                case INS_rcl:
                case INS_rcr:
                case INS_shl:
                case INS_shr:
                case INS_sar:
                {
                    printf("%s", emitRegName(id->idReg1(), attr));
                    printf(", %s", emitRegName(id->idReg2(), attr));
                    emitDispShift(ins, (BYTE)0);
                    break;
                }

                default:
                {
                    printf("%s", emitRegName(id->idReg1(), attr));
                    emitDispEmbMasking(id);
                    printf(", %s", emitRegName(id->idReg2(), attr));
                    emitDispEmbRounding(id);
                    break;
                }
            }
            break;
        }

        case IF_RRD_RRD_RRD:
        case IF_RWR_RRD_RRD:
        case IF_RRW_RRD_RRD:
        case IF_RWR_RWR_RRD:
        {
            assert(IsVexOrEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));
            assert(IsThreeOperandAVXInstruction(ins) || IsKInstruction(ins) || IsApxExtendedEvexInstruction(ins));

            regNumber reg2 = id->idReg2();
            regNumber reg3 = id->idReg3();

            if ((ins == INS_bextr) || (ins == INS_bzhi) || (ins == INS_sarx) || (ins == INS_shlx) || (ins == INS_shrx))
            {
                // These instructions have their operands swapped to simplify the emitter implementation.
                // They encode reg3 in VEX.vvvv and reg2 in modRM, which is opposite most instructions.
                // We swap them back here so they will display in the correct order.
                std::swap(reg2, reg3);
            }

            emitAttr attr3 = attr;
            if ((insTupleTypeInfo(ins) & INS_TT_MEM128) != 0)
            {
                // Shift instructions take xmm for the 3rd operand regardless of instruction size.
                attr3 = EA_16BYTE;
            }

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, ", emitRegName(reg2, attr));
            printf("%s", emitRegName(reg3, attr3));
            emitDispEmbRounding(id);
            break;
        }

        case IF_RWR_RRD_RRD_CNS:
        {
            assert(IsVexOrEvexEncodableInstruction(ins));
            assert(IsThreeOperandAVXInstruction(ins));

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg2(), attr));

            switch (ins)
            {
                case INS_vinsertf32x8:
                case INS_vinsertf64x4:
                case INS_vinserti32x8:
                case INS_vinserti64x4:
                {
                    attr = EA_32BYTE;
                    break;
                }

                case INS_vinsertf32x4:
                case INS_vinsertf64x2:
                case INS_vinserti32x4:
                case INS_vinserti64x2:
                {
                    attr = EA_16BYTE;
                    break;
                }

                case INS_pinsrb:
                case INS_pinsrw:
                case INS_pinsrd:
                {
                    attr = EA_4BYTE;
                    break;
                }

                case INS_pinsrq:
                {
                    attr = EA_8BYTE;
                    break;
                }

                default:
                {
                    break;
                }
            }

            printf(", %s", emitRegName(id->idReg3(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RWR_RRD_RRD_RRD:
        {
            assert(IsVexOrEvexEncodableInstruction(ins));
            assert(UseVEXEncoding());

            printf("%s", emitRegName(id->idReg1(), attr));

            regNumber op4Reg     = id->idReg4();
            bool      hasMaskReg = isMaskReg(op4Reg);

            if (hasMaskReg)
            {
                emitDispMask(id, op4Reg);
            }

            printf(", %s, %s", emitRegName(id->idReg2(), attr), emitRegName(id->idReg3(), attr));

            if (!hasMaskReg)
            {
                printf(", %s", emitRegName(op4Reg, attr));
            }
            break;
        }

        case IF_RRD_RRD_CNS:
        case IF_RWR_RRD_CNS:
        case IF_RRW_RRD_CNS:
        {
            emitAttr tgtAttr = attr;

            switch (ins)
            {
                case INS_vextractf32x4:
                case INS_vextractf64x2:
                case INS_vextracti32x4:
                case INS_vextracti64x2:
                {
                    tgtAttr = EA_16BYTE;
                    break;
                }

                case INS_vextractf32x8:
                case INS_vextractf64x4:
                case INS_vextracti32x8:
                case INS_vextracti64x4:
                {
                    tgtAttr = EA_32BYTE;
                    break;
                }

                case INS_extractps:
                case INS_pextrb:
                case INS_pextrw:
                case INS_pextrw_sse42:
                case INS_pextrd:
                {
                    tgtAttr = EA_4BYTE;
                    break;
                }

                case INS_pextrq:
                {
                    tgtAttr = EA_8BYTE;
                    break;
                }

                case INS_pinsrb:
                case INS_pinsrw:
                case INS_pinsrd:
                {
                    attr = EA_4BYTE;
                    break;
                }

                case INS_pinsrq:
                {
                    attr = EA_8BYTE;
                    break;
                }

                default:
                {
                    break;
                }
            }

            printf("%s", emitRegName(id->idReg1(), tgtAttr));
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg2(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RRD:
        case IF_RWR:
        case IF_RRW:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispShift(ins);
            break;
        }

        case IF_RRD_CNS:
        case IF_RWR_CNS:
        case IF_RRW_CNS:
        case IF_RRW_SHF:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            emitDispConstant(id);
            break;
        }

        case IF_RWR_RRD_SHF:
        {
            assert(IsApxExtendedEvexInstruction(id->idIns()));
            printf("%s, %s", emitRegName(id->idReg1(), attr), emitRegName(id->idReg2(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RRD_MRD:
        case IF_RWR_MRD:
        case IF_RRW_MRD:
        {
            if (ins == INS_movsx || ins == INS_movzx)
            {
                attr = EA_PTRSIZE;
            }
#ifdef TARGET_AMD64
            else if (ins == INS_movsxd)
            {
                attr = EA_PTRSIZE;
            }
#endif
            else if ((ins == INS_crc32) && (attr != EA_8BYTE))
            {
                // The idReg1 is always 4 bytes, but the size of idReg2 can vary.
                // This logic ensures that we print `crc32 eax, bx` instead of `crc32 ax, bx`
                attr = EA_4BYTE;
            }
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);
            break;
        }

        case IF_RRD_MRD_CNS:
        case IF_RWR_MRD_CNS:
        case IF_RRW_MRD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s", sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_MRD_RRD_CNS:
        case IF_MWR_RRD_CNS:
        case IF_MRW_RRD_CNS:
        {
            switch (ins)
            {
                case INS_vextractf32x4:
                case INS_vextractf64x2:
                case INS_vextracti32x4:
                case INS_vextracti64x2:
                {
                    // vextracti/f128 extracts 128-bit data, so we fix sstr as "xmm ptr"
                    sstr = codeGen->genSizeStr(EA_ATTR(16));
                    break;
                }

                case INS_vextractf32x8:
                case INS_vextractf64x4:
                case INS_vextracti32x8:
                case INS_vextracti64x4:
                {
                    // vextracti/f*x* extracts 256-bit data, so we fix sstr as "ymm ptr"
                    sstr = codeGen->genSizeStr(EA_ATTR(32));
                    break;
                }

                default:
                {
                    break;
                }
            }

            printf(sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg1(), attr));
            emitDispConstant(id);
            break;
        }

        case IF_RRD_RRD_MRD:
        case IF_RWR_RRD_MRD:
        case IF_RRW_RRD_MRD:
        case IF_RWR_RWR_MRD:
        {
            if ((ins == INS_bextr) || (ins == INS_bzhi) || (ins == INS_sarx) || (ins == INS_shlx) || (ins == INS_shrx))
            {
                // These instructions have their operands swapped to simplify the emitter implementation.
                // They will appear here as IF_RWR_RRD_MRD but should actually
                // display as if they were  IF_RWR_MRD_RRD.

                printf("%s", emitRegName(id->idReg1(), attr));
                printf(", %s", sstr);
                offs = emitGetInsDsp(id);
                emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
                printf(", %s", emitRegName(id->idReg2(), attr));
                break;
            }

            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);
            break;
        }

        case IF_RWR_RRD_MRD_CNS:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);
            emitDispConstant(id);
            break;
        }

        case IF_RWR_RRD_MRD_RRD:
        {
            printf("%s", emitRegName(id->idReg1(), attr));

            CnsVal cnsVal;
            emitGetInsDcmCns(id, &cnsVal);
            regNumber op3Reg     = decodeRegFromIval(cnsVal.cnsVal);
            bool      hasMaskReg = isMaskReg(op3Reg);

            if (hasMaskReg)
            {
                emitDispMask(id, op3Reg);
            }

            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);

            if (!hasMaskReg)
            {
                printf(", %s", emitRegName(op3Reg, attr));
            }
            break;
        }

        case IF_RWR_MRD_OFF:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            printf("%s, %s", emitRegName(id->idReg1(), attr), "offset");
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            break;
        }

        case IF_MRD_RRD:
        case IF_MWR_RRD:
        case IF_MRW_RRD:
        case IF_MRW_RRW:
        {
            printf("%s", sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbMasking(id);
            printf(", %s", emitRegName(id->idReg1(), attr));
            break;
        }

        case IF_MRD_CNS:
        case IF_MWR_CNS:
        case IF_MRW_CNS:
        case IF_MRW_SHF:
        {
            printf("%s", sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbMasking(id);
            emitDispConstant(id);
            break;
        }

        case IF_MRD:
        case IF_MWR:
        case IF_MRW:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            printf("%s", sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispShift(ins);
            break;
        }

        case IF_MRD_OFF:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            printf("offset ");
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            break;
        }

        case IF_RRD_MRD_RRD:
        case IF_RWR_MRD_RRD:
        case IF_RRW_MRD_RRD:
        {
            printf("%s", emitRegName(id->idReg1(), attr));
            emitDispEmbMasking(id);
            printf(", %s, %s", emitRegName(id->idReg2(), attr), sstr);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            emitDispEmbBroadcastCount(id);
            printf(", %s", emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_MWR_RRD_RRD:
        {
            printf("%s", sstr);
            emitDispEmbMasking(id);
            offs = emitGetInsDsp(id);
            emitDispClsVar(id->idAddr()->iiaFieldHnd, offs, ID_INFO_DSP_RELOC);
            printf(", %s, %s", emitRegName(id->idReg1(), attr), emitRegName(id->idReg2(), attr));
            break;
        }

        case IF_LABEL:
        case IF_RWR_LABEL:
        case IF_SWR_LABEL:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));

            if (ins == INS_lea)
            {
                printf("%s, ", emitRegName(id->idReg1(), attr));
            }
            else if (ins == INS_mov)
            {
                /* mov   dword ptr [frame.callSiteReturnAddress], label */
                assert(id->idInsFmt() == IF_SWR_LABEL);
                instrDescLbl* idlbl = (instrDescLbl*)id;

                emitDispFrameRef(idlbl->dstLclVar.lvaVarNum(), idlbl->dstLclVar.lvaOffset(), 0, asmfm);

                printf(", ");
            }

            if (((instrDescJmp*)id)->idjShort)
            {
                printf("SHORT ");
            }

            if (id->idIsBound())
            {
                if (id->idAddr()->iiaHasInstrCount())
                {
                    printf("%3d instr", id->idAddr()->iiaGetInstrCount());
                }
                else
                {
                    emitPrintLabel(id->idAddr()->iiaIGlabel);
                }
            }
            else
            {
                printf("L_M%03u_" FMT_BB, emitComp->compMethodID, id->idAddr()->iiaBBlabel->bbNum);
            }
            break;
        }

        case IF_METHOD:
        case IF_METHPTR:
        {
            assert(!IsEvexEncodableInstruction(id->idIns()));
            methodName = emitComp->eeGetMethodFullName((CORINFO_METHOD_HANDLE)id->idDebugOnlyInfo()->idMemCookie);

            if (id->idInsFmt() == IF_METHPTR)
            {
                printf("[");
            }

            printf("%s", methodName);

            if (id->idInsFmt() == IF_METHPTR)
            {
                printf("]");
            }

            break;
        }

        case IF_NONE:
        {
#if FEATURE_LOOP_ALIGN
            if (ins == INS_align)
            {
                instrDescAlign* alignInstrId = (instrDescAlign*)id;
                printf("[%d bytes", alignInstrId->idCodeSize());
                // targetIG is only set for 1st of the series of align instruction
                if ((alignInstrId->idaLoopHeadPredIG != nullptr) && (alignInstrId->loopHeadIG() != nullptr))
                {
                    printf(" for IG%02u", alignInstrId->loopHeadIG()->igNum);
                }
                printf("]");
            }
#endif
            break;
        }

        default:
            printf("unexpected format %s", emitIfName(id->idInsFmt()));
            assert(!"unexpectedFormat");
            break;
    }

#ifdef DEBUG
    if (sz != 0 && sz != id->idCodeSize() && (!asmfm || emitComp->verbose))
    {
        // Code size in the instrDesc is different from the actual code size we've been given!
        printf(" (ECS:%d, ACS:%d)", id->idCodeSize(), sz);
    }
#endif

    printf("\n");
}

/*****************************************************************************
 *
 *  Output 0x66 byte of `data16` instructions
 */

BYTE* emitter::emitOutputData16(BYTE* dst)
{
#ifdef TARGET_AMD64
    BYTE* dstRW = dst + writeableOffset;
    *dstRW++    = 0x66;
    return dstRW - writeableOffset;
#else
    return dst;
#endif
}

/*****************************************************************************
 *
 *  Output nBytes bytes of NOP instructions
 */

BYTE* emitter::emitOutputNOP(BYTE* dst, size_t nBytes)
{
    assert(nBytes <= 15);

    BYTE* dstRW = dst + writeableOffset;

#ifndef TARGET_AMD64
    // TODO-X86-CQ: when VIA C3 CPU's are out of circulation, switch to the
    // more efficient real NOP: 0x0F 0x1F +modR/M
    // Also can't use AMD recommended, multiple size prefixes (i.e. 0x66 0x66 0x90 for 3 byte NOP)
    // because debugger and msdis don't like it, so maybe VIA doesn't either
    // So instead just stick to repeating single byte nops

    switch (nBytes)
    {
        case 15:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 14:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 13:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 12:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 11:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 10:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 9:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 8:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 7:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 6:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 5:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 4:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 3:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 2:
            *dstRW++ = 0x90;
            FALLTHROUGH;
        case 1:
            *dstRW++ = 0x90;
            break;
        case 0:
            break;
    }
#else  // TARGET_AMD64
    switch (nBytes)
    {
        case 2:
            *dstRW++ = 0x66;
            FALLTHROUGH;
        case 1:
            *dstRW++ = 0x90;
            break;
        case 0:
            break;
        case 3:
            *dstRW++ = 0x0F;
            *dstRW++ = 0x1F;
            *dstRW++ = 0x00;
            break;
        case 4:
            *dstRW++ = 0x0F;
            *dstRW++ = 0x1F;
            *dstRW++ = 0x40;
            *dstRW++ = 0x00;
            break;
        case 6:
            *dstRW++ = 0x66;
            FALLTHROUGH;
        case 5:
            *dstRW++ = 0x0F;
            *dstRW++ = 0x1F;
            *dstRW++ = 0x44;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            break;
        case 7:
            *dstRW++ = 0x0F;
            *dstRW++ = 0x1F;
            *dstRW++ = 0x80;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            break;
        case 15:
            // More than 3 prefixes is slower than just 2 NOPs
            return emitOutputNOP(emitOutputNOP(dst, 7), 8);
        case 14:
            // More than 3 prefixes is slower than just 2 NOPs
            return emitOutputNOP(emitOutputNOP(dst, 7), 7);
        case 13:
            // More than 3 prefixes is slower than just 2 NOPs
            return emitOutputNOP(emitOutputNOP(dst, 5), 8);
        case 12:
            // More than 3 prefixes is slower than just 2 NOPs
            return emitOutputNOP(emitOutputNOP(dst, 4), 8);
        case 11:
            *dstRW++ = 0x66;
            FALLTHROUGH;
        case 10:
            *dstRW++ = 0x66;
            FALLTHROUGH;
        case 9:
            *dstRW++ = 0x66;
            FALLTHROUGH;
        case 8:
            *dstRW++ = 0x0F;
            *dstRW++ = 0x1F;
            *dstRW++ = 0x84;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            *dstRW++ = 0x00;
            break;
    }
#endif // TARGET_AMD64

    return dstRW - writeableOffset;
}

//--------------------------------------------------------------------
// emitOutputAlign: Outputs NOP to align the loop
//
// Arguments:
//   ig - Current instruction group
//   id - align instruction that holds amount of padding (NOPs) to add
//   dst - Destination buffer
//
// Return Value:
//   None.
//
// Notes:
//   Amount of padding needed to align the loop is already calculated. This
//   method extracts that information and inserts suitable NOP instructions.
//
BYTE* emitter::emitOutputAlign(insGroup* ig, instrDesc* id, BYTE* dst)
{
    instrDescAlign* alignInstr = (instrDescAlign*)id;

#ifdef DEBUG
    // For cases where 'align' was placed behind a 'jmp' in an IG that does not
    // immediately precede the loop IG, we do not know in advance the offset of
    // IG having loop. For such cases, skip the padding calculation validation.

    // For AOT, `dst` is not aligned as requested, but the final assembly will have them aligned.
    // So, just calculate the offset of the current `dst` from the start.
    size_t offset          = emitComp->IsAot() ? emitCurCodeOffs(dst) : (size_t)dst;
    bool   validatePadding = !alignInstr->isPlacedAfterJmp;
#endif

    // Candidate for loop alignment
    assert(codeGen->ShouldAlignLoops());
    assert(ig->endsWithAlignInstr());

    unsigned paddingToAdd = id->idCodeSize();

    // Either things are already aligned or align them here.
    assert(!validatePadding || (paddingToAdd == 0) || ((offset & (emitComp->opts.compJitAlignLoopBoundary - 1)) != 0));

    // Padding amount should not exceed the alignment boundary
    assert(0 <= paddingToAdd && paddingToAdd < emitComp->opts.compJitAlignLoopBoundary);

#ifdef DEBUG
    if (validatePadding)
    {
        unsigned paddingNeeded =
            emitCalculatePaddingForLoopAlignment(((instrDescAlign*)id)->idaIG->igNext, offset, true, 0, 0);

        // For non-adaptive, padding size is spread in multiple instructions, so don't bother checking
        if (emitComp->opts.compJitAlignLoopAdaptive)
        {
            assert(paddingToAdd == paddingNeeded);
        }
    }
#endif

    emitComp->Metrics.LoopsAligned++;

#ifdef DEBUG
    // Under STRESS_EMITTER, if this is the 'align' before the 'jmp' instruction,
    // then add "int3" instruction. Since int3 takes 1 byte, we would only add
    // it if paddingToAdd >= 1 byte.

    if (emitComp->compStressCompile(Compiler::STRESS_EMITTER, 50) && alignInstr->isPlacedAfterJmp && paddingToAdd >= 1)
    {
        size_t int3Code = insCodeMR(INS_BREAKPOINT);
        // There is no good way to squeeze in "int3" as well as display it
        // in the disassembly because there is no corresponding instrDesc for
        // it. As such, leave it as is, the "0xCC" bytecode will be seen next
        // to the nop instruction in disasm.
        // e.g. CC                   align    [1 bytes for IG29]
        //
        // if (emitComp->opts.disAsm)
        //{
        //    emitDispInsAddr(dstRW);

        //    emitDispInsOffs(0, false);

        //    printf("                      %-9s  ; stress-mode injected interrupt\n", "int3");
        //}
        dst += emitOutputByte(dst, int3Code);
        paddingToAdd -= 1;
    }
#endif

    return emitOutputNOP(dst, paddingToAdd);
}

/*****************************************************************************
 *
 *  Output an instruction involving an address mode.
 */

BYTE* emitter::emitOutputAM(BYTE* dst, instrDesc* id, code_t code, CnsVal* addc)
{
    assert(id->idHasMemAdr());

    regNumber reg;
    regNumber rgx;
    ssize_t   dsp;
    bool      dspInByte;
    bool      dspIsZero;
    bool      isMoffset = false;

    instruction ins  = id->idIns();
    emitAttr    size = id->idOpSize();
    size_t      opsz = EA_SIZE_IN_BYTES(size);

    // Get the base/index registers
    reg = id->idAddr()->iiaAddrMode.amBaseReg;
    rgx = id->idAddr()->iiaAddrMode.amIndxReg;

    // For INS_call the instruction size is actually the return value size
    if ((ins == INS_call) || (ins == INS_tail_i_jmp))
    {
        code = AddX86PrefixIfNeeded(id, code, size);
        if (ins == INS_tail_i_jmp)
        {
            // tail call with addressing mode (or through register) needs rex.w
            // prefix to be recognized by unwinder as part of epilog.
            code = AddRexWPrefix(id, code);
        }

        // Special case: call via a register
        if (id->idIsCallRegPtr())
        {
            code = insEncodeMRreg(id, reg, EA_PTRSIZE, code);
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
            dst += emitOutputWord(dst, code);
            goto DONE;
        }

        // The displacement field is in an unusual place for calls
        dsp = emitGetInsCIdisp(id);

#ifdef TARGET_AMD64

        // Compute the REX prefix if it exists
        if (IsExtendedReg(reg, EA_PTRSIZE))
        {
            insEncodeReg012(id, reg, EA_PTRSIZE, &code);
            // TODO-Cleanup: stop casting RegEncoding() back to a regNumber.
            reg = (regNumber)RegEncoding(reg);
        }

        if (IsExtendedReg(rgx, EA_PTRSIZE))
        {
            insEncodeRegSIB(id, rgx, &code);
            // TODO-Cleanup: stop casting RegEncoding() back to a regNumber.
            rgx = (regNumber)RegEncoding(rgx);
        }

        // And emit the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

#endif // TARGET_AMD64

        goto GOT_DSP;
    }

    // `addc` is used for two kinds if instructions
    // 1. ins like ADD that can have reg/mem and const versions both and const version needs to modify the opcode for
    // large constant operand (e.g., imm32)
    // 2. certain SSE/AVX ins have const operand as control bits that is always 1-Byte (imm8) even if `size` > 1-Byte
    if (addc && (size > EA_1BYTE))
    {
        ssize_t cval = addc->cnsVal;

        // Does the constant fit in a byte?
        // SSE/AVX do not need to modify opcode
        if ((signed char)cval == cval && addc->cnsReloc == false && ins != INS_mov && ins != INS_test)
        {
            if (id->idInsFmt() != IF_ARW_SHF && !IsSimdInstruction(ins))
            {
                code |= 2;
            }

            opsz = 1;
        }
    }
#ifdef TARGET_X86
    else
    {
        // Special case: "mov eax, [addr]" and "mov [addr], eax"
        // Amd64: this is one case where addr can be 64-bit in size.  This is
        // currently unused or not enabled on amd64 as it always uses RIP
        // relative addressing which results in smaller instruction size.
        if ((ins == INS_mov) && (id->idReg1() == REG_EAX) && (reg == REG_NA) && (rgx == REG_NA))
        {
            insFormat insFmt = id->idInsFmt();

            if (insFmt == IF_RWR_ARD)
            {
                assert(code == (insCodeRM(ins) | (insEncodeReg345(id, REG_EAX, EA_PTRSIZE, NULL) << 8)));

                code &= ~((code_t)0xFFFFFFFF);
                code |= 0xA0;
                isMoffset = true;
            }
            else if (insFmt == IF_AWR_RRD)
            {
                assert(code == (insCodeMR(ins) | (insEncodeReg345(id, REG_EAX, EA_PTRSIZE, NULL) << 8)));

                code &= ~((code_t)0xFFFFFFFF);
                code |= 0xA2;
                isMoffset = true;
            }
        }
    }
#endif // TARGET_X86

    // Emit SIMD prefix if required
    // There are some callers who already add SIMD prefix and call this routine.
    // Therefore, add SIMD prefix is one is not already present.
    code = AddX86PrefixIfNeededAndNotPresent(id, code, size);

    // For this format, moves do not support a third operand, so we only need to handle the binary ops.
    if (TakesSimdPrefix(id))
    {
        if (IsDstDstSrcAVXInstruction(ins))
        {
            regNumber src1 = REG_NA;

            switch (id->idInsFmt())
            {
                case IF_RRD_RRD_ARD:
                case IF_RWR_RRD_ARD:
                case IF_RRW_RRD_ARD:
                case IF_RWR_RWR_ARD:
                case IF_RRD_ARD_RRD:
                case IF_RWR_ARD_RRD:
                case IF_RRW_ARD_RRD:
                case IF_RWR_RRD_ARD_CNS:
                case IF_RWR_RRD_ARD_RRD:
                {
                    src1 = id->idReg2();
                    break;
                }

                case IF_RRD_ARD:
                case IF_RWR_ARD:
                case IF_RRW_ARD:
                case IF_AWR_RRD_RRD:
                case IF_RRD_ARD_CNS:
                case IF_RWR_ARD_CNS:
                case IF_RRW_ARD_CNS:
                {
                    src1 = id->idReg1();
                    break;
                }

                default:
                {
                    assert(!"Unhandled insFmt in emitOutputAM");
                    src1 = id->idReg1();
                    break;
                }
            }

            // encode source operand reg in 'vvvv' bits in 1's complement form
            code = insEncodeReg3456(id, src1, size, code);
        }
        else if (IsDstSrcSrcAVXInstruction(ins))
        {
            if (id->idHasReg2())
            {
                code = insEncodeReg3456(id, id->idReg2(), size, code);
            }
        }
    }

    // Emit the REX prefix if required
    if (TakesRexWPrefix(id))
    {
        code = AddRexWPrefix(id, code);
    }

    if (IsExtendedReg(reg, EA_PTRSIZE))
    {
        insEncodeReg012(id, reg, EA_PTRSIZE, &code);
        // TODO-Cleanup: stop casting RegEncoding() back to a regNumber.
        reg = (regNumber)RegEncoding(reg);
    }

    if (IsExtendedReg(rgx, EA_PTRSIZE))
    {
        insEncodeRegSIB(id, rgx, &code);
        // TODO-Cleanup: stop casting RegEncoding() back to a regNumber.
        rgx = (regNumber)RegEncoding(rgx);
    }

    // Special case emitting AVX instructions
    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
    {
        if ((ins == INS_crc32) && (size > EA_1BYTE))
        {
            code |= 0x0100;

            if (size == EA_2BYTE)
            {
                dst += emitOutputByte(dst, 0x66);
            }
        }

        regNumber reg345 = REG_NA;
        if (IsBMIInstruction(ins))
        {
            reg345 = getBmiRegNumber(ins);
        }
        if (reg345 == REG_NA)
        {
            switch (id->idInsFmt())
            {
                case IF_AWR_RRD_RRD:
                {
                    if (ins != INS_extractps)
                    {
                        reg345 = id->idReg2();
                        break;
                    }
                    FALLTHROUGH;
                }

                default:
                {
                    reg345 = id->idReg1();
                    break;
                }
            }
        }
        unsigned regcode = insEncodeReg345(id, reg345, size, &code);

        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        if (UseSimdEncoding() && (ins != INS_crc32))
        {
            // Emit last opcode byte
            // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
            assert((code & 0xFF) == 0);
            dst += emitOutputByte(dst, (code >> 8) & 0xFF);
        }
        else
        {
            dst += emitOutputWord(dst, code >> 16);
            dst += emitOutputWord(dst, code & 0xFFFF);
        }

        code = regcode;
    }
    // Is this a 'big' opcode?
    else if (code & 0xFF000000)
    {
        if (size == EA_2BYTE)
        {
            assert(ins == INS_movbe);

            dst += emitOutputByte(dst, 0x66);
        }

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Output the highest word of the opcode
        // We need to check again as in case of AVX instructions leading opcode bytes are stripped off
        // and encoded as part of VEX prefix.
        if (code & 0xFF000000)
        {
            dst += emitOutputWord(dst, code >> 16);
            code &= 0x0000FFFF;
        }
    }
    else if (code & 0x00FF0000)
    {
        if ((size == EA_2BYTE) && (ins == INS_cmpxchg))
        {
            dst += emitOutputByte(dst, 0x66);
        }

        // BT supports 16 bit operands and this code doesn't handle the necessary 66 prefix.
        assert(ins != INS_bt);

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Output the highest byte of the opcode
        if (code & 0x00FF0000)
        {
            dst += emitOutputByte(dst, code >> 16);
            code &= 0x0000FFFF;
        }

        // Use the large version if this is not a byte. This trick will not
        // work in case of SSE2 and AVX instructions.
        if ((size != EA_1BYTE) && HasRegularWideForm(ins))
        {
            code |= 0x1;
        }
    }
    else if (CodeGen::instIsFP(ins))
    {
        assert(size == EA_4BYTE || size == EA_8BYTE);
        if (size == EA_8BYTE)
        {
            code += 4;
        }
    }
    else if (!IsSSEInstruction(ins) && !IsVexOrEvexEncodableInstruction(ins))
    {
        /* Is the operand size larger than a byte? */

        switch (size)
        {
            case EA_1BYTE:
                break;

            case EA_2BYTE:
            {
                // Output a size prefix for a 16-bit operand
                if (TakesApxExtendedEvexPrefix(id))
                {
                    assert(IsApxExtendedEvexInstruction(ins));
                    assert(hasEvexPrefix(code));
                    // Evex.pp should already be added when adding the prefix.
                    assert((code & EXTENDED_EVEX_PP_BITS) != 0);
                }
                else
                {
                    dst += emitOutputByte(dst, 0x66);
                }
                FALLTHROUGH;
            }

            case EA_4BYTE:
#ifdef TARGET_AMD64
            case EA_8BYTE:
#endif

                /* Set the 'w' bit to get the large version */

                code |= 0x1;
                break;

#ifdef TARGET_X86
            case EA_8BYTE:

                /* Double operand - set the appropriate bit */

                code |= 0x04;
                break;

#endif // TARGET_X86

            default:
                NO_WAY("unexpected size");
                break;
        }
#ifdef TARGET_AMD64
        if (ins == INS_crc32_apx || ins == INS_movbe_apx)
        {
            code |= (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
        }
#endif // TARGET_AMD64
    }

    // Output the REX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    // Get the displacement value
    dsp = emitGetInsAmdAny(id);

GOT_DSP:

    if (id->idIsDspReloc())
    {
        dspInByte = false; // relocs can't be placed in a byte
        dspIsZero = false; // relocs won't always be zero
    }
    else if (IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
    {
        ssize_t compressedDsp;

        if (HasCompressedDisplacement(id))
        {
            bool isCompressed = TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte);
            assert(isCompressed && dspInByte);
            dsp = compressedDsp;
        }
        else if (TakesEvexPrefix(id) && !IsBMIInstruction(ins))
        {
            assert(!(TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte) && hasTupleTypeInfo(ins)));
            dspInByte = false;
        }
        else
        {
            // TODO-XArch-APX: for now, Extended Evex instruction will not have compressed displacement, or more
            // accurately, extended evex may not have compressed displacement optimization as the scaling factor is
            // constantly 1.
            dspInByte = ((signed char)dsp == (ssize_t)dsp);
        }
        dspIsZero = (dsp == 0);
    }
    else
    {
        dspInByte = ((signed char)dsp == (ssize_t)dsp);
        dspIsZero = (dsp == 0);
    }

    if (isMoffset)
    {
#ifdef TARGET_AMD64
        // This code path should never be hit on amd64 since it always uses RIP relative addressing.
        // In future if ever there is a need to enable this special case, also enable the logic
        // that sets isMoffset to true on amd64.
        unreached();
#else // TARGET_X86

        dst += emitOutputByte(dst, code);
        dst += emitOutputSizeT(dst, dsp);

        if (id->idIsDspReloc())
        {
            emitRecordRelocation((void*)(dst - TARGET_POINTER_SIZE), (void*)dsp, IMAGE_REL_BASED_MOFFSET);
        }

#endif // TARGET_X86
    }
    // Is there a [scaled] index component?
    else if (rgx == REG_NA)
    {
        // The address is of the form "[reg+disp]"
        switch (reg)
        {
            case REG_NA:
            {
                if (id->idIsDspReloc())
                {
                    // The address is of the form "[disp]"
                    // On x86 - disp is relative to zero
                    // On Amd64 - disp is relative to RIP
                    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                    {
                        dst += emitOutputByte(dst, code | 0x05);
                    }
                    else
                    {
                        dst += emitOutputWord(dst, code | 0x0500);
                    }

                    INT32 addlDelta = 0;
#ifdef TARGET_AMD64
                    if (addc)
                    {
                        // It is of the form "ins [disp], imm" or "ins reg, [disp], imm". Emitting relocation for a
                        // RIP-relative address means we also need to take into account the additional bytes of code
                        // generated for the immediate value, since RIP will point at the next instruction.
                        ssize_t cval = addc->cnsVal;

                        // all these opcodes only take a sign-extended 4-byte immediate
                        noway_assert(opsz < 8 || ((int)cval == cval && !addc->cnsReloc));

                        switch (opsz)
                        {
                            case 0:
                            case 4:
                            case 8:
                                addlDelta = -4;
                                break;
                            case 2:
                                addlDelta = -2;
                                break;
                            case 1:
                                addlDelta = -1;
                                break;

                            default:
                                assert(!"unexpected operand size");
                                unreached();
                        }
                    }
#endif // TARGET_AMD64

#ifdef TARGET_AMD64
                    // We emit zero on Amd64, to avoid the assert in emitOutputLong()
                    dst += emitOutputLong(dst, 0);
#else
                    dst += emitOutputLong(dst, dsp);
#endif
                    if (!IsSimdInstruction(ins) && id->idIsTlsGD())
                    {
                        addlDelta = -4;
                        emitRecordRelocationWithAddlDelta((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_TLSGD,
                                                          addlDelta);
                    }
                    else
                    {
                        emitRecordRelocationWithAddlDelta((void*)(dst - sizeof(INT32)), (void*)dsp,
                                                          IMAGE_REL_BASED_DISP32, addlDelta);
                    }
                }
                else
                {
#ifdef TARGET_X86
                    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                    {
                        dst += emitOutputByte(dst, code | 0x05);
                    }
                    else
                    {
                        dst += emitOutputWord(dst, code | 0x0500);
                    }
#else  // TARGET_AMD64
       // Amd64: addr fits within 32-bits and can be encoded as a displacement relative to zero.
       // This addr mode should never be used while generating relocatable AOT code nor if
       // the addr can be encoded as pc-relative address.
                    noway_assert(!emitComp->opts.compReloc);
                    noway_assert(codeGen->genAddrRelocTypeHint((size_t)dsp) != IMAGE_REL_BASED_REL32);
                    noway_assert((int)dsp == dsp);

                    // This requires, specifying a SIB byte after ModRM byte.
                    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                    {
                        dst += emitOutputByte(dst, code | 0x04);
                    }
                    else
                    {
                        dst += emitOutputWord(dst, code | 0x0400);
                    }
                    dst += emitOutputByte(dst, 0x25);
#endif // TARGET_AMD64
                    dst += emitOutputLong(dst, dsp);
                }
                break;
            }

            case REG_EBP:
            {
                if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                {
                    if (dspInByte)
                    {
                        // This is "[rbp + dsp8]"
                        dst += emitOutputByte(dst, code | 0x45);
                        dst += emitOutputByte(dst, dsp);
                    }
                    else
                    {
                        // This is "[rbp + dsp32]"
                        dst += emitOutputByte(dst, code | 0x85);
                        dst += emitOutputLong(dst, dsp);

                        if (id->idIsDspReloc())
                        {
                            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                        }
                    }
                }
                else if (dspInByte)
                {
                    // This is "[rbp + dsp8]"
                    dst += emitOutputWord(dst, code | 0x4500);
                    dst += emitOutputByte(dst, dsp);
                }
                else
                {
                    // This is "[rbp + dsp32]"
                    dst += emitOutputWord(dst, code | 0x8500);
                    dst += emitOutputLong(dst, dsp);

                    if (id->idIsDspReloc())
                    {
                        emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                    }
                }
                break;
            }

            case REG_ESP:
            {
                if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                {
                    if (dspIsZero)
                    {
                        // This is simply "[rsp]"
                        dst += emitOutputByte(dst, code | 0x04);
                        dst += emitOutputByte(dst, 0x24);
                    }
                    else if (dspInByte)
                    {
                        // This is "[rsp + dsp8]"
                        dst += emitOutputByte(dst, code | 0x44);
                        dst += emitOutputByte(dst, 0x24);
                        dst += emitOutputByte(dst, dsp);
                    }
                    else
                    {
                        // This is "[rsp + dsp32]"
                        dst += emitOutputByte(dst, code | 0x84);
                        dst += emitOutputByte(dst, 0x24);
                        dst += emitOutputLong(dst, dsp);

                        if (id->idIsDspReloc())
                        {
                            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                        }
                    }
                }
                else if (dspIsZero)
                {
                    // This is simply "[rsp]"
                    dst += emitOutputWord(dst, code | 0x0400);
                    dst += emitOutputByte(dst, 0x24);
                }
                else if (dspInByte)
                {
                    // This is "[rsp + dsp8]"
                    dst += emitOutputWord(dst, code | 0x4400);
                    dst += emitOutputByte(dst, 0x24);
                    dst += emitOutputByte(dst, dsp);
                }
                else
                {
                    // This is "[rsp + dsp32]"
                    dst += emitOutputWord(dst, code | 0x8400);
                    dst += emitOutputByte(dst, 0x24);
                    dst += emitOutputLong(dst, dsp);

                    if (id->idIsDspReloc())
                    {
                        emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                    }
                }
                break;
            }

            default:
            {
                if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                {
                    // Put the register in the opcode
                    code |= insEncodeReg012(id, reg, EA_PTRSIZE, nullptr);

                    if (dspIsZero)
                    {
                        // This is simply "[reg]"
                        dst += emitOutputByte(dst, code);
                    }
                    else if (dspInByte)
                    {
                        // This is "[reg + dsp8]"
                        dst += emitOutputByte(dst, code | 0x40);
                        dst += emitOutputByte(dst, dsp);
                    }
                    else
                    {
                        // This is "[reg + dsp32]"
                        dst += emitOutputByte(dst, code | 0x80);
                        dst += emitOutputLong(dst, dsp);

                        if (id->idIsDspReloc())
                        {
                            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                        }
                    }
                }
                else
                {
                    // Put the register in the opcode
                    code |= insEncodeReg012(id, reg, EA_PTRSIZE, nullptr) << 8;

                    // Is there a displacement?
                    if (dspIsZero)
                    {
                        // This is simply "[reg]"
                        dst += emitOutputWord(dst, code);
                    }
                    else if (dspInByte)
                    {
                        // This is "[reg + dsp8]"
                        dst += emitOutputWord(dst, code | 0x4000);
                        dst += emitOutputByte(dst, dsp);
                    }
                    else
                    {
                        // This is "[reg + dsp32]"
                        dst += emitOutputWord(dst, code | 0x8000);
                        dst += emitOutputLong(dst, dsp);

                        if (id->idIsDspReloc())
                        {
                            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                        }
                    }
                }

                break;
            }
        }
    }
    else
    {
        unsigned regByte;

        // We have a scaled index operand
        unsigned mul = emitDecodeScale(id->idAddr()->iiaAddrMode.amScale);

        // Is the index operand scaled?
        if (mul > 1)
        {
            // Is there a base register?
            if (reg != REG_NA)
            {
                // The address is "[reg + {2/4/8} * rgx + icon]"
                regByte = insEncodeReg012(id, reg, EA_PTRSIZE, nullptr) |
                          insEncodeReg345(id, rgx, EA_PTRSIZE, nullptr) | insSSval(mul);

                if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                {
                    if (dspIsZero && (reg != REG_EBP))
                    {
                        // The address is "[reg + {2/4/8} * rgx]"
                        dst += emitOutputByte(dst, code | 0x04);
                        dst += emitOutputByte(dst, regByte);
                    }
                    else if (dspInByte)
                    {
                        // The address is "[reg + {2/4/8} * rgx + dsp8]"
                        dst += emitOutputByte(dst, code | 0x44);
                        dst += emitOutputByte(dst, regByte);
                        dst += emitOutputByte(dst, dsp);
                    }
                    else
                    {
                        // The address is "[reg + {2/4/8} * rgx + dsp32]"
                        dst += emitOutputByte(dst, code | 0x84);
                        dst += emitOutputByte(dst, regByte);
                        dst += emitOutputLong(dst, dsp);

                        if (id->idIsDspReloc())
                        {
                            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                        }
                    }
                }
                else if (dspIsZero && (reg != REG_EBP))
                {
                    // The address is "[reg + {2/4/8} * rgx]"
                    dst += emitOutputWord(dst, code | 0x0400);
                    dst += emitOutputByte(dst, regByte);
                }
                else if (dspInByte)
                {
                    // The address is "[reg + {2/4/8} * rgx + dsp8]"
                    dst += emitOutputWord(dst, code | 0x4400);
                    dst += emitOutputByte(dst, regByte);
                    dst += emitOutputByte(dst, dsp);
                }
                else
                {
                    // The address is "[reg + {2/4/8} * rgx + dsp32]"
                    dst += emitOutputWord(dst, code | 0x8400);
                    dst += emitOutputByte(dst, regByte);
                    dst += emitOutputLong(dst, dsp);

                    if (id->idIsDspReloc())
                    {
                        emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                    }
                }
            }
            else
            {
                // The address is "[{2/4/8} * rgx + icon]"
                regByte = insEncodeReg012(id, REG_EBP, EA_PTRSIZE, nullptr) |
                          insEncodeReg345(id, rgx, EA_PTRSIZE, nullptr) | insSSval(mul);

                if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
                {
                    dst += emitOutputByte(dst, code | 0x04);
                }
                else
                {
                    dst += emitOutputWord(dst, code | 0x0400);
                }

                dst += emitOutputByte(dst, regByte);

                // Special case: jump through a jump table
                if (ins == INS_i_jmp)
                {
                    dsp += (size_t)emitConsBlock;
                }

                dst += emitOutputLong(dst, dsp);
                if (id->idIsDspReloc())
                {
                    emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                }
            }
        }
        else
        {
            // The address is "[reg+rgx+dsp]"
            regByte = insEncodeReg012(id, reg, EA_PTRSIZE, nullptr) | insEncodeReg345(id, rgx, EA_PTRSIZE, nullptr);

            if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
            {
                if (dspIsZero && (reg != REG_EBP))
                {
                    // This is [reg+rgx]"
                    dst += emitOutputByte(dst, code | 0x04);
                    dst += emitOutputByte(dst, regByte);
                }
                else if (dspInByte)
                {
                    // This is [reg+rgx+dsp8]"
                    dst += emitOutputByte(dst, code | 0x44);
                    dst += emitOutputByte(dst, regByte);
                    dst += emitOutputByte(dst, dsp);
                }
                else
                {
                    // This is [reg+rgx+dsp32]"
                    dst += emitOutputByte(dst, code | 0x84);
                    dst += emitOutputByte(dst, regByte);
                    dst += emitOutputLong(dst, dsp);

                    if (id->idIsDspReloc())
                    {
                        emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                    }
                }
            }
            else if (dspIsZero && (reg != REG_EBP))
            {
                // This is [reg+rgx]"
                dst += emitOutputWord(dst, code | 0x0400);
                dst += emitOutputByte(dst, regByte);
            }
            else if (dspInByte)
            {
                // This is [reg+rgx+dsp8]"
                dst += emitOutputWord(dst, code | 0x4400);
                dst += emitOutputByte(dst, regByte);
                dst += emitOutputByte(dst, dsp);
            }
            else
            {
                // This is [reg+rgx+dsp32]"
                dst += emitOutputWord(dst, code | 0x8400);
                dst += emitOutputByte(dst, regByte);
                dst += emitOutputLong(dst, dsp);

                if (id->idIsDspReloc())
                {
                    emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)dsp, IMAGE_REL_BASED_HIGHLOW);
                }
            }
        }
    }

    // Now generate the constant value, if present
    if (addc)
    {
        ssize_t cval = addc->cnsVal;

#ifdef TARGET_AMD64
        // all these opcodes only take a sign-extended 4-byte immediate
        noway_assert(opsz < 8 || ((int)cval == cval && !addc->cnsReloc));
#endif

        switch (opsz)
        {
            case 0:
            case 4:
            case 8:
                dst += emitOutputLong(dst, cval);
                break;
            case 2:
                dst += emitOutputWord(dst, cval);
                break;
            case 1:
                dst += emitOutputByte(dst, cval);
                break;

            default:
                assert(!"unexpected operand size");
        }

        if (addc->cnsReloc)
        {
            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)cval, IMAGE_REL_BASED_HIGHLOW);
            assert(opsz == 4);
        }
    }

DONE:

    // Does this instruction operate on a GC ref value?
    if (id->idGCref())
    {
        switch (id->idInsFmt())
        {
            case IF_ARD:
            case IF_AWR:
            case IF_ARW:
                break;

            case IF_RRD_ARD:
                break;

            case IF_RWR_ARD:
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_RRW_ARD:
                // Mark the destination register as holding a GC ref
                assert(((id->idGCref() == GCT_BYREF) &&
                        (ins == INS_add || ins == INS_sub || ins == INS_sub_hide || insIsCMOV(ins))) ||
                       ((id->idGCref() == GCT_GCREF) && insIsCMOV(ins)));
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_RWR_RRD_ARD:
                assert(((id->idGCref() == GCT_BYREF) &&
                        (ins == INS_add || ins == INS_sub || ins == INS_sub_hide || insIsCMOV(ins))) ||
                       ((id->idGCref() == GCT_GCREF) && insIsCMOV(ins)));
                assert(id->idIsEvexNdContextSet());
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_ARD_RRD:
            case IF_AWR_RRD:
                break;

            case IF_AWR_RRD_RRD:
                break;

            case IF_ARD_CNS:
            case IF_AWR_CNS:
                break;

            case IF_ARW_RRD:
            case IF_ARW_RRW:
            case IF_ARW_CNS:
            case IF_ARW_SHF:
                if (id->idGCref() == GCT_BYREF)
                {
                    assert(ins == INS_add || ins == INS_sub || ins == INS_sub_hide);
                }
                else
                {
                    assert((id->idGCref() == GCT_GCREF) && (ins == INS_cmpxchg || ins == INS_xchg));
                }
                break;

            default:
#ifdef DEBUG
                emitDispIns(id, false, false, false);
#endif
                assert(!"unexpected GC ref instruction format");
        }

        // mul can never produce a GC ref
        assert(!instrIs3opImul(ins));
        assert(ins != INS_mulEAX && ins != INS_imulEAX);
    }
    else
    {
        if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
        {
            switch (id->idInsFmt())
            {
                case IF_RWR_ARD:
                case IF_RRW_ARD:
                case IF_RWR_ARD_CNS:
                case IF_RRW_ARD_CNS:
                case IF_RWR_ARD_RRD:
                case IF_RRW_ARD_RRD:
                case IF_RWR_RRD_ARD:
                case IF_RRW_RRD_ARD:
                case IF_RWR_RRD_ARD_CNS:
                case IF_RWR_RRD_ARD_RRD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    break;
                }

                case IF_RWR_RWR_ARD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    emitGCregDeadUpd(id->idReg2(), dst);
                    break;
                }

                default:
                    break;
            }

            if (ins == INS_mulEAX || ins == INS_imulEAX)
            {
                emitGCregDeadUpd(REG_EAX, dst);
                emitGCregDeadUpd(REG_EDX, dst);
            }

            // For the three operand imul instruction the target register
            // is encoded in the opcode

            if (instrIs3opImul(ins))
            {
                regNumber tgtReg = inst3opImulReg(ins);
                emitGCregDeadUpd(tgtReg, dst);
            }
        }
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction involving a stack frame value.
 */

BYTE* emitter::emitOutputSV(BYTE* dst, instrDesc* id, code_t code, CnsVal* addc)
{
    assert(id->idHasMemStk());

    int  adr;
    int  dsp;
    bool EBPbased;
    bool dspInByte;
    bool dspIsZero;

    instruction ins  = id->idIns();
    emitAttr    size = id->idOpSize();
    size_t      opsz = EA_SIZE_IN_BYTES(size);

    assert(ins != INS_imul || id->idReg1() == REG_EAX || size == EA_4BYTE || size == EA_8BYTE);

    // `addc` is used for two kinds if instructions
    // 1. ins like ADD that can have reg/mem and const versions both and const version needs to modify the opcode for
    // large constant operand (e.g., imm32)
    // 2. certain SSE/AVX ins have const operand as control bits that is always 1-Byte (imm8) even if `size` > 1-Byte
    if (addc && (size > EA_1BYTE))
    {
        ssize_t cval = addc->cnsVal;

        // Does the constant fit in a byte?
        // SSE/AVX/AVX512 do not need to modify opcode
        if ((signed char)cval == cval && addc->cnsReloc == false && ins != INS_mov && ins != INS_test)
        {
            if ((id->idInsFmt() != IF_SRW_SHF) && (id->idInsFmt() != IF_RRW_SRD_CNS) &&
                (id->idInsFmt() != IF_RWR_RRD_SRD_CNS) && !IsSimdInstruction(ins))
            {
                code |= 2;
            }

            opsz = 1;
        }
    }

    // Add VEX or EVEX prefix if required.
    // There are some callers who already add prefix and call this routine.
    // Therefore, add VEX or EVEX prefix if one is not already present.
    code = AddX86PrefixIfNeededAndNotPresent(id, code, size);

    // Compute the REX prefix
    if (TakesRexWPrefix(id))
    {
        code = AddRexWPrefix(id, code);
    }

    // Special case emitting AVX instructions
    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
    {
        if ((ins == INS_crc32) && (size > EA_1BYTE))
        {
            code |= 0x0100;

            if (size == EA_2BYTE)
            {
                dst += emitOutputByte(dst, 0x66);
            }
        }

        regNumber reg345 = REG_NA;
        if (IsBMIInstruction(ins))
        {
            reg345 = getBmiRegNumber(ins);
        }
        if (reg345 == REG_NA)
        {
            reg345 = id->idReg1();
        }
        else
        {
            code = insEncodeReg3456(id, id->idReg1(), size, code);
        }
        unsigned regcode = insEncodeReg345(id, reg345, size, &code);

        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        if (UseSimdEncoding() && (ins != INS_crc32))
        {
            // Emit last opcode byte
            // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
            assert((code & 0xFF) == 0);
            dst += emitOutputByte(dst, (code >> 8) & 0xFF);
        }
        else
        {
            dst += emitOutputWord(dst, code >> 16);
            dst += emitOutputWord(dst, code & 0xFFFF);
        }

        code = regcode;
    }
    // Is this a 'big' opcode?
    else if (code & 0xFF000000)
    {
        if (size == EA_2BYTE)
        {
            assert(ins == INS_movbe);

            dst += emitOutputByte(dst, 0x66);
        }

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Output the highest word of the opcode
        // We need to check again because in case of AVX instructions the leading
        // escape byte(s) (e.g. 0x0F) will be encoded as part of VEX prefix.
        if (code & 0xFF000000)
        {
            dst += emitOutputWord(dst, code >> 16);
            code &= 0x0000FFFF;
        }
    }
    else if (code & 0x00FF0000)
    {
        if ((size == EA_2BYTE) && (ins == INS_cmpxchg))
        {
            dst += emitOutputByte(dst, 0x66);
        }

        // BT supports 16 bit operands and this code doesn't add the necessary 66 prefix.
        assert(ins != INS_bt);

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Output the highest byte of the opcode.
        // We need to check again because in case of AVX instructions the leading
        // escape byte(s) (e.g. 0x0F) will be encoded as part of VEX prefix.
        if (code & 0x00FF0000)
        {
            dst += emitOutputByte(dst, code >> 16);
            code &= 0x0000FFFF;
        }

        // Use the large version if this is not a byte
        if ((size != EA_1BYTE) && HasRegularWideForm(ins))
        {
            code |= 0x1;
        }
    }
    else if (CodeGen::instIsFP(ins))
    {
        assert(size == EA_4BYTE || size == EA_8BYTE);

        if (size == EA_8BYTE)
        {
            code += 4;
        }
    }
    else if (!IsSSEInstruction(ins) && !IsVexOrEvexEncodableInstruction(ins))
    {
        // Is the operand size larger than a byte?
        switch (size)
        {
            case EA_1BYTE:
#ifdef TARGET_AMD64
                assert((ins != INS_lzcnt_apx) && (ins != INS_tzcnt_apx) && (ins != INS_popcnt_apx));
#endif // TARGET_AMD64
                break;

            case EA_2BYTE:
                // Output a size prefix for a 16-bit operand
                {
                    if (!TakesApxExtendedEvexPrefix(id))
                    {
                        dst += emitOutputByte(dst, 0x66);
                    }
#ifdef TARGET_AMD64
                    else
                    {
                        code |= EXTENDED_EVEX_PP_BITS;
                    }
#endif // TARGET_AMD64
                }
                FALLTHROUGH;

            case EA_4BYTE:
                code |= 0x01;
                break;

#ifdef TARGET_AMD64
            case EA_8BYTE:
                /* Set the 'w' size bit to indicate 32-bit operation
                 * Note that incrementing "code" for INS_call (0xFF) would
                 * overflow, whereas setting the lower bit to 1 just works out
                 */
                {
                    if (TakesApxExtendedEvexPrefix(id))
                    {
                        assert(hasEvexPrefix(code));
                        code = AddRexWPrefix(id, code);
                    }
                    if ((ins != INS_lzcnt_apx) && (ins != INS_tzcnt_apx) && (ins != INS_popcnt_apx))
                    // These instructions do not support 1-byte inputs and the opcode is exact.
                    {
                        code |= 0x01;
                    }
                    break;
                }
#endif // TARGET_AMD64

#ifdef TARGET_X86
            case EA_8BYTE:

                // Double operand - set the appropriate bit.
                // I don't know what a legitimate reason to end up in this case would be
                // considering that FP is taken care of above...
                // what is an instruction that takes a double which is not covered by the
                // above instIsFP? Of the list in instrsxarch, only INS_fprem
                code |= 0x04;
                NO_WAY("bad 8 byte op");
                break;
#endif // TARGET_X86

            default:
                NO_WAY("unexpected size");
                break;
        }
#ifdef TARGET_AMD64
        if (ins == INS_crc32_apx || ins == INS_movbe_apx)
        {
            // The promoted CRC32 is in 1-byte opcode, unlike other instructions on this path, the register encoding for
            // CRC32 need to be done here.
            code |= (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
        }
#endif // TARGET_AMD64
    }

    // Output the REX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    // Figure out the variable's frame position
    int varNum = id->idAddr()->iiaLclVar.lvaVarNum();

    adr = emitComp->lvaFrameAddress(varNum, &EBPbased);
    dsp = adr + id->idAddr()->iiaLclVar.lvaOffset();

    if (IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
    {
        ssize_t compressedDsp;

        if (HasCompressedDisplacement(id))
        {
            bool isCompressed = TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte);
            assert(isCompressed && dspInByte);
            dsp = (int)compressedDsp;
        }
        else if (TakesEvexPrefix(id) && !IsBMIInstruction(ins))
        {
#if FEATURE_FIXED_OUT_ARGS
            // TODO-AMD64-CQ: We should be able to accurately predict this when FEATURE_FIXED_OUT_ARGS
            // is available. However, there's some nuance in how emitInsSizeSVCalcDisp does things
            // compared to emitOutputSV here, so we will miss a few cases today.
            //
            // assert(!TryEvexCompressDisp8Byte(id, dsp, &compressedDsp, &dspInByte));
#endif
            dspInByte = false;
        }
        else
        {
            dspInByte = ((signed char)dsp == (ssize_t)dsp);
        }
    }
    else
    {
        dspInByte = ((signed char)dsp == (ssize_t)dsp);
    }
    dspIsZero = (dsp == 0);

    // for stack variables the dsp should never be a reloc
    assert(id->idIsDspReloc() == 0);

    if (EBPbased)
    {
        // EBP-based variable: does the offset fit in a byte?
        if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
        {
            if (dspInByte)
            {
                dst += emitOutputByte(dst, code | 0x45);
                dst += emitOutputByte(dst, dsp);
            }
            else
            {
                dst += emitOutputByte(dst, code | 0x85);
                dst += emitOutputLong(dst, dsp);
            }
        }
        else if (dspInByte)
        {
            dst += emitOutputWord(dst, code | 0x4500);
            dst += emitOutputByte(dst, dsp);
        }
        else
        {
            dst += emitOutputWord(dst, code | 0x8500);
            dst += emitOutputLong(dst, dsp);
        }
    }
    else
    {
#if !FEATURE_FIXED_OUT_ARGS
        // Adjust the offset by the amount currently pushed on the CPU stack
        dsp += emitCurStackLvl;

        if (IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins))
        {
            // We cannot reliably predict the encoding size up front so we shouldn't
            // have encountered a scenario marked with compressed displacement. We
            // did predict cases that could use the small encoding for VEX scenarios

            assert(!HasCompressedDisplacement(id));

            if (!TakesEvexPrefix(id))
            {
                dspInByte = ((signed char)dsp == (ssize_t)dsp);
            }
        }
        else
        {
            dspInByte = ((signed char)dsp == (ssize_t)dsp);
        }
        dspIsZero = (dsp == 0);
#endif // !FEATURE_FIXED_OUT_ARGS

        // Does the offset fit in a byte?
        if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
        {
            if (dspIsZero)
            {
                dst += emitOutputByte(dst, code | 0x04);
                dst += emitOutputByte(dst, 0x24);
            }
            else if (dspInByte)
            {
                dst += emitOutputByte(dst, code | 0x44);
                dst += emitOutputByte(dst, 0x24);
                dst += emitOutputByte(dst, dsp);
            }
            else
            {
                dst += emitOutputByte(dst, code | 0x84);
                dst += emitOutputByte(dst, 0x24);
                dst += emitOutputLong(dst, dsp);
            }
        }
        else if (dspIsZero)
        {
            dst += emitOutputWord(dst, code | 0x0400);
            dst += emitOutputByte(dst, 0x24);
        }
        else if (dspInByte)
        {
            dst += emitOutputWord(dst, code | 0x4400);
            dst += emitOutputByte(dst, 0x24);
            dst += emitOutputByte(dst, dsp);
        }
        else
        {
            dst += emitOutputWord(dst, code | 0x8400);
            dst += emitOutputByte(dst, 0x24);
            dst += emitOutputLong(dst, dsp);
        }
    }

    // Now generate the constant value, if present
    if (addc)
    {
        ssize_t cval = addc->cnsVal;

#ifdef TARGET_AMD64
        // all these opcodes only take a sign-extended 4-byte immediate
        noway_assert(opsz < 8 || ((int)cval == cval && !addc->cnsReloc));
#endif

        switch (opsz)
        {
            case 0:
            case 4:
            case 8:
                dst += emitOutputLong(dst, cval);
                break;
            case 2:
                dst += emitOutputWord(dst, cval);
                break;
            case 1:
                dst += emitOutputByte(dst, cval);
                break;

            default:
                assert(!"unexpected operand size");
        }

        if (addc->cnsReloc)
        {
            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)cval, IMAGE_REL_BASED_HIGHLOW);
            assert(opsz == 4);
        }
    }

    // Does this instruction operate on a GC ref value?
    if (id->idGCref())
    {
        // Factor in the sub-variable offset
        adr += AlignDown(id->idAddr()->iiaLclVar.lvaOffset(), TARGET_POINTER_SIZE);

        switch (id->idInsFmt())
        {
            case IF_SRD:
                // Read  stack                    -- no change
                break;

            case IF_SWR: // Stack Write (So we need to update GC live for stack var)
                // Write stack                    -- GC var may be born
                emitGCvarLiveUpd(adr, varNum, id->idGCref(), dst DEBUG_ARG(varNum));
                break;

            case IF_SRD_CNS:
                // Read  stack                    -- no change
                break;

            case IF_SWR_CNS:
                // Write stack                    -- no change
                break;

            case IF_SRD_RRD:
            case IF_RRD_SRD:
                // Read  stack   , read  register -- no change
                break;

            case IF_RWR_SRD: // Register Write, Stack Read (So we need to update GC live for register)

                // Read  stack   , write register -- GC reg may be born
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_SWR_RRD: // Stack Write, Register Read (So we need to update GC live for stack var)
                // Read  register, write stack    -- GC var may be born
                emitGCvarLiveUpd(adr, varNum, id->idGCref(), dst DEBUG_ARG(varNum));
                break;

            case IF_RRW_SRD: // Register Read/Write, Stack Read (So we need to update GC live for register)

                // reg could have been a GCREF as GCREF + int=BYREF
                //                             or BYREF+/-int=BYREF
                assert(id->idGCref() == GCT_BYREF && (ins == INS_add || ins == INS_sub || ins == INS_sub_hide));
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_RWR_RRD_SRD: // Register Read/Write, Stack Read (So we need to update GC live for register)

                // reg could have been a GCREF as GCREF + int=BYREF
                //                             or BYREF+/-int=BYREF
                assert(id->idGCref() == GCT_BYREF && (ins == INS_add || ins == INS_sub || ins == INS_sub_hide));
                assert(id->idIsEvexNdContextSet());
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_SRW_CNS:
            case IF_SRW_RRD:
            case IF_SRW_RRW:
                // += -= of a byref, no change

            case IF_SRW:
                break;

            default:
#ifdef DEBUG
                emitDispIns(id, false, false, false);
#endif
                assert(!"unexpected GC ref instruction format");
        }
    }
    else
    {
        if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
        {
            switch (id->idInsFmt())
            {
                case IF_RWR_SRD: // Register Write, Stack Read
                case IF_RRW_SRD: // Register Read/Write, Stack Read
                case IF_RWR_RRD_SRD:
                case IF_RRW_RRD_SRD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    break;
                }

                case IF_RWR_RWR_SRD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    emitGCregDeadUpd(id->idReg2(), dst);
                    break;
                }

                default:
                    break;
            }

            if (ins == INS_mulEAX || ins == INS_imulEAX)
            {
                emitGCregDeadUpd(REG_EAX, dst);
                emitGCregDeadUpd(REG_EDX, dst);
            }

            // For the three operand imul instruction the target register
            // is encoded in the opcode

            if (instrIs3opImul(ins))
            {
                regNumber tgtReg = inst3opImulReg(ins);
                emitGCregDeadUpd(tgtReg, dst);
            }
        }
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction with a static data member (class variable).
 */

BYTE* emitter::emitOutputCV(BYTE* dst, instrDesc* id, code_t code, CnsVal* addc)
{
    assert(id->idHasMemGen());

    BYTE*                addr;
    CORINFO_FIELD_HANDLE fldh;
    ssize_t              offs;
    int                  doff;

    emitAttr    size      = id->idOpSize();
    size_t      opsz      = EA_SIZE_IN_BYTES(size);
    instruction ins       = id->idIns();
    bool        isMoffset = false;

    // Get hold of the field handle and offset
    fldh = id->idAddr()->iiaFieldHnd;
    offs = emitGetInsDsp(id);

    if (fldh == FLD_GLOBAL_FS)
    {
        // Special case: mov reg, fs:[ddd]
        dst += emitOutputByte(dst, 0x64);
    }
    else if (fldh == FLD_GLOBAL_GS)
    {
        // Special case: mov reg, gs:[ddd]
        dst += emitOutputByte(dst, 0x65);
    }

    // Compute VEX/EVEX prefix
    // Some of its callers already add EVEX/VEX prefix and then call this routine.
    // Therefore add EVEX/VEX prefix is not already present.
    code = AddX86PrefixIfNeededAndNotPresent(id, code, size);

    // Compute the REX prefix
    if (TakesRexWPrefix(id))
    {
        code = AddRexWPrefix(id, code);
    }

    // `addc` is used for two kinds if instructions
    // 1. ins like ADD that can have reg/mem and const versions both and const version needs to modify the opcode for
    // large constant operand (e.g., imm32)
    // 2. certain SSE/AVX ins have const operand as control bits that is always 1-Byte (imm8) even if `size` > 1-Byte
    if (addc && (size > EA_1BYTE))
    {
        ssize_t cval = addc->cnsVal;
        // Does the constant fit in a byte?
        if ((signed char)cval == cval && addc->cnsReloc == false && ins != INS_mov && ins != INS_test)
        {
            // SSE/AVX do not need to modify opcode
            if (id->idInsFmt() != IF_MRW_SHF && !IsSimdInstruction(ins))
            {
                code |= 2;
            }

            opsz = 1;
        }
    }
#ifdef TARGET_X86
    else
    {
        // Special case: "mov eax, [addr]" and "mov [addr], eax"
        // Amd64: this is one case where addr can be 64-bit in size.  This is
        // currently unused or not enabled on amd64 as it always uses RIP
        // relative addressing which results in smaller instruction size.
        if (ins == INS_mov && id->idReg1() == REG_EAX)
        {
            insFormat insFmt = id->idInsFmt();

            if (insFmt == IF_RWR_MRD)
            {
                assert(code == (insCodeRM(ins) | (insEncodeReg345(id, REG_EAX, EA_PTRSIZE, NULL) << 8) | 0x0500));

                code &= ~((code_t)0xFFFFFFFF);
                code |= 0xA0;
                isMoffset = true;
            }
            else if (insFmt == IF_MWR_RRD)
            {
                assert(code == (insCodeMR(ins) | (insEncodeReg345(id, REG_EAX, EA_PTRSIZE, NULL) << 8) | 0x0500));

                code &= ~((code_t)0xFFFFFFFF);
                code |= 0xA2;
                isMoffset = true;
            }
        }
    }
#endif // TARGET_X86

    // Special case emitting AVX instructions
    if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
    {
        if ((ins == INS_crc32) && (size > EA_1BYTE))
        {
            code |= 0x0100;

            if (size == EA_2BYTE)
            {
                dst += emitOutputByte(dst, 0x66);
            }
        }

        regNumber reg345 = REG_NA;
        if (IsBMIInstruction(ins))
        {
            reg345 = getBmiRegNumber(ins);
        }
        if (reg345 == REG_NA)
        {
            reg345 = id->idReg1();
        }
        else
        {
            code = insEncodeReg3456(id, id->idReg1(), size, code);
        }
        unsigned regcode = insEncodeReg345(id, reg345, size, &code);

        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        if (UseVEXEncoding() && (ins != INS_crc32))
        {
            // Emit last opcode byte
            // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
            assert((code & 0xFF) == 0);
            dst += emitOutputByte(dst, (code >> 8) & 0xFF);
        }
        else
        {
            dst += emitOutputWord(dst, code >> 16);
            dst += emitOutputWord(dst, code & 0xFFFF);
        }

        // Emit Mod,R/M byte
        dst += emitOutputByte(dst, regcode | 0x05);
        code = 0;
    }
    // Is this a 'big' opcode?
    else if (code & 0xFF000000)
    {
        if (size == EA_2BYTE)
        {
            assert(ins == INS_movbe);

            dst += emitOutputByte(dst, 0x66);
        }

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Output the highest word of the opcode.
        // Check again since AVX instructions encode leading opcode bytes as part of VEX prefix.
        if (code & 0xFF000000)
        {
            dst += emitOutputWord(dst, code >> 16);
        }
        code &= 0x0000FFFF;
    }
    else if (code & 0x00FF0000)
    {
        if ((size == EA_2BYTE) && (ins == INS_cmpxchg))
        {
            dst += emitOutputByte(dst, 0x66);
        }

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        // Check again as VEX prefix would have encoded leading opcode byte
        if (code & 0x00FF0000)
        {
            dst += emitOutputByte(dst, code >> 16);
            code &= 0x0000FFFF;
        }

        if (size != EA_1BYTE && HasRegularWideForm(ins))
        {
            code |= 0x1;
        }
    }
    else if (CodeGen::instIsFP(ins))
    {
        assert(size == EA_4BYTE || size == EA_8BYTE);

        if (size == EA_8BYTE)
        {
            code += 4;
        }
    }
    else
    {
        // Is the operand size larger than a byte?
        switch (size)
        {
            case EA_1BYTE:
                break;

            case EA_2BYTE:
                // Output a size prefix for a 16-bit operand
                dst += emitOutputByte(dst, 0x66);
                FALLTHROUGH;

            case EA_4BYTE:
#ifdef TARGET_AMD64
            case EA_8BYTE:
#endif
                // Set the 'w' bit to get the large version
                code |= 0x1;
                break;

#ifdef TARGET_X86
            case EA_8BYTE:
                // Double operand - set the appropriate bit
                code |= 0x04;
                break;
#endif // TARGET_X86

            default:
                assert(!"unexpected size");
        }
    }

    // Output the REX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    if (code)
    {
        if (id->idInsFmt() == IF_MRD_OFF || id->idInsFmt() == IF_RWR_MRD_OFF || isMoffset)
        {
            dst += emitOutputByte(dst, code);
        }
        else
        {
            dst += emitOutputWord(dst, code);
        }
    }

    if (fldh == FLD_GLOBAL_GS)
    {
        dst += emitOutputByte(dst, 0x25);
    }

    // Do we have a constant or a static data member?
    doff = Compiler::eeGetJitDataOffs(fldh);
    if (doff >= 0)
    {
        addr = emitConsBlock + doff;

#ifdef DEBUG
        int byteSize = EA_SIZE_IN_BYTES(emitGetMemOpSize(id, /*ignoreEmbeddedBroadcast*/ false));

        // Check that the offset is properly aligned (i.e. the ddd in [ddd])
        // When SMALL_CODE is set, we only expect 4-byte alignment, otherwise
        // we expect the same alignment as the size of the constant.

        if (emitChkAlign && (ins != INS_lea))
        {
            if (emitComp->compCodeOpt() == Compiler::SMALL_CODE)
            {
                assert(IS_ALIGNED(addr, 4));
            }
            else
            {
                assert(IS_ALIGNED(addr, byteSize));
            }
        }
#endif // DEBUG
    }
    else
    {
        // Special case: mov reg, fs:[ddd] or mov reg, [ddd]
        if (jitStaticFldIsGlobAddr(fldh))
        {
            addr = nullptr;
        }
        else
        {
            assert(jitStaticFldIsGlobAddr(fldh));
            addr = nullptr;
        }
    }

    BYTE* target = (addr + offs);

    if (!isMoffset)
    {
        INT32 addlDelta = 0;

#ifdef TARGET_AMD64
        if (addc)
        {
            // It is of the form "ins [disp], imm" or "ins reg, [disp], imm". Emitting relocation for a
            // RIP-relative address means we also need to take into account the additional bytes of code
            // generated for the immediate value, since RIP will point at the next instruction.
            ssize_t cval = addc->cnsVal;

            // all these opcodes only take a sign-extended 4-byte immediate
            noway_assert(opsz < 8 || ((int)cval == cval && !addc->cnsReloc));

            switch (opsz)
            {
                case 0:
                case 4:
                case 8:
                    addlDelta = -4;
                    break;
                case 2:
                    addlDelta = -2;
                    break;
                case 1:
                    addlDelta = -1;
                    break;

                default:
                    assert(!"unexpected operand size");
                    unreached();
            }
        }
#endif // TARGET_AMD64

#ifdef TARGET_AMD64
        if (id->idIsDspReloc())
        {
            // All static field and data section constant accesses should be marked as relocatable
            dst += emitOutputLong(dst, 0);
        }
        else
        {
            dst += emitOutputLong(dst, (ssize_t)target);
        }
#else
        dst += emitOutputLong(dst, (int)(ssize_t)target);
#endif // TARGET_AMD64

        if (id->idIsDspReloc())
        {
            emitRecordRelocationWithAddlDelta((void*)(dst - sizeof(int)), target, IMAGE_REL_BASED_DISP32, addlDelta);
        }
    }
    else
    {
#ifdef TARGET_AMD64
        // This code path should never be hit on amd64 since it always uses RIP relative addressing.
        // In future if ever there is a need to enable this special case, also enable the logic
        // that sets isMoffset to true on amd64.
        unreached();
#else // TARGET_X86

        dst += emitOutputSizeT(dst, (ssize_t)target);

        if (id->idIsDspReloc())
        {
            emitRecordRelocation((void*)(dst - TARGET_POINTER_SIZE), target, IMAGE_REL_BASED_MOFFSET);
        }

#endif // TARGET_X86
    }

    // Now generate the constant value, if present
    if (addc)
    {
        ssize_t cval = addc->cnsVal;

#ifdef TARGET_AMD64
        // all these opcodes only take a sign-extended 4-byte immediate
        noway_assert(opsz < 8 || ((int)cval == cval && !addc->cnsReloc));
#endif

        switch (opsz)
        {
            case 0:
            case 4:
            case 8:
                dst += emitOutputLong(dst, cval);
                break;
            case 2:
                dst += emitOutputWord(dst, cval);
                break;
            case 1:
                dst += emitOutputByte(dst, cval);
                break;

            default:
                assert(!"unexpected operand size");
        }
        if (addc->cnsReloc)
        {
            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)cval, IMAGE_REL_BASED_HIGHLOW);
            assert(opsz == 4);
        }
    }

    // Does this instruction operate on a GC ref value?
    if (id->idGCref())
    {
        switch (id->idInsFmt())
        {
            case IF_MRD:
            case IF_MRW:
            case IF_MWR:
                break;

            case IF_RRD_MRD:
                break;

            case IF_RWR_MRD:
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_MRD_RRD:
            case IF_MWR_RRD:
            case IF_MRW_RRD:
            case IF_MRW_RRW:
                break;

            case IF_MRD_CNS:
            case IF_MWR_CNS:
            case IF_MRW_CNS:
            case IF_MRW_SHF:
                break;

            case IF_RRW_MRD:

                assert(id->idGCref() == GCT_BYREF);
                assert(ins == INS_add || ins == INS_sub || ins == INS_sub_hide);

                // Mark it as holding a GCT_BYREF
                emitGCregLiveUpd(GCT_BYREF, id->idReg1(), dst);
                break;

            default:
#ifdef DEBUG
                emitDispIns(id, false, false, false);
#endif
                assert(!"unexpected GC ref instruction format");
        }
    }
    else
    {
        if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
        {
            switch (id->idInsFmt())
            {
                case IF_RWR_MRD:
                case IF_RRW_MRD:
                case IF_RWR_RRD_MRD:
                case IF_RRW_RRD_MRD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    break;
                }

                case IF_RWR_RWR_MRD:
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                    emitGCregDeadUpd(id->idReg2(), dst);
                    break;
                }

                default:
                    break;
            }

            if (ins == INS_mulEAX || ins == INS_imulEAX)
            {
                emitGCregDeadUpd(REG_EAX, dst);
                emitGCregDeadUpd(REG_EDX, dst);
            }

            // For the three operand imul instruction the target register
            // is encoded in the opcode

            if (instrIs3opImul(ins))
            {
                regNumber tgtReg = inst3opImulReg(ins);
                emitGCregDeadUpd(tgtReg, dst);
            }
        }
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction with one register operand.
 */

BYTE* emitter::emitOutputR(BYTE* dst, instrDesc* id)
{
    code_t code;

    instruction ins  = id->idIns();
    regNumber   reg  = id->idReg1();
    emitAttr    size = id->idOpSize();

    assert(!id->idHasReg2());

    // We would to update GC info correctly
    assert(!IsSSEInstruction(ins));
    assert(!IsVexOrEvexEncodableInstruction(ins));

    // Get the 'base' opcode
    switch (ins)
    {
        case INS_inc:
        case INS_dec:

#ifdef TARGET_AMD64
            if (true)
#else
            if (size == EA_1BYTE)
#endif
            {
                assert(INS_inc_l == INS_inc + 1);
                assert(INS_dec_l == INS_dec + 1);

                // Can't use the compact form, use the long form
                ins = (instruction)(ins + 1);
                if (size == EA_2BYTE && !TakesApxExtendedEvexPrefix(id))
                {
                    // Output a size prefix for a 16-bit operand
                    dst += emitOutputByte(dst, 0x66);
                }

                code = insCodeRR(ins);
                if (size != EA_1BYTE)
                {
                    // Set the 'w' bit to get the large version
                    code |= 0x1;
                }

                code = AddX86PrefixIfNeeded(id, code, size);

                if (TakesRexWPrefix(id))
                {
                    code = AddRexWPrefix(id, code);
                }

                // Register...
                unsigned regcode = insEncodeReg012(id, reg, size, &code);

                // Output the REX prefix
                dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

                dst += emitOutputWord(dst, code | (regcode << 8));
            }
            else
            {
                if (size == EA_2BYTE)
                {
                    // Output a size prefix for a 16-bit operand
                    dst += emitOutputByte(dst, 0x66);
                }
                dst += emitOutputByte(dst, insCodeRR(ins) | insEncodeReg012(id, reg, size, nullptr));
            }
            break;

        case INS_pop:
        case INS_pop_hide:
        case INS_push:
        case INS_push_hide:

            assert(size == EA_PTRSIZE);
            code = insEncodeOpreg(id, reg, size);

            // TODO-xarch-apx: it is TBD if we will use REX2 for PUSH/POP,
            //                 the implementation here is optional.
            if (TakesRex2Prefix(id))
            {
                code = AddRex2Prefix(ins, code);
                // Setting EVEX.W = 1 bit indicates a push-pop acceleration (PPX) hint
                // So, it is used only in Epilog/Prolog code generation
                if (id->idIsApxPpxContextSet())
                {
                    code = AddRexWPrefix(id, code);
                }
            }

            assert(!TakesSimdPrefix(id));
            assert(!TakesRexWPrefix(id));

            // Output the REX prefix
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

            dst += emitOutputByte(dst, code);
            break;

        case INS_bswap:
        {
            assert(size >= EA_4BYTE && size <= EA_PTRSIZE); // 16-bit BSWAP is undefined

            // The Intel instruction set reference for BSWAP states that extended registers
            // should be enabled via REX.R, but per Vol. 2A, Sec. 2.2.1.2 (see also Figure 2-7),
            // REX.B should instead be used if the register is encoded in the opcode byte itself.
            // Therefore the default logic of insEncodeReg012 is correct for this case.

            code = insCodeRR(ins);

            if (TakesRex2Prefix(id))
            {
                code = AddRex2Prefix(ins, code);
            }

            if (TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }

            // Register...
            unsigned regcode = insEncodeReg012(id, reg, size, &code);

            // Output the REX prefix
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

            // If the instruction is prefixed by REX2, then 0x0F has been removed, just need to emit the opcode byte.
            dst +=
                TakesRex2Prefix(id) ? emitOutputByte(dst, code | regcode) : emitOutputWord(dst, code | (regcode << 8));
            break;
        }

        case INS_seto:
        case INS_setno:
        case INS_setb:
        case INS_setae:
        case INS_sete:
        case INS_setne:
        case INS_setbe:
        case INS_seta:
        case INS_sets:
        case INS_setns:
        case INS_setp:
        case INS_setnp:
        case INS_setl:
        case INS_setge:
        case INS_setle:
        case INS_setg:
        {
            assert(id->idGCref() == GCT_NONE);
            assert(size == EA_1BYTE);

            code = insCodeMR(ins);

            if (TakesRex2Prefix(id))
            {
                code = AddRex2Prefix(ins, code);
                code = insEncodeMRreg(id, reg, EA_1BYTE, code);
                dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
                dst += emitOutputWord(dst, code & 0x0000FFFF);
            }
            else
            {
                code = insEncodeMRreg(id, reg, EA_1BYTE, code);
                // Output the REX prefix
                dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
                // We expect this to always be a 'big' opcode
                assert(code & 0x00FF0000);

                dst += emitOutputByte(dst, code >> 16);
                dst += emitOutputWord(dst, code & 0x0000FFFF);
            }
            break;
        }

#ifdef TARGET_AMD64
        case INS_seto_apx:
        case INS_setno_apx:
        case INS_setb_apx:
        case INS_setae_apx:
        case INS_sete_apx:
        case INS_setne_apx:
        case INS_setbe_apx:
        case INS_seta_apx:
        case INS_sets_apx:
        case INS_setns_apx:
        case INS_setp_apx:
        case INS_setnp_apx:
        case INS_setl_apx:
        case INS_setge_apx:
        case INS_setle_apx:
        case INS_setg_apx:
        {
            assert(TakesApxExtendedEvexPrefix(id));
            assert(size == EA_1BYTE);

            code = insCodeMR(ins);
            code = AddEvexPrefix(id, code, size);
            code = insEncodeMRreg(id, reg, EA_1BYTE, code);
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
            dst += emitOutputWord(dst, code & 0x0000FFFF);
            break;
        }
#endif

        case INS_mulEAX:
        case INS_imulEAX:

            // Kill off any GC refs in EAX or EDX
            emitGCregDeadUpd(REG_EAX, dst);
            emitGCregDeadUpd(REG_EDX, dst);

            FALLTHROUGH;

        default:

            assert(id->idGCref() == GCT_NONE);
            code = insCodeMR(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeMRreg(id, reg, size, code);

            if (size != EA_1BYTE)
            {
                // Set the 'w' bit to get the large version
                code |= 0x1;

                if (size == EA_2BYTE && !TakesApxExtendedEvexPrefix(id))
                {
                    // Output a size prefix for a 16-bit operand
                    dst += emitOutputByte(dst, 0x66);
                }
            }

            if (TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }

            // Output the REX prefix
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

            dst += emitOutputWord(dst, code);
            break;
    }

    // Are we writing the register? if so then update the GC information
    switch (id->idInsFmt())
    {
        case IF_RRD:
            break;
        case IF_RWR:
            if (id->idGCref())
            {
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
            }
            else
            {
                emitGCregDeadUpd(id->idReg1(), dst);
            }
            break;
        case IF_RRW:
        {
#ifdef DEBUG
            regMaskTP regMask = genRegMask(reg);
#endif
            if (id->idGCref())
            {
                assert(ins == INS_inc || ins == INS_dec || ins == INS_inc_l || ins == INS_dec_l);
                // We would like to assert that the reg must currently be holding either a gcref or a byref.
                // However, we can see cases where a LCLHEAP generates a non-gcref value into a register,
                // and the first instruction we generate after the LCLHEAP is an `inc` that is typed as
                // byref. We'll properly create the byref gcinfo when this happens.
                //     assert((emitThisGCrefRegs | emitThisByrefRegs) & regMask);
                assert(id->idGCref() == GCT_BYREF);
                // Mark it as holding a GCT_BYREF
                emitGCregLiveUpd(GCT_BYREF, id->idReg1(), dst);
            }
            else
            {
                // Can't use RRW to trash a GC ref.  It's OK for unverifiable code
                // to trash Byrefs.
                assert((emitThisGCrefRegs & regMask) == 0);
            }
        }
        break;
        default:
#ifdef DEBUG
            emitDispIns(id, false, false, false);
#endif
            assert(!"unexpected instruction format");
            break;
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction with two register operands.
 */

BYTE* emitter::emitOutputRR(BYTE* dst, instrDesc* id)
{
    code_t code;

    instruction ins  = id->idIns();
    regNumber   reg1 = id->idReg1();
    regNumber   reg2 = id->idReg2();
    emitAttr    size = id->idOpSize();

    assert(!id->idHasReg3());
    bool isInsCodeMR = false;

    if (IsSimdInstruction(ins))
    {
        assert(((ins != INS_movd32) && (ins != INS_movd64)) || (isFloatReg(reg1) != isFloatReg(reg2)));

        if (ins == INS_kmovb_gpr || ins == INS_kmovw_gpr || ins == INS_kmovd_gpr || ins == INS_kmovq_gpr)
        {
            assert(!(isGeneralRegister(reg1) && isGeneralRegister(reg2)));

            code = insCodeRM(ins);
            if (isGeneralRegister(reg1))
            {
                // kmov r, k form, flip last byte of opcode from 0x92 to 0x93
                code |= 0x01;
            }
        }
        else
        {
            switch (ins)
            {
                case INS_vcompresspd:
                case INS_vcompressps:
                case INS_vpcompressb:
                case INS_vpcompressd:
                case INS_vpcompressq:
                case INS_vpcompressw:
                {
                    isInsCodeMR = true;
                    break;
                }

                case INS_movd32:
                case INS_movd64:
                {
                    isInsCodeMR = !isFloatReg(reg1);
                    break;
                }

                default:
                {
                    isInsCodeMR = false;
                    break;
                }
            }

            if (isInsCodeMR)
            {
                code = insCodeMR(ins);
            }
            else
            {
                code = insCodeRM(ins);
            }
        }
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeRMreg(id, code);

        if (TakesRexWPrefix(id))
        {
            code = AddRexWPrefix(id, code);
        }
    }
    else if ((ins == INS_movsx) || (ins == INS_movzx) || (insIsCMOV(ins)))
    {
        assert(hasCodeRM(ins) && !hasCodeMI(ins) && !hasCodeMR(ins));
        code = insCodeRM(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeRMreg(id, code) | (int)(size == EA_2BYTE);
#ifdef TARGET_AMD64

        assert((size < EA_4BYTE) || (insIsCMOV(ins)));
        if ((size == EA_8BYTE) || (ins == INS_movsx))
        {
            code = AddRexWPrefix(id, code);
        }
    }
    else if (ins == INS_movsxd)
    {
        assert(hasCodeRM(ins) && !hasCodeMI(ins) && !hasCodeMR(ins));
        code = insCodeRM(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeRMreg(id, code);
        code = AddRexWPrefix(id, code);

#endif // TARGET_AMD64
    }
#ifdef FEATURE_HW_INTRINSICS
    else if ((ins == INS_bsf) || (ins == INS_bsr) || (ins == INS_crc32) || (ins == INS_lzcnt) || (ins == INS_popcnt) ||
             (ins == INS_tzcnt)
#ifdef TARGET_AMD64
             || (ins == INS_lzcnt_apx) || (ins == INS_tzcnt_apx) || (ins == INS_popcnt_apx) || (ins == INS_crc32_apx)
#endif // TARGET_AMD64
    )
    {
        assert(hasCodeRM(ins) && !hasCodeMI(ins) && !hasCodeMR(ins));
        code = insCodeRM(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeRMreg(id, code);
        if ((ins == INS_crc32) && (size > EA_1BYTE))
        {
            code |= 0x0100;
        }
#ifdef TARGET_AMD64
        if ((ins == INS_crc32_apx) && (size > EA_1BYTE))
        {
            code |= 0x01;
        }
#endif // TARGET_AMD64

        if (size == EA_2BYTE)
        {
            if (!TakesApxExtendedEvexPrefix(id))
            {
                assert(ins == INS_crc32);
                dst += emitOutputByte(dst, 0x66);
            }
            else
            {
                code |= EXTENDED_EVEX_PP_BITS;
            }
        }
        else if (size == EA_8BYTE)
        {
            code = AddRexWPrefix(id, code);
        }
    }
#endif // FEATURE_HW_INTRINSICS
#ifdef TARGET_AMD64
    else if ((ins == INS_push2) || (ins == INS_pop2))
    {
        assert(size == EA_PTRSIZE);
        assert(TakesApxExtendedEvexPrefix(id));
        code = insCodeMR(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeMRreg(id, code);
        // Setting EVEX.W = 1 bit indicates a push-pop acceleration (PPX) hint
        // The current recommendation is to use PUSH2/POP2 only with PPX hint
        // So, it is used only in Epilog/Prolog code generation
        assert(id->idIsApxPpxContextSet());
        code = AddRexWPrefix(id, code);
    }
#endif // TARGET_AMD64
    else
    {
        // TODO-XArch-APX:
        // some instructions with NDD form might go into this path with EVEX prefix.
        // might consider having a separate path with checks like: TakesApxExtendedEvexPrefix
        // essentially, we need to make it clear on the priority and necessity of REX2 and EVEX:
        // REX2 is needed iff EGPRs are involved.
        // EVEX is needed when NDD, NF or other features are involved.
        // So the logic should be:
        // checking if those new features are used, then check if EGPRs are involved.
        // EGPRs will be supported by EVEX anyway, so don't need to check in the first place.
        assert(!TakesSimdPrefix(id) || TakesApxExtendedEvexPrefix(id));
        code = insCodeMR(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeMRreg(id, code);

        if (ins != INS_test && !IsShiftInstruction(ins))
        {
            code |= 2;
        }

        switch (size)
        {
            case EA_1BYTE:
                noway_assert(RBM_BYTE_REGS & genRegMask(reg1));
                noway_assert(RBM_BYTE_REGS & genRegMask(reg2));
                break;

            case EA_2BYTE:
                // Output a size prefix for a 16-bit operand
                if (TakesApxExtendedEvexPrefix(id))
                {
                    assert(hasEvexPrefix(code));
                    // Evex.pp should already be added when adding the prefix.
                    assert((code & EXTENDED_EVEX_PP_BITS) != 0);
                }
                else
                {
                    dst += emitOutputByte(dst, 0x66);
                }

                code |= 0x1;
                break;

            case EA_4BYTE:
                // Set the 'w' bit to get the large version

#ifdef TARGET_AMD64
                if (TakesApxExtendedEvexPrefix(id))
                {
                    assert(hasEvexPrefix(code));
                    // Evex.pp should already be added when adding the prefix
                    assert((code & EXTENDED_EVEX_PP_BITS) == 0);
                }
#endif
                code |= 0x1;
                break;

#ifdef TARGET_AMD64
            case EA_8BYTE:
                // TODO-AMD64-CQ: Better way to not emit REX.W when we don't need it
                // Don't need to zero out the high bits explicitly
                if ((ins != INS_xor) || (reg1 != reg2))
                {
                    code = AddRexWPrefix(id, code);
                }
                else
                {
                    id->idOpSize(EA_4BYTE);
                }

                // Set the 'w' bit to get the large version
                code |= 0x1;
                break;

#endif // TARGET_AMD64

            default:
                assert(!"unexpected size");
        }
    }

    regNumber regFor012Bits = reg2;
    regNumber regFor345Bits = REG_NA;

    if (IsBMIInstruction(ins))
    {
        regFor345Bits = getBmiRegNumber(ins);
    }

    if (regFor345Bits == REG_NA)
    {
        regFor345Bits = reg1;
    }

    if (isInsCodeMR)
    {
        std::swap(regFor012Bits, regFor345Bits);
    }

    unsigned regCode;
    if (!IsApxNddEncodableInstruction(ins) || !id->idIsEvexNdContextSet())
    {
        regCode = insEncodeReg345(id, regFor345Bits, size, &code);
        regCode |= insEncodeReg012(id, regFor012Bits, size, &code);
    }
    else
    {
        // unary ins with NDD form use Evex.vvvvv for dst, and ModRM.rm for src
        code    = insEncodeReg3456(id, reg1, size, code);
        regCode = insEncodeReg012(id, reg2, size, &code);
    }

#ifdef TARGET_AMD64
    if (TakesSimdPrefix(id) && !IsCCMP(ins))
#else
    if (TakesSimdPrefix(id))
#endif
    {
        // In case of AVX instructions that take 3 operands, we generally want to encode reg1
        // as first source.  In this case, reg1 is both a source and a destination.
        // The exception is the "merge" 3-operand case, where we have a move instruction, such
        // as movss, and we want to merge the source with itself.
        //
        // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
        // now we use the single source as source1 and source2.
        if (IsDstDstSrcAVXInstruction(ins))
        {
            // encode source/dest operand reg in 'vvvv' bits in 1's complement form
            code = insEncodeReg3456(id, reg1, size, code);
        }
        else if (IsDstSrcSrcAVXInstruction(ins))
        {
            // encode source operand reg in 'vvvv' bits in 1's complement form
            code = insEncodeReg3456(id, reg2, size, code);
        }
    }

    // Output the REX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    if (code & 0xFF000000)
    {
        // Output the highest word of the opcode
        dst += emitOutputWord(dst, code >> 16);
        code &= 0x0000FFFF;

        if (Is4ByteSSEInstruction(ins))
        {
            // Output 3rd byte of the opcode
            dst += emitOutputByte(dst, code);
            code &= 0xFF00;
        }
    }
    else if (code & 0x00FF0000)
    {
        dst += emitOutputByte(dst, code >> 16);
        code &= 0x0000FFFF;
    }

    // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
    if ((code & 0xFF00) == 0xC000)
    {
        dst += emitOutputWord(dst, code | (regCode << 8));
    }
    else if ((code & 0xFF) == 0x00)
    {
        // This case happens for some SSE/AVX instructions only
        assert(IsVexOrEvexEncodableInstruction(ins) || Is4ByteSSEInstruction(ins));

        dst += emitOutputByte(dst, (code >> 8) & 0xFF);
        dst += emitOutputByte(dst, (0xC0 | regCode));
    }
    else if (IsApxNddEncodableInstruction(ins) && id->idIsEvexNdContextSet())
    {
        dst += emitOutputByte(dst, (code & 0xFF));
        dst += emitOutputByte(dst, (0xC0 | regCode | (code >> 8)));
    }
    else
    {
        dst += emitOutputWord(dst, code);
        dst += emitOutputByte(dst, (0xC0 | regCode));
    }

    // Does this instruction operate on a GC ref value?
    if (id->idGCref())
    {
        emitHandleGCrefRegs(dst, id);
    }
    else
    {
        if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
        {
            switch (id->idInsFmt())
            {
                case IF_RRD_CNS:
                {
                    // INS_mulEAX can not be used with any of these formats
                    assert(ins != INS_mulEAX && ins != INS_imulEAX);

                    // For the three operand imul instruction the target
                    // register is encoded in the opcode

                    if (instrIs3opImul(ins))
                    {
                        regNumber tgtReg = inst3opImulReg(ins);
                        emitGCregDeadUpd(tgtReg, dst);
                    }
                    break;
                }

                case IF_RWR_RRD:
                case IF_RRW_RRD:
                {
                    emitGCregDeadUpd(reg1, dst);
                    break;
                }

                default:
                    break;
            }
        }
    }

    return dst;
}

BYTE* emitter::emitOutputRRR(BYTE* dst, instrDesc* id)
{
    code_t code;

    instruction ins = id->idIns();
    assert(IsVexOrEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));
    assert(IsThreeOperandAVXInstruction(ins) || isAvxBlendv(ins) || isAvx512Blendv(ins) || IsKInstruction(ins) ||
           IsApxExtendedEvexInstruction(ins));
    regNumber targetReg = id->idReg1();
    regNumber src1      = id->idReg2();
    regNumber src2      = id->idReg3();
    emitAttr  size      = id->idOpSize();

    code = insCodeRM(ins);
    code = AddX86PrefixIfNeeded(id, code, size);

    if (IsApxExtendedEvexInstruction(ins) && !IsBMIInstruction(ins))
    {
        // TODO-XArch-apx:
        // For rm-like operand encoding instructions:
        // legacy promoted EVEX encoding has introduced different semantic:
        // op1 - vvvvv
        // op2 - MODRM.REG
        // op3 - MODRM.R/M
        regNumber tmp = src1;
        src1          = targetReg;
        targetReg     = tmp;

        switch (size)
        {
            case EA_1BYTE:
                // TODO-APX : verify  We should never end up here. Atleast for instructions I have looked into, we
                // promote to int to do operation
                noway_assert(RBM_BYTE_REGS & genRegMask(src1));
                noway_assert(RBM_BYTE_REGS & genRegMask(src2));
                noway_assert(RBM_BYTE_REGS & genRegMask(targetReg));
                break;

            case EA_2BYTE:
            case EA_4BYTE:
                // Set the 'w' bit to get the large version
                code = insIsCMOV(ins) ? code : (code | (0x01));
                break;

#ifdef TARGET_AMD64
            case EA_8BYTE:
                // TODO-AMD64-CQ: Better way to not emit REX.W when we don't need it
                // Don't need to zero out the high bits explicitly
                code = AddRexWPrefix(id, code); // TODO-APX : Revisit. does xor or other cases need to be handled
                                                // differently? see emitOutputRR
                // Set the 'w' bit to get the large version
                code = insIsCMOV(ins) ? code : (code | (0x01));
                break;

#endif // TARGET_AMD64

            default:
                assert(!"unexpected size");
        }
    }

    code = insEncodeRMreg(id, code);

    if (TakesRexWPrefix(id))
    {
        code = AddRexWPrefix(id, code);
    }

    unsigned regCode = insEncodeReg345(id, targetReg, size, &code);
    regCode |= insEncodeReg012(id, src2, size, &code);
    // encode source operand reg in 'vvvv' bits in 1's complement form
    code = insEncodeReg3456(id, src1, size, code);

    // Output the REX/VEX/EVEX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    // Is this a 'big' opcode?
    if (code & 0xFF000000)
    {
        // Output the highest word of the opcode
        dst += emitOutputWord(dst, code >> 16);
        code &= 0x0000FFFF;
    }
    else if (code & 0x00FF0000)
    {
        dst += emitOutputByte(dst, code >> 16);
        code &= 0x0000FFFF;
    }

    // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
    if ((code & 0xFF00) == 0xC000)
    {
        dst += emitOutputWord(dst, code | (regCode << 8));
    }
    else if ((code & 0xFF) == 0x00)
    {
        // This case happens for AVX instructions only
        assert(IsVexOrEvexEncodableInstruction(ins));

        dst += emitOutputByte(dst, (code >> 8) & 0xFF);
        dst += emitOutputByte(dst, (0xC0 | regCode));
    }
    else
    {
        dst += emitOutputWord(dst, code);
        dst += emitOutputByte(dst, (0xC0 | regCode));
    }

    if (id->idGCref())
    {
        emitHandleGCrefRegs(dst, id);
    }

    if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
    {
        switch (id->idInsFmt())
        {
            case IF_RWR_RRD_RRD:
            case IF_RRW_RRD_RRD:
            case IF_RWR_RRD_RRD_CNS:
            case IF_RWR_RRD_RRD_RRD:
            {
                emitGCregDeadUpd(id->idReg1(), dst);
                break;
            }

            case IF_RWR_RWR_RRD:
            {
                emitGCregDeadUpd(id->idReg1(), dst);
                emitGCregDeadUpd(id->idReg2(), dst);
                break;
            }

            default:
                break;
        }
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction with a register and constant operands.
 */

BYTE* emitter::emitOutputRI(BYTE* dst, instrDesc* id)
{
    code_t      code;
    emitAttr    size      = id->idOpSize();
    instruction ins       = id->idIns();
    regNumber   reg       = id->idReg1();
    ssize_t     val       = emitGetInsSC(id);
    bool        valInByte = ((signed char)val == (target_ssize_t)val) && (ins != INS_mov) && (ins != INS_test);

    assert(!id->idHasReg2());

    // BT reg,imm might be useful but it requires special handling of the immediate value
    // (it is always encoded in a byte). Let's not complicate things until this is needed.
    assert(ins != INS_bt);

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte
    }

    noway_assert(emitVerifyEncodable(ins, size, reg));

    if (IsSimdInstruction(ins))
    {
        // Handle SSE2 instructions of the form "opcode reg, immed8"

        assert(id->idGCref() == GCT_NONE);
        assert(valInByte);

        // The left and right shifts use the same encoding, and are distinguished by the Reg/Opcode field.
        regNumber regOpcode = getSseShiftRegNumber(ins);

        // Get the 'base' opcode.
        code = insCodeMI(ins);
        code = AddX86PrefixIfNeeded(id, code, size);
        code = insEncodeMIreg(id, reg, size, code);
        assert(code & 0x00FF0000);
        if (TakesSimdPrefix(id))
        {
            // The 'vvvv' bits encode the destination register, which for this case (RI)
            // is the same as the source.
            code = insEncodeReg3456(id, reg, size, code);
        }

        unsigned regcode = (insEncodeReg345(id, regOpcode, size, &code) | insEncodeReg012(id, reg, size, &code)) << 8;

        // Output the REX prefix
        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        if (code & 0xFF000000)
        {
            dst += emitOutputWord(dst, code >> 16);
        }
        else if (code & 0xFF0000)
        {
            dst += emitOutputByte(dst, code >> 16);
        }

        dst += emitOutputWord(dst, code | regcode);

        dst += emitOutputByte(dst, val);

        return dst;
    }

    // The 'mov' opcode is special
    if (ins == INS_mov)
    {
        code = insCodeACC(ins);
        assert(code < 0x100);

        // This is INS_mov and will not take VEX prefix
        assert(!TakesVexPrefix(ins));

        code = AddX86PrefixIfNeededAndNotPresent(id, code, size);
        code |= 0x08; // Set the 'w' bit
        unsigned regcode = insEncodeReg012(id, reg, size, &code);
        code |= regcode;

        if (TakesRexWPrefix(id))
        {
            code = AddRexWPrefix(id, code);
        }

        dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

        dst += emitOutputByte(dst, code);
        if (size == EA_4BYTE)
        {
            dst += emitOutputLong(dst, val);
        }
#ifdef TARGET_AMD64
        else
        {
            assert(size == EA_PTRSIZE);
            dst += emitOutputSizeT(dst, val);
        }
#endif

        if (id->idIsCnsReloc())
        {
            if (emitComp->IsTargetAbi(CORINFO_NATIVEAOT_ABI) && id->idAddr()->iiaSecRel)
            {
                // For section relative, the immediate offset is relocatable and hence need IMAGE_REL_SECREL
                emitRecordRelocation((void*)(dst - (unsigned)EA_SIZE(size)), (void*)(size_t)val, IMAGE_REL_SECREL);
            }
            else
            {
                emitRecordRelocation((void*)(dst - (unsigned)EA_SIZE(size)), (void*)(size_t)val,
                                     IMAGE_REL_BASED_MOFFSET);
            }
        }

        goto DONE;
    }

    // Decide which encoding is the shortest
    bool useSigned, useACC;

    if (reg == REG_EAX && !instrIs3opImul(ins))
    {
        if (size == EA_1BYTE || (ins == INS_test))
        {
            // For al, ACC encoding is always the smallest
            useSigned = false;
            useACC    = true;
        }
        else
        {
            /* For ax/eax, we avoid ACC encoding for small constants as we
             * can emit the small constant and have it sign-extended.
             * For big constants, the ACC encoding is better as we can use
             * the 1 byte opcode
             */

            if (valInByte)
            {
                // avoid using ACC encoding
                useSigned = true;
                useACC    = false;
            }
            else
            {
                useSigned = false;
                useACC    = true;
            }
        }

        if (TakesApxExtendedEvexPrefix(id))
        {
            // ACC form does not have support for promoted EVEX.
            useACC = false;
        }
    }
    else
    {
        useACC = false;

        if (valInByte)
        {
            useSigned = true;
        }
        else
        {
            useSigned = false;
        }
    }

    // "test" has no 's' bit
    if (!HasRegularWideImmediateForm(ins))
    {
        useSigned = false;
    }

    // Get the 'base' opcode
    if (useACC)
    {
        assert(!useSigned);
        code = insCodeACC(ins);
        // TODO-xarch-apx:
        // There is a case that instructions with 0xA* opcode cannot be prefixed by REX2.
        code = (ins == INS_test) ? code : AddX86PrefixIfNeeded(id, code, size);
    }
    else
    {
        assert(!useSigned || valInByte);

        // Some instructions (at least 'imul') do not have a
        // r/m, immed form, but do have a dstReg,srcReg,imm8 form.
        if (valInByte && useSigned && insNeedsRRIb(ins))
        {
            code = insEncodeRRIb(id, reg, size);
        }
        else
        {
            code = insCodeMI(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeMIreg(id, reg, size, code);
        }
    }

    switch (size)
    {
        case EA_1BYTE:
            break;

        case EA_2BYTE:
            // Output a size prefix for a 16-bit operand
            if (!TakesApxExtendedEvexPrefix(id))
            {
                dst += emitOutputByte(dst, 0x66);
            }
            FALLTHROUGH;

        case EA_4BYTE:
            // Set the 'w' bit to get the large version
            code |= 0x1;
            break;

#ifdef TARGET_AMD64
        case EA_8BYTE:
            /* Set the 'w' bit to get the large version */
            /* and the REX.W bit to get the really large version */

            code = AddRexWPrefix(id, code);
            code |= 0x1;
            break;
#endif

        default:
            assert(!"unexpected size");
    }

    // Output the REX prefix
    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

    // Does the value fit in a sign-extended byte?
    // Important!  Only set the 's' bit when we have a size larger than EA_1BYTE.
    // Note: A sign-extending immediate when (size == EA_1BYTE) is invalid in 64-bit mode.

    if (useSigned && (size > EA_1BYTE))
    {
        // We can just set the 's' bit, and issue an immediate byte

        code |= 0x2; // Set the 's' bit to use a sign-extended immediate byte.
        dst += emitOutputWord(dst, code);
        dst += emitOutputByte(dst, val);
    }
    else
    {
        // Can we use an accumulator (EAX) encoding?
        if (useACC)
        {
            dst += emitOutputByte(dst, code);
        }
        else
        {
            dst += emitOutputWord(dst, code);
        }

        switch (size)
        {
            case EA_1BYTE:
                dst += emitOutputByte(dst, val);
                break;
            case EA_2BYTE:
                dst += emitOutputWord(dst, val);
                break;
            case EA_4BYTE:
                dst += emitOutputLong(dst, val);
                break;
#ifdef TARGET_AMD64
            case EA_8BYTE:
                dst += emitOutputLong(dst, val);
                break;
#endif // TARGET_AMD64
            default:
                break;
        }

        if (id->idIsCnsReloc())
        {
            emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)val, IMAGE_REL_BASED_HIGHLOW);
            assert(size == EA_4BYTE);
        }
    }

DONE:

    // Does this instruction operate on a GC ref value?
    if (id->idGCref())
    {
        switch (id->idInsFmt())
        {
            case IF_RRD_CNS:
                break;

            case IF_RWR_CNS:
                emitGCregLiveUpd(id->idGCref(), id->idReg1(), dst);
                break;

            case IF_RRW_CNS:
            {
                assert(id->idGCref() == GCT_BYREF);

#ifdef DEBUG
                regMaskTP regMask;
                regMask = genRegMask(reg);
                // FIXNOW review the other places and relax the assert there too

                // The reg must currently be holding either a gcref or a byref
                // GCT_GCREF+int = GCT_BYREF, and GCT_BYREF+/-int = GCT_BYREF
                if (emitThisGCrefRegs & regMask)
                {
                    assert(ins == INS_add);
                }
                if (emitThisByrefRegs & regMask)
                {
                    assert(ins == INS_add || ins == INS_sub || ins == INS_sub_hide);
                }
#endif
                // Mark it as holding a GCT_BYREF
                emitGCregLiveUpd(GCT_BYREF, id->idReg1(), dst);
                break;
            }
            default:
#ifdef DEBUG
                emitDispIns(id, false, false, false);
#endif
                assert(!"unexpected GC ref instruction format");
        }

        // mul can never produce a GC ref
        assert(!instrIs3opImul(ins));
        assert(ins != INS_mulEAX && ins != INS_imulEAX);
    }
    else
    {
        switch (id->idInsFmt())
        {
            case IF_RRD_CNS:
                // INS_mulEAX can not be used with any of these formats
                assert(ins != INS_mulEAX && ins != INS_imulEAX);

                // For the three operand imul instruction the target
                // register is encoded in the opcode

                if (instrIs3opImul(ins))
                {
                    regNumber tgtReg = inst3opImulReg(ins);
                    emitGCregDeadUpd(tgtReg, dst);
                }
                break;

            case IF_RRW_CNS:
            case IF_RWR_CNS:
                assert(!instrIs3opImul(ins));

                emitGCregDeadUpd(id->idReg1(), dst);
                break;

            default:
#ifdef DEBUG
                emitDispIns(id, false, false, false);
#endif
                assert(!"unexpected GC ref instruction format");
        }
    }

    return dst;
}

/*****************************************************************************
 *
 *  Output an instruction with a constant operand.
 */

BYTE* emitter::emitOutputIV(BYTE* dst, instrDesc* id)
{
    code_t      code;
    instruction ins       = id->idIns();
    emitAttr    size      = id->idOpSize();
    ssize_t     val       = emitGetInsSC(id);
    bool        valInByte = ((signed char)val == (target_ssize_t)val);

    // We would to update GC info correctly
    assert(!IsSSEInstruction(ins));
    assert(!IsVexOrEvexEncodableInstruction(ins));

#ifdef TARGET_AMD64
    // all these opcodes take a sign-extended 4-byte immediate, max
    noway_assert(size < EA_8BYTE || ((int)val == val && !id->idIsCnsReloc()));
#endif

    if (id->idIsCnsReloc())
    {
        valInByte = false; // relocs can't be placed in a byte

        // Of these instructions only the push instruction can have reloc
        assert(ins == INS_push || ins == INS_push_hide);
    }

    switch (ins)
    {
        case INS_jge:
            assert((val >= -128) && (val <= 127));
            dst += emitOutputByte(dst, insCode(ins));
            dst += emitOutputByte(dst, val);
            break;

        case INS_loop:
            assert((val >= -128) && (val <= 127));
            dst += emitOutputByte(dst, insCodeMI(ins));
            dst += emitOutputByte(dst, val);
            break;

        case INS_ret:
            assert(val);
            dst += emitOutputByte(dst, insCodeMI(ins));
            dst += emitOutputWord(dst, val);
            break;

        case INS_push_hide:
        case INS_push:
            code = insCodeMI(ins);

            // TODO-xarch-apx: it is TBD if we will use REX2 for PUSH/POP,
            //                 the implementation here is optional.
            if (TakesRex2Prefix(id))
            {
                code = AddRex2Prefix(ins, code);
            }

            // Does the operand fit in a byte?
            if (valInByte)
            {
                if (TakesRex2Prefix(id))
                {
                    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
                }

                dst += emitOutputByte(dst, code | 2);
                dst += emitOutputByte(dst, val);
            }
            else
            {
                if (TakesRexWPrefix(id) || TakesRex2Prefix(id))
                {
                    code = AddRexWPrefix(id, code);
                    dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
                }

                dst += emitOutputByte(dst, code);
                dst += emitOutputLong(dst, val);
                if (id->idIsCnsReloc())
                {
                    emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)val, IMAGE_REL_BASED_HIGHLOW);
                }
            }
            break;

        default:
            assert(!"unexpected instruction");
    }

    // GC tracking for "push"es is done by "emitStackPush", for all other instructions
    // that can reach here we do not expect (and do not handle) GC refs.
    assert((ins == INS_push) || !id->idGCref());

    return dst;
}

/*****************************************************************************
 *
 *  Output a local jump instruction.
 *  This function also handles non-jumps that have jump-like characteristics, like RIP-relative LEA of a label that
 *  needs to get bound to an actual address and processed by branch shortening.
 */
BYTE* emitter::emitOutputLJ(insGroup* ig, BYTE* dst, instrDesc* i)
{
    unsigned srcOffs;
    unsigned dstOffs;
    BYTE*    srcAddr;
    BYTE*    dstAddr;
    ssize_t  distVal;

    instrDescJmp* id  = (instrDescJmp*)i;
    instruction   ins = id->idIns();
    bool          jmp;
    bool          relAddr = true; // does the instruction use relative-addressing?

    // SSE/AVX doesnt make any sense here
    assert(!IsSSEInstruction(ins));
    assert(!IsVexOrEvexEncodableInstruction(ins));

    size_t ssz;
    size_t lsz;

    switch (ins)
    {
        default:
            ssz = JCC_SIZE_SMALL;
            lsz = JCC_SIZE_LARGE;
            jmp = true;
            break;

        case INS_jmp:
            ssz = JMP_SIZE_SMALL;
            lsz = JMP_SIZE_LARGE;
            jmp = true;
            break;

        case INS_call:
            ssz = lsz = CALL_INST_SIZE;
            jmp       = false;
            break;

        case INS_push_hide:
        case INS_push:
            ssz = lsz = 5;
            jmp       = false;
            relAddr   = false;
            break;

        case INS_mov:
        case INS_lea:
            ssz = lsz = id->idCodeSize();
            jmp       = false;
            relAddr   = false;
            break;
    }

    // Figure out the distance to the target
    srcOffs = emitCurCodeOffs(dst);
    srcAddr = emitOffsetToPtr(srcOffs);

    if (id->idAddr()->iiaHasInstrCount())
    {
        assert(ig != nullptr);
        int      instrCount = id->idAddr()->iiaGetInstrCount();
        unsigned insNum     = emitFindInsNum(ig, id);
        if (instrCount < 0)
        {
            // Backward branches using instruction count must be within the same instruction group.
            assert(insNum + 1 >= (unsigned)(-instrCount));
        }
        dstOffs = ig->igOffs + emitFindOffset(ig, (insNum + 1 + instrCount));
        dstAddr = emitOffsetToPtr(dstOffs);
    }
    else
    {
        dstOffs = id->idAddr()->iiaIGlabel->igOffs;
        dstAddr = emitOffsetToPtr(dstOffs);
        if (!relAddr)
        {
            srcAddr = nullptr;
        }
    }

    distVal = (ssize_t)(dstAddr - srcAddr);

    if (dstOffs <= srcOffs)
    {
        // This is a backward jump - distance is known at this point

#if DEBUG_EMIT
        if (id->idDebugOnlyInfo()->idNum == (unsigned)INTERESTING_JUMP_NUM || INTERESTING_JUMP_NUM == 0)
        {
            size_t blkOffs = id->idjIG->igOffs;

            if (INTERESTING_JUMP_NUM == 0)
            {
                printf("[3] Jump %u:\n", id->idDebugOnlyInfo()->idNum);
            }
            printf("[3] Jump  block is at %08X - %02X = %08X\n", blkOffs, emitOffsAdj, blkOffs - emitOffsAdj);
            printf("[3] Jump        is at %08X - %02X = %08X\n", srcOffs, emitOffsAdj, srcOffs - emitOffsAdj);
            printf("[3] Label block is at %08X - %02X = %08X\n", dstOffs, emitOffsAdj, dstOffs - emitOffsAdj);
        }
#endif

        // Can we use a short jump?
        if (jmp && distVal - ssz >= (size_t)JMP_DIST_SMALL_MAX_NEG)
        {
            emitSetShortJump(id);
        }
    }
    else
    {
        // This is a  forward jump - distance will be an upper limit
        emitFwdJumps = true;

        // The target offset will be closer by at least 'emitOffsAdj', but only if this
        // jump doesn't cross the hot-cold boundary.
        if (!emitJumpCrossHotColdBoundary(srcOffs, dstOffs))
        {
            dstOffs -= emitOffsAdj;
            distVal -= emitOffsAdj;
        }

        // Record the location of the jump for later patching
        id->idjOffs = dstOffs;

        // Are we overflowing the id->idjOffs bitfield?
        if (id->idjOffs != dstOffs)
        {
            IMPL_LIMITATION("Method is too large");
        }

#if DEBUG_EMIT
        if (id->idDebugOnlyInfo()->idNum == (unsigned)INTERESTING_JUMP_NUM || INTERESTING_JUMP_NUM == 0)
        {
            size_t blkOffs = id->idjIG->igOffs;

            if (INTERESTING_JUMP_NUM == 0)
            {
                printf("[4] Jump %u:\n", id->idDebugOnlyInfo()->idNum);
            }
            printf("[4] Jump  block is at %08X\n", blkOffs);
            printf("[4] Jump        is at %08X\n", srcOffs);
            printf("[4] Label block is at %08X - %02X = %08X\n", dstOffs + emitOffsAdj, emitOffsAdj, dstOffs);
        }
#endif

        // Can we use a short jump?
        if (jmp && distVal - ssz <= (size_t)JMP_DIST_SMALL_MAX_POS)
        {
            emitSetShortJump(id);
        }
    }

    // Adjust the offset to emit relative to the end of the instruction
    if (relAddr)
    {
        distVal -= id->idjShort ? ssz : lsz;
    }

#ifdef DEBUG
    if (0 && emitComp->verbose)
    {
        size_t sz          = id->idjShort ? ssz : lsz;
        int    distValSize = id->idjShort ? 4 : 8;
        printf("; %s jump [%08X/%03u] from %0*X to %0*X: dist = 0x%08X\n", (dstOffs <= srcOffs) ? "Fwd" : "Bwd",
               emitComp->dspPtr(id), id->idDebugOnlyInfo()->idNum, distValSize, srcOffs + sz, distValSize, dstOffs,
               distVal);
    }
#endif

    // What size jump should we use?
    if (id->idjShort)
    {
        // Short jump
        assert(!id->idjKeepLong);
        assert(emitJumpCrossHotColdBoundary(srcOffs, dstOffs) == false);

        assert(JMP_SIZE_SMALL == JCC_SIZE_SMALL);
        assert(JMP_SIZE_SMALL == 2);

        assert(jmp);

        if (id->idCodeSize() != JMP_SIZE_SMALL)
        {
#if DEBUG_EMIT || defined(DEBUG)
            int offsShrinkage = id->idCodeSize() - JMP_SIZE_SMALL;
            if (INDEBUG(emitComp->verbose ||)(id->idDebugOnlyInfo()->idNum == (unsigned)INTERESTING_JUMP_NUM ||
                                              INTERESTING_JUMP_NUM == 0))
            {
                printf("; NOTE: size of jump [%08p] mis-predicted by %d bytes\n", dspPtr(id), offsShrinkage);
            }
#endif
        }

        dst += emitOutputByte(dst, insCode(ins));

        // For forward jumps, record the address of the distance value
        id->idjTemp.idjAddr = (distVal > 0) ? dst : nullptr;

        dst += emitOutputByte(dst, distVal);
    }
    else
    {
        code_t code;

        // Long  jump
        if (jmp)
        {
            // clang-format off
            assert(INS_jmp + (INS_l_jmp - INS_jmp) == INS_l_jmp);
            assert(INS_jo  + (INS_l_jmp - INS_jmp) == INS_l_jo);
            assert(INS_jb  + (INS_l_jmp - INS_jmp) == INS_l_jb);
            assert(INS_jae + (INS_l_jmp - INS_jmp) == INS_l_jae);
            assert(INS_je  + (INS_l_jmp - INS_jmp) == INS_l_je);
            assert(INS_jne + (INS_l_jmp - INS_jmp) == INS_l_jne);
            assert(INS_jbe + (INS_l_jmp - INS_jmp) == INS_l_jbe);
            assert(INS_ja  + (INS_l_jmp - INS_jmp) == INS_l_ja);
            assert(INS_js  + (INS_l_jmp - INS_jmp) == INS_l_js);
            assert(INS_jns + (INS_l_jmp - INS_jmp) == INS_l_jns);
            assert(INS_jp  + (INS_l_jmp - INS_jmp) == INS_l_jp);
            assert(INS_jnp + (INS_l_jmp - INS_jmp) == INS_l_jnp);
            assert(INS_jl  + (INS_l_jmp - INS_jmp) == INS_l_jl);
            assert(INS_jge + (INS_l_jmp - INS_jmp) == INS_l_jge);
            assert(INS_jle + (INS_l_jmp - INS_jmp) == INS_l_jle);
            assert(INS_jg  + (INS_l_jmp - INS_jmp) == INS_l_jg);
            // clang-format on

            code = insCode((instruction)(ins + (INS_l_jmp - INS_jmp)));
        }
        else if (ins == INS_push || ins == INS_push_hide)
        {
            assert(insCodeMI(INS_push) == 0x68);
            code = 0x68;
        }
        else if (ins == INS_mov)
        {
            // Make it look like IF_SWR_CNS so that emitOutputSV emits the r/m32 for us
            insFormat tmpInsFmt   = id->idInsFmt();
            insGroup* tmpIGlabel  = id->idAddr()->iiaIGlabel;
            bool      tmpDspReloc = id->idIsDspReloc();

            id->idInsFmt(emitInsModeFormat(ins, IF_SRD_CNS));
            id->idAddr()->iiaLclVar = ((instrDescLbl*)id)->dstLclVar;
            id->idSetIsDspReloc(false);

            dst = emitOutputSV(dst, id, insCodeMI(ins));

            // Restore id fields with original values
            id->idInsFmt(tmpInsFmt);
            id->idAddr()->iiaIGlabel = tmpIGlabel;
            id->idSetIsDspReloc(tmpDspReloc);
            code = 0xCC;
        }
        else if (ins == INS_lea)
        {
            // Make an instrDesc that looks like IF_RWR_ARD so that emitOutputAM emits the r/m32 for us.
            // We basically are doing what emitIns_R_AI does.
            // TODO-XArch-Cleanup: revisit this.
            inlineInstrDesc<instrDescAmd> idAmdStackLocal;
            instrDescAmd*                 idAmd = idAmdStackLocal.id();
            *(instrDesc*)idAmd                  = *(instrDesc*)id; // copy all the "core" fields

            if (m_debugInfoSize > 0)
            {
                idAmd->idDebugOnlyInfo(id->idDebugOnlyInfo());
            }

            idAmd->idInsFmt(emitInsModeFormat(ins, IF_RRD_ARD));
            idAmd->idAddr()->iiaAddrMode.amBaseReg = REG_NA;
            idAmd->idAddr()->iiaAddrMode.amIndxReg = REG_NA;
            emitSetAmdDisp(idAmd, distVal); // set the displacement
            idAmd->idSetIsDspReloc(id->idIsDspReloc());
            assert(emitGetInsAmdAny(idAmd) == distVal); // make sure "disp" is stored properly

            UNATIVE_OFFSET sz = emitInsSizeAM(idAmd, insCodeRM(ins));
            idAmd->idCodeSize(sz);

            code = insCodeRM(ins);
            code = AddX86PrefixIfNeeded(id, code, id->idOpSize());
            code |= (insEncodeReg345(id, id->idReg1(), EA_PTRSIZE, &code) << 8);

            dst = emitOutputAM(dst, idAmd, code, nullptr);

            code = 0xCC;

            // For forward jumps, record the address of the distance value
            // Hard-coded 4 here because we already output the displacement, as the last thing.
            id->idjTemp.idjAddr = (dstOffs > srcOffs) ? (dst - 4) : nullptr;

            // We're done
            return dst;
        }
        else
        {
            code = 0xE8;
        }

        if (ins != INS_mov)
        {
            dst += emitOutputByte(dst, code);

            if (code & 0xFF00)
            {
                dst += emitOutputByte(dst, code >> 8);
            }
        }

        // For forward jumps, record the address of the distance value
        id->idjTemp.idjAddr = (dstOffs > srcOffs) ? dst : nullptr;

        bool crossJump = emitJumpCrossHotColdBoundary(srcOffs, dstOffs);

        int32_t encodedDisplacement;
        if (emitComp->opts.compReloc && (!relAddr || crossJump))
        {
            // Cross jumps may not be encodable in a 32-bit displacement as the
            // hot/cold code buffers may be allocated arbitrarily far away from
            // each other. Similarly, absolute addresses when cross compiling
            // for 32-bit may also not be representable. We simply encode a 0
            // under the assumption that the relocations will take care of it.
            encodedDisplacement = 0;
        }
        else
        {
            // For all other cases the displacement should be encodable in 32
            // bits.
            assert((distVal >= INT32_MIN) && (distVal <= INT32_MAX));
            encodedDisplacement = static_cast<int32_t>(distVal);
        }

        dst += emitOutputLong(dst, encodedDisplacement);

        if (emitComp->opts.compReloc)
        {
            if (!relAddr)
            {
                emitRecordRelocation((void*)(dst - sizeof(int32_t)), (void*)distVal, IMAGE_REL_BASED_HIGHLOW);
            }
            else if (crossJump)
            {
                assert(id->idjKeepLong);
                emitRecordRelocation((void*)(dst - sizeof(int32_t)), dst + distVal, IMAGE_REL_BASED_REL32);
            }
        }
    }

    // Local calls kill all registers
    if (ins == INS_call && (emitThisGCrefRegs | emitThisByrefRegs))
    {
        emitGCregDeadUpdMask(emitThisGCrefRegs | emitThisByrefRegs, dst);
    }

    return dst;
}

//------------------------------------------------------------------------
// GetInputSizeInBytes: Get size of input for instruction in bytes.
//
// Arguments:
//    id -- Instruction descriptor.
//
// Return Value:
//    size in bytes.
//
ssize_t emitter::GetInputSizeInBytes(const instrDesc* id) const
{
    assert((unsigned)id->idIns() < ArrLen(CodeGenInterface::instInfo));
    insFlags inputSize = static_cast<insFlags>((CodeGenInterface::instInfo[id->idIns()] & Input_Mask));

    switch (inputSize)
    {
        case 0:
            return EA_SIZE_IN_BYTES(id->idOpSize());
        case Input_8Bit:
            return 1;
        case Input_16Bit:
            return 2;
        case Input_32Bit:
            return 4;
        case Input_64Bit:
            return 8;
        default:
            unreached();
    }
}

//------------------------------------------------------------------------
// TryEvexCompressDisp8Byte: Do we do compressed displacement encoding for EVEX.
//
// Arguments:
//    id              -- Instruction descriptor.
//    dsp             -- displacement to try and compress
//    compressedDsp   -- [out] the compressed displacement on success; otherwise, dsp
//    fitsInByte      -- [out] true if the displacement fits in a byte; otherwise, false
//
// Return Value:
//    True if the displacement was compressed; otherwise, false
//
bool emitter::TryEvexCompressDisp8Byte(instrDesc* id, ssize_t dsp, ssize_t* compressedDsp, bool* fitsInByte) const
{
    instruction ins = id->idIns();

    assert(IsEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));
    assert(id->idHasMem() && !id->idHasMemGen());
    assert(!id->idIsDspReloc());
    assert(compressedDsp != nullptr);
    assert(fitsInByte != nullptr);

    *compressedDsp = dsp;
    *fitsInByte    = (static_cast<signed char>(dsp) == dsp);

    if (!hasTupleTypeInfo(ins))
    {
        // After APX, some instructions with APX features will be promoted
        // to APX-EVEX, we will re-use the existing displacement emitting
        // path, but for those instructions with no tuple information,
        // APX-EVEX treat the scaling factor to be 1 constantly.

        assert(IsApxExtendedEvexInstruction(ins) || IsBMIInstruction(ins) || IsKMOVInstruction(ins));
        assert(*compressedDsp == dsp);

        return *fitsInByte;
    }

    if (*fitsInByte)
    {
        if (!TakesEvexPrefix(id))
        {
            // We already fit into a byte and do not otherwise require the EVEX prefix
            // which means we can use the VEX encoding instead and be even smaller.

            assert(*compressedDsp == dsp);
            return false;
        }
    }
    else
    {
        ssize_t compressedTest = dsp / 64;

        if (static_cast<signed char>(compressedTest) != compressedTest)
        {
            // We are larger than the maximum possible compressed displacement
            assert(*compressedDsp == dsp);
            return false;
        }
    }

    insTupleType tt = insTupleTypeInfo(ins);

    ssize_t vectorLength     = EA_SIZE_IN_BYTES(id->idOpSize());
    ssize_t inputSize        = GetInputSizeInBytes(id);
    ssize_t disp8Compression = 1;

    if ((tt & INS_TT_MEM128) != 0)
    {
        // These instructions can be one of two tuple types, so we need to find the right one
        insFormat insFmt = id->idInsFmt();

        if ((tt & INS_TT_FULL) != 0)
        {
            assert(tt == (INS_TT_FULL | INS_TT_MEM128));
            assert((ins == INS_pslld) || (ins == INS_psrad) || (ins == INS_psrld) || (ins == INS_psllq) ||
                   (ins == INS_vpsraq) || (ins == INS_psrlq));
        }
        else
        {
            assert(tt == (INS_TT_FULL_MEM | INS_TT_MEM128));
            assert((ins == INS_psllw) || (ins == INS_psraw) || (ins == INS_psrlw));
        }

        switch (insFmt)
        {
            case IF_RWR_RRD_ARD:
            case IF_RWR_RRD_MRD:
            case IF_RWR_RRD_SRD:
            {
                tt = static_cast<insTupleType>(tt & INS_TT_MEM128);
                break;
            }

            case IF_RWR_ARD_CNS:
            case IF_RWR_MRD_CNS:
            case IF_RWR_SRD_CNS:
            {
                tt = static_cast<insTupleType>(tt & ~INS_TT_MEM128);
                break;
            }

            default:
            {
                unreached();
            }
        }
    }

    bool isEmbBroadcast = HasEmbeddedBroadcast(id);

    switch (tt)
    {
        case INS_TT_FULL:
        {
            if (isEmbBroadcast)
            {
                // N = input size in bytes
                disp8Compression = inputSize;
            }
            else
            {
                // N = vector length in bytes
                disp8Compression = vectorLength;
            }
            break;
        }

        case INS_TT_HALF:
        {
            assert(inputSize == 4);
            if (isEmbBroadcast)
            {
                // N = input size in bytes
                disp8Compression = inputSize;
            }
            else
            {
                // N = vector length in bytes
                disp8Compression = vectorLength / 2;
            }
            break;
        }

        case INS_TT_FULL_MEM:
        {
            // N = vector length in bytes
            assert(!isEmbBroadcast);
            disp8Compression = vectorLength;
            break;
        }

        case INS_TT_TUPLE1_SCALAR:
        {
            assert(!isEmbBroadcast);
            disp8Compression = inputSize;
            break;
        }

        case INS_TT_TUPLE1_FIXED:
        {
            // N = input size in bytes, 32bit and 64bit only
            assert(!isEmbBroadcast);
            assert((inputSize == 4) || (inputSize == 8));
            disp8Compression = inputSize;
            break;
        }

        case INS_TT_TUPLE2:
        {
            // N = input size in bytes * 2, 32bit and 64bit for 256 bit and 512 bit only
            assert(!isEmbBroadcast);
            assert((inputSize == 4) || ((inputSize == 8) && (vectorLength >= 32)));
            disp8Compression = inputSize * 2;
            break;
        }

        case INS_TT_TUPLE4:
        {
            // N = input size in bytes * 4, 32bit for 256 bit and 512 bit, 64bit for 512 bit
            assert(!isEmbBroadcast);
            assert(((inputSize == 4) && (vectorLength >= 32)) || ((inputSize == 8) && (vectorLength >= 64)));
            disp8Compression = inputSize * 4;
            break;
        }

        case INS_TT_TUPLE8:
        {
            // N = input size in bytes * 8, 32bit for 512 only
            assert(!isEmbBroadcast);
            assert((inputSize == 4) && (vectorLength >= 64));
            disp8Compression = inputSize * 8;
            break;
        }

        case INS_TT_HALF_MEM:
        {
            // N = vector length in bytes / 2
            assert(!isEmbBroadcast);
            disp8Compression = vectorLength / 2;
            break;
        }

        case INS_TT_QUARTER_MEM:
        {
            // N = vector length in bytes / 4
            assert(!isEmbBroadcast);
            disp8Compression = vectorLength / 4;
            break;
        }

        case INS_TT_EIGHTH_MEM:
        {
            // N = vector length in bytes / 8
            assert(!isEmbBroadcast);
            disp8Compression = vectorLength / 8;
            break;
        }

        case INS_TT_MEM128:
        {
            // N = 16
            assert(!isEmbBroadcast);
            disp8Compression = 16;
            break;
        }

        case INS_TT_MOVDDUP:
        {
            // N = vector length in bytes / 2
            assert(!isEmbBroadcast);
            disp8Compression = (vectorLength == 16) ? (vectorLength / 2) : vectorLength;
            break;
        }

        default:
        {
            unreached();
        }
    }

    // If we can evenly divide dsp by the disp8Compression, we can attempt to use it in a disp8 byte form
    if ((dsp % disp8Compression) != 0)
    {
        assert(*compressedDsp == dsp);
        *fitsInByte = false;
        return false;
    }

    ssize_t compressedDisp = dsp / disp8Compression;

    if (static_cast<signed char>(compressedDisp) != compressedDisp)
    {
        assert(*compressedDsp == dsp);
        *fitsInByte = false;
        return false;
    }

    *compressedDsp = compressedDisp;
    *fitsInByte    = true;

    return true;
}

/*****************************************************************************
 *
 *  Append the machine code corresponding to the given instruction descriptor
 *  to the code block at '*dp'; the base of the code block is 'bp', and 'ig'
 *  is the instruction group that contains the instruction. Updates '*dp' to
 *  point past the generated code, and returns the size of the instruction
 *  descriptor in bytes.
 */
size_t emitter::emitOutputInstr(insGroup* ig, instrDesc* id, BYTE** dp)
{
    assert(emitIssuing);

    BYTE*         dst           = *dp;
    size_t        sz            = sizeof(instrDesc);
    instruction   ins           = id->idIns();
    insFormat     insFmt        = id->idInsFmt();
    unsigned char callInstrSize = 0;

    // Indicates a jump between after a call and before an OS epilog was replaced by a nop on AMD64
    bool convertedJmpToNop = false;

#ifdef DEBUG
    bool dspOffs = emitComp->opts.dspGCtbls;
#endif // DEBUG

    emitAttr size = id->idOpSize();

    assert(REG_NA == (int)REG_NA);

    assert(ins != INS_imul || size >= EA_4BYTE);                  // Has no 'w' bit
    assert(instrIs3opImul(id->idIns()) == 0 || size >= EA_4BYTE); // Has no 'w' bit

    VARSET_TP GCvars(VarSetOps::UninitVal());
    regMaskTP gcrefRegs;
    regMaskTP byrefRegs;

    // What instruction format have we got?
    switch (insFmt)
    {
        code_t   code;
        unsigned regcode;
        int      args;
        CnsVal   cnsVal;

        BYTE* addr;
        bool  recCall;

        /********************************************************************/
        /*                        No operands                               */
        /********************************************************************/
        case IF_NONE:
        {
            // the loop alignment pseudo instruction
            if (ins == INS_align)
            {
                sz = sizeof(instrDescAlign);
                // IG can be marked as not needing alignment after emitting align instruction
                // In such case, skip outputting alignment.
                if (ig->endsWithAlignInstr())
                {
                    dst = emitOutputAlign(ig, id, dst);
                }
#ifdef DEBUG
                else
                {
                    // If the IG is not marked as need alignment, then the code size
                    // should be zero i.e. no padding needed.
                    assert(id->idCodeSize() == 0);
                }
#endif
                break;
            }

            if (ins == INS_nop)
            {
                dst = emitOutputNOP(dst, id->idCodeSize());
                break;
            }

            if (ins == INS_data16)
            {
                dst = emitOutputData16(dst);
                sz  = emitSizeOfInsDsc_NONE(id);
                break;
            }

            // the cdq instruction kills the EDX register implicitly
            if (ins == INS_cdq)
            {
                emitGCregDeadUpd(REG_EDX, dst);
            }

            assert(id->idGCref() == GCT_NONE);

            code = insCodeMR(ins);

#ifdef TARGET_AMD64
            // Support only scalar AVX instructions and hence size is hard coded to 4-byte.
            code = AddX86PrefixIfNeeded(id, code, EA_4BYTE);

            if (((ins == INS_cdq) || (ins == INS_cwde)) && TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
#endif
            // Is this a 'big' opcode?
            if (code & 0xFF000000)
            {
                // The high word and then the low word
                dst += emitOutputWord(dst, code >> 16);
                code &= 0x0000FFFF;
                dst += emitOutputWord(dst, code);
            }
            else if (code & 0x00FF0000)
            {
                // The high byte and then the low word
                dst += emitOutputByte(dst, code >> 16);
                code &= 0x0000FFFF;
                dst += emitOutputWord(dst, code);
            }
            else if (code & 0xFF00)
            {
                // The 2 byte opcode
                dst += emitOutputWord(dst, code);
            }
            else
            {
                // The 1 byte opcode
                dst += emitOutputByte(dst, code);
            }

            break;
        }

            /********************************************************************/
            /*                Simple constant, local label, method              */
            /********************************************************************/

        case IF_CNS:
        {
            dst = emitOutputIV(dst, id);
            sz  = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_LABEL:
        {
            instrDescJmp* jmp = (instrDescJmp*)id;
            assert(id->idGCref() == GCT_NONE);

            if (!jmp->idjIsRemovableJmpCandidate)
            {
                assert(id->idIsBound());
                dst = emitOutputLJ(ig, dst, id);
            }
#ifdef TARGET_AMD64
            else if (jmp->idjIsAfterCallBeforeEpilog)
            {
                // Need to insert a nop if the removed jump was after a call and before an OS epilog
                // (The code size should already be set to 1 for the nop)
                assert(id->idCodeSize() == 1);
                dst = emitOutputNOP(dst, 1);

                // Set convertedJmpToNop in case we need to print this instrDesc as a nop in a disasm
                convertedJmpToNop = true;
            }
#endif // TARGET_AMD64
            else
            {
                // Jump was removed, and no nop was needed, so id should not have any code
                assert(jmp->idjIsRemovableJmpCandidate);
                assert(emitJmpInstHasNoCode(id));
            }

            sz = sizeof(instrDescJmp);
            break;
        }
        case IF_RWR_LABEL:
        case IF_SWR_LABEL:
        {
            assert(id->idGCref() == GCT_NONE);
            assert(id->idIsBound() || emitJmpInstHasNoCode(id));
            instrDescJmp* jmp = (instrDescJmp*)id;

            // Jump removal optimization is only for IF_LABEL
            assert(!jmp->idjIsRemovableJmpCandidate);

            // TODO-XArch-Cleanup: handle IF_RWR_LABEL in emitOutputLJ() or change it to emitOutputAM()?
            dst = emitOutputLJ(ig, dst, id);
            sz  = (id->idInsFmt() == IF_SWR_LABEL ? sizeof(instrDescLbl) : sizeof(instrDescJmp));
            break;
        }

        case IF_METHOD:
        case IF_METHPTR:
        {
            // Get hold of the argument count and field Handle
            args = emitGetInsCDinfo(id);

            // Is this a "fat" call descriptor?
            if (id->idIsLargeCall())
            {
                instrDescCGCA* idCall = (instrDescCGCA*)id;
                gcrefRegs             = idCall->idcGcrefRegs;
                byrefRegs             = idCall->idcByrefRegs;
                VarSetOps::Assign(emitComp, GCvars, idCall->idcGCvars);
                sz = sizeof(instrDescCGCA);
            }
            else
            {
                assert(!id->idIsLargeDsp());
                assert(!id->idIsLargeCns());

                gcrefRegs = emitDecodeCallGCregs(id);
                byrefRegs = 0;
                VarSetOps::AssignNoCopy(emitComp, GCvars, VarSetOps::MakeEmpty(emitComp));
                sz = sizeof(instrDesc);
            }

            addr = (BYTE*)id->idAddr()->iiaAddr;
            assert(addr != nullptr);

            // What kind of a call do we have here?
            if (id->idInsFmt() == IF_METHPTR)
            {
                // This is call indirect via a method pointer
                assert((ins == INS_call) || (ins == INS_tail_i_jmp));

                code = insCodeMR(ins);
                code = AddX86PrefixIfNeeded(id, code, size);

                if (id->idIsDspReloc())
                {
                    dst += emitOutputWord(dst, code | 0x0500);
#ifdef TARGET_AMD64
                    dst += emitOutputLong(dst, 0);
#else
                    dst += emitOutputLong(dst, (int)(ssize_t)addr);
#endif
                    emitRecordRelocation((void*)(dst - sizeof(int)), addr, IMAGE_REL_BASED_DISP32);
                }
                else
                {
#ifdef TARGET_X86
                    dst += emitOutputWord(dst, code | 0x0500);
#else  // TARGET_AMD64
       // Amd64: addr fits within 32-bits and can be encoded as a displacement relative to zero.
       // This addr mode should never be used while generating relocatable AOT code nor if
       // the addr can be encoded as pc-relative address.
                    noway_assert(!emitComp->opts.compReloc);
                    noway_assert(codeGen->genAddrRelocTypeHint((size_t)addr) != IMAGE_REL_BASED_REL32);
                    noway_assert(static_cast<int>(reinterpret_cast<intptr_t>(addr)) == (ssize_t)addr);

                    // This requires, specifying a SIB byte after ModRM byte.
                    dst += emitOutputWord(dst, code | 0x0400);
                    dst += emitOutputByte(dst, 0x25);
#endif // TARGET_AMD64
                    dst += emitOutputLong(dst, static_cast<int>(reinterpret_cast<intptr_t>(addr)));
                }
                goto DONE_CALL;
            }

            // Else
            // This is call direct where we know the target, thus we can
            // use a direct call; the target to jump to is in iiaAddr.
            assert(id->idInsFmt() == IF_METHOD);

            // Output the call opcode followed by the target distance
            if (ins == INS_l_jmp)
            {
                dst += emitOutputByte(dst, insCode(ins));
            }
            else
            {
                assert(ins == INS_call);
                code_t callCode = insCodeMI(ins);
                if (emitComp->IsTargetAbi(CORINFO_NATIVEAOT_ABI) && id->idIsTlsGD())
                {
                    callCode = (callCode << 8) | 0x48; // REX.W prefix
                    dst += emitOutputWord(dst, callCode);
                }
                else
                {
                    dst += emitOutputByte(dst, callCode);
                }
            }

            ssize_t offset;
#ifdef TARGET_AMD64
            // All REL32 on Amd64 go through recordRelocation.  Here we will output zero to advance dst.
            offset = 0;
            assert(id->idIsDspReloc());
#else
            // Calculate PC relative displacement.
            // Although you think we should be using sizeof(void*), the x86 and x64 instruction set
            // only allow a 32-bit offset, so we correctly use sizeof(INT32)
            offset = addr - (dst + sizeof(INT32));
#endif

            dst += emitOutputLong(dst, offset);

            if (id->idIsDspReloc())
            {
                emitRecordRelocation((void*)(dst - sizeof(INT32)), addr, IMAGE_REL_BASED_REL32);
            }

        DONE_CALL:

            // Assume we'll be recording this call
            recCall = true;

            // Some helpers don't get recorded in GC tables
            if (id->idIsNoGC())
            {
                recCall = false;
            }

            /* We update the variable (not register) GC info before the call as the variables cannot be
               used by the call. Killing variables before the call helps with
               boundary conditions if the call is CORINFO_HELP_THROW - see bug 50029.
               If we ever track aliased variables (which could be used by the
               call), we would have to keep them alive past the call.
             */
            assert(FitsIn<unsigned char>(dst - *dp));
            callInstrSize = static_cast<unsigned char>(dst - *dp);

            // Note the use of address `*dp`, the call instruction address, instead of `dst`, the post-call-instruction
            // address.
            emitUpdateLiveGCvars(GCvars, *dp);

#ifdef DEBUG
            // Output any delta in GC variable info, corresponding to the before-call GC var updates done above.
            if (EMIT_GC_VERBOSE || emitComp->opts.disasmWithGC)
            {
                emitDispGCVarDelta();
            }
#endif // DEBUG

            // If the method returns a GC ref, mark EAX appropriately
            if (id->idGCref() == GCT_GCREF)
            {
                gcrefRegs |= RBM_EAX;
            }
            else if (id->idGCref() == GCT_BYREF)
            {
                byrefRegs |= RBM_EAX;
            }

            // If is a multi-register return method is called, mark RDX appropriately (for System V AMD64).
            if (id->idIsLargeCall())
            {
                instrDescCGCA* idCall = (instrDescCGCA*)id;
#ifdef UNIX_AMD64_ABI
                if (idCall->idSecondGCref() == GCT_GCREF)
                {
                    gcrefRegs |= RBM_RDX;
                }
                else if (idCall->idSecondGCref() == GCT_BYREF)
                {
                    byrefRegs |= RBM_RDX;
                }
#endif // UNIX_AMD64_ABI
                if (idCall->hasAsyncContinuationRet())
                {
                    gcrefRegs |= RBM_ASYNC_CONTINUATION_RET;
                }
            }

            // If the GC register set has changed, report the new set
            if (gcrefRegs != emitThisGCrefRegs)
            {
                emitUpdateLiveGCregs(GCT_GCREF, gcrefRegs, dst);
            }

            if (byrefRegs != emitThisByrefRegs)
            {
                emitUpdateLiveGCregs(GCT_BYREF, byrefRegs, dst);
            }

            if (recCall || args)
            {
                // For callee-pop, all arguments will be popped  after the call.
                // For caller-pop, any GC arguments will go dead after the call.

                assert(callInstrSize != 0);

                if (args >= 0)
                {
                    emitStackPop(dst, /*isCall*/ true, callInstrSize, args);
                }
                else
                {
                    emitStackKillArgs(dst, -args, callInstrSize);
                }
            }

            // Do we need to record a call location for GC purposes?
            if (!emitFullGCinfo && recCall)
            {
                assert(callInstrSize != 0);
                emitRecordGCcall(dst, callInstrSize);
            }

#ifdef DEBUG
            if ((ins == INS_call) && !id->idIsTlsGD())
            {
                emitRecordCallSite(emitCurCodeOffs(*dp), id->idDebugOnlyInfo()->idCallSig,
                                   (CORINFO_METHOD_HANDLE)id->idDebugOnlyInfo()->idMemCookie);
            }
#endif // DEBUG

            break;
        }

            /********************************************************************/
            /*                      One register operand                        */
            /********************************************************************/

        case IF_RRD:
        case IF_RWR:
        case IF_RRW:
        {
            dst = emitOutputR(dst, id);
            sz  = SMALL_IDSC_SIZE;
            break;
        }

            /********************************************************************/
            /*                 Register and register/constant                   */
            /********************************************************************/

        case IF_RRW_SHF:
        {
            code = insCodeMR(ins);
            // Emit the VEX prefix if it exists
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeMRreg(id, id->idReg1(), size, code);

            // set the W bit
            if (size != EA_1BYTE)
            {
                code |= 1;
            }

            // Emit the REX prefix if it exists
            if (TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }

            // Output a size prefix for a 16-bit operand
            if (size == EA_2BYTE && !TakesApxExtendedEvexPrefix(id))
            {
                dst += emitOutputByte(dst, 0x66);
            }

            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
            dst += emitOutputWord(dst, code);
            dst += emitOutputByte(dst, emitGetInsSC(id));
            sz = emitSizeOfInsDsc_CNS(id);

            // Update GC info.
            assert(!id->idGCref());
            emitGCregDeadUpd(id->idReg1(), dst);
            break;
        }

        case IF_RWR_RRD_SHF:
        {
            assert(IsApxExtendedEvexInstruction(ins));
            code = insCodeMR(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeMRreg(id, id->idReg2(), size, code);
            code = insEncodeReg3456(id, id->idReg1(), size, code);

            // set the W bit
            if (size != EA_1BYTE)
            {
                code |= 1;
            }

            // Emit the REX prefix if it exists
            if (TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }

            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);
            dst += emitOutputWord(dst, code);
            dst += emitOutputByte(dst, emitGetInsSC(id));
            sz = emitSizeOfInsDsc_CNS(id);

            // Update GC info.
            assert(!id->idGCref());
            emitGCregDeadUpd(id->idReg1(), dst);
            break;
        }

        case IF_RRD_RRD:
        case IF_RWR_RRD:
        case IF_RRW_RRD:
        case IF_RRW_RRW:
        {
            dst = emitOutputRR(dst, id);
            sz  = SMALL_IDSC_SIZE;
            break;
        }

        case IF_RRD_CNS:
        case IF_RWR_CNS:
        case IF_RRW_CNS:
        {
            dst = emitOutputRI(dst, id);
            sz  = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_RRD_RRD_RRD:
        case IF_RWR_RRD_RRD:
        case IF_RRW_RRD_RRD:
        case IF_RWR_RWR_RRD:
        {
            dst = emitOutputRRR(dst, id);
            sz  = sizeof(instrDesc);
            break;
        }

        case IF_RWR_RRD_RRD_CNS:
        {
            dst = emitOutputRRR(dst, id);
            dst += emitOutputByte(dst, emitGetInsSC(id));
            sz = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_RWR_RRD_RRD_RRD:
        {
            // This should only be called on AVX instructions
            assert(IsVexOrEvexEncodableInstruction(ins));

            regNumber op4Reg = id->idReg4();

            if (isMaskReg(op4Reg))
            {
                assert(IsAvx512OnlyInstruction(ins));
                assert(EncodedBySSE38orSSE3A(ins));

                dst = emitOutputRRR(dst, id);
                sz  = sizeof(instrDesc);
                break;
            }

            ssize_t cnsVal = encodeRegAsIval(op4Reg);
            cnsVal         = (cnsVal - XMMBASE) << 4;

            dst = emitOutputRRR(dst, id);
            dst += emitOutputByte(dst, cnsVal);
            sz = sizeof(instrDesc);
            break;
        }

        case IF_RRD_RRD_CNS:
        case IF_RWR_RRD_CNS:
        case IF_RRW_RRD_CNS:
        {
            assert(id->idGCref() == GCT_NONE);

            // Get the 'base' opcode (it's a big one)
            // Also, determine which operand goes where in the ModRM byte.
            regNumber mReg;
            regNumber rReg;
            if (IsApxExtendedEvexInstruction(ins))
            {
                assert(hasCodeMI(ins));
                code              = insCodeMI(ins);
                code              = AddX86PrefixIfNeeded(id, code, size);
                code              = insEncodeReg3456(id, id->idReg1(), size, code);
                mReg              = id->idReg2();
                code              = insEncodeMIreg(id, mReg, size, code);
                rReg              = REG_NA;
                ssize_t val       = emitGetInsSC(id);
                bool    valInByte = ((signed char)val == (target_ssize_t)val) && (ins != INS_mov) && (ins != INS_test);

                switch (size)
                {
                    case EA_1BYTE:
                        break;

                    case EA_2BYTE:
                        code |= EXTENDED_EVEX_PP_BITS;
                        FALLTHROUGH;

                    case EA_4BYTE:
                        code |= 1;
                        break;

#ifdef TARGET_AMD64
                    case EA_8BYTE:
                        code = AddRexWPrefix(id, code);
                        code |= 1;
                        break;
#endif // TARGET_AMD64

                    default:
                        assert(!"unexpected size");
                }

                dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

                if (valInByte && size > EA_1BYTE)
                {
                    code |= 2;
                    dst += emitOutputWord(dst, code);
                    dst += emitOutputByte(dst, val);
                }
                else
                {
                    dst += emitOutputWord(dst, code);
                    switch (size)
                    {
                        case EA_1BYTE:
                            dst += emitOutputByte(dst, val);
                            break;
                        case EA_2BYTE:
                            dst += emitOutputWord(dst, val);
                            break;
                        case EA_4BYTE:
                            dst += emitOutputLong(dst, val);
                            break;
#ifdef TARGET_AMD64
                        case EA_8BYTE:
                            dst += emitOutputLong(dst, val);
                            break;
#endif // TARGET_AMD64
                        default:
                            break;
                    }

                    if (id->idIsCnsReloc())
                    {
                        emitRecordRelocation((void*)(dst - sizeof(INT32)), (void*)(size_t)val, IMAGE_REL_BASED_HIGHLOW);
                        assert(size == EA_4BYTE);
                    }
                }

                sz = emitSizeOfInsDsc_CNS(id);

                if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
                {
                    emitGCregDeadUpd(id->idReg1(), dst);
                }

                switch (id->idInsFmt())
                {
                    case IF_RWR_RRD_CNS:
                        assert(!instrIs3opImul(ins));

                        emitGCregDeadUpd(id->idReg1(), dst);
                        break;

                    default:
#ifdef DEBUG
                        emitDispIns(id, false, false, false);
#endif
                        assert(!"unexpected GC ref instruction format");
                }

                break;
            }
            else if (hasCodeMR(ins))
            {
                code = insCodeMR(ins);
                // Emit the VEX prefix if it exists
                code = AddX86PrefixIfNeeded(id, code, size);
                if ((size == EA_2BYTE) && TakesRex2Prefix(id))
                {
                    // REX2 needs explicit pp prefix.
                    dst += emitOutputByte(dst, 0x66);
                }
                code = insEncodeMRreg(id, code);
                mReg = id->idReg1();
                rReg = id->idReg2();
            }
            else if (hasCodeMI(ins))
            {
                code = insCodeMI(ins);

                // Emit the VEX prefix if it exists
                code = AddX86PrefixIfNeeded(id, code, size);

                assert((code & 0xC000) == 0);
                code |= 0xC000;

                mReg = id->idReg2();

                // The left and right shifts use the same encoding, and are distinguished by the Reg/Opcode field.
                rReg = getSseShiftRegNumber(ins);
            }
            else
            {
                code = insCodeRM(ins);
                // Emit the VEX prefix if it exists
                code = AddX86PrefixIfNeeded(id, code, size);
                code = insEncodeRMreg(id, code);
                mReg = id->idReg2();
                rReg = id->idReg1();
            }
            assert(code & 0x00FF0000);

            if (TakesRexWPrefix(id))
            {
                code = AddRexWPrefix(id, code);
            }

            if (TakesSimdPrefix(id))
            {
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // Encode source/dest operand reg in 'vvvv' bits in 1's complement form
                    // This code will have to change when we support 3 operands.
                    // For now, we always overload this source with the destination (always reg1).
                    // (Though we will need to handle the few ops that can have the 'vvvv' bits as destination,
                    // e.g. pslldq, when/if we support those instructions with 2 registers.)
                    // (see x64 manual Table 2-9. Instructions with a VEX.vvvv destination)
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }
                else if (IsDstSrcSrcAVXInstruction(ins))
                {
                    // This is a "merge" move instruction.
                    // Encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg2(), size, code);
                }
            }

            regcode = (insEncodeReg345(id, rReg, size, &code) | insEncodeReg012(id, mReg, size, &code));

            // Output the REX prefix
            dst += emitOutputRexOrSimdPrefixIfNeeded(ins, dst, code);

            if (code & 0xFF000000)
            {
                // Output the highest word of the opcode
                dst += emitOutputWord(dst, code >> 16);
                code &= 0x0000FFFF;

                if (Is4ByteSSEInstruction(ins))
                {
                    // Output 3rd byte of the opcode
                    dst += emitOutputByte(dst, code);
                    code &= 0xFF00;
                }
            }
            else if (code & 0x00FF0000)
            {
                dst += emitOutputByte(dst, code >> 16);
                code &= 0x0000FFFF;
            }

            // TODO-XArch-CQ: Right now support 4-byte opcode instructions only
            if ((code & 0xFF00) == 0xC000)
            {
                dst += emitOutputWord(dst, code | (regcode << 8));
            }
            else if ((code & 0xFF) == 0x00)
            {
                // This case happens for some SSE/AVX instructions only
                assert(IsVexOrEvexEncodableInstruction(ins) || Is4ByteSSEInstruction(ins));

                dst += emitOutputByte(dst, (code >> 8) & 0xFF);
                dst += emitOutputByte(dst, (0xC0 | regcode));
            }
            else
            {
                dst += emitOutputWord(dst, code);
                dst += emitOutputByte(dst, (0xC0 | regcode));
            }

            dst += emitOutputByte(dst, emitGetInsSC(id));
            sz = emitSizeOfInsDsc_CNS(id);

            // Kill any GC ref in the destination register if necessary.
            if (!emitInsCanOnlyWriteSSE2OrAVXReg(id))
            {
                emitGCregDeadUpd(id->idReg1(), dst);
            }
            break;
        }

            /********************************************************************/
            /*                      Address mode operand                        */
            /********************************************************************/

        case IF_ARD:
        case IF_AWR:
        case IF_ARW:
        {
            dst = emitCodeWithInstructionSize(dst, emitOutputAM(dst, id, insCodeMR(ins)), &callInstrSize);

            switch (ins)
            {
                case INS_call:

                IND_CALL:
                    // Get hold of the argument count and method handle
                    args = emitGetInsCIargs(id);

                    // Is this a "fat" call descriptor?
                    if (id->idIsLargeCall())
                    {
                        instrDescCGCA* idCall = (instrDescCGCA*)id;

                        gcrefRegs = idCall->idcGcrefRegs;
                        byrefRegs = idCall->idcByrefRegs;
                        VarSetOps::Assign(emitComp, GCvars, idCall->idcGCvars);
                        sz = sizeof(instrDescCGCA);
                    }
                    else
                    {
                        assert(!id->idIsLargeDsp());
                        assert(!id->idIsLargeCns());

                        gcrefRegs = emitDecodeCallGCregs(id);
                        byrefRegs = 0;
                        VarSetOps::AssignNoCopy(emitComp, GCvars, VarSetOps::MakeEmpty(emitComp));
                        sz = sizeof(instrDesc);
                    }

                    goto DONE_CALL;

                default:
                {
                    if (id->idInsFmt() == IF_ARD)
                    {
                        sz = emitSizeOfInsDsc_SPEC(id);
                    }
                    else
                    {
                        sz = emitSizeOfInsDsc_AMD(id);
                    }
                    break;
                }
            }
            break;
        }

        case IF_RRD_ARD_CNS:
        case IF_RWR_ARD_CNS:
        case IF_RRW_ARD_CNS:
        {
            assert(IsSimdInstruction(ins));
            emitGetInsAmdCns(id, &cnsVal);

            if (hasCodeMI(ins))
            {
                assert(TakesEvexPrefix(id));
                assert(!EncodedBySSE38orSSE3A(ins));

                code    = insCodeMI(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, getSseShiftRegNumber(ins), size, &code);
            }
            else
            {
                code    = insCodeRM(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, id->idReg1(), size, &code);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputAM(dst, id, code, &cnsVal);
            }
            else
            {
                dst = emitOutputAM(dst, id, code | (regcode << 8), &cnsVal);
            }

            sz = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_ARD_RRD_CNS:
        case IF_AWR_RRD_CNS:
        case IF_ARW_RRD_CNS:
        {
            assert(IsSimdInstruction(ins));
            emitGetInsAmdCns(id, &cnsVal);
            dst = emitOutputAM(dst, id, insCodeMR(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_RRD_ARD:
        case IF_RWR_ARD:
        case IF_RRW_ARD:
        case IF_RRD_RRD_ARD:
        case IF_RWR_RRD_ARD:
        case IF_RRW_RRD_ARD:
        case IF_RWR_RWR_ARD:
        {
            code = insCodeRM(ins);

            if (IsApxNddCompatibleInstruction(ins) && id->idIsEvexNdContextSet())
            {
                // TODO-XArch-APX:
                // I'm not sure why instructions on this path can be with instruction
                // format other than IF_RWR_RRD_ARD, fix here for debug purpose only,
                // need revisit.
                id->idInsFmt(IF_RWR_RRD_ARD);

                code    = AddX86PrefixIfNeeded(id, code, size);
                code    = insEncodeReg3456(id, id->idReg1(), size, code);
                regcode = (insEncodeReg345(id, id->idReg2(), size, &code) << 8);
                dst     = emitOutputAM(dst, id, code | regcode);

                sz = emitSizeOfInsDsc_AMD(id);
                break;
            }

            if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputAM(dst, id, code);
            }
            else
            {
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputAM(dst, id, code | regcode);
            }

            sz = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_RRD_ARD_RRD:
        case IF_RWR_ARD_RRD:
        case IF_RRW_ARD_RRD:
        {
            assert(IsAVX2GatherInstruction(ins));
            dst = emitOutputAM(dst, id, insCodeRM(ins));
            sz  = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_RWR_RRD_ARD_CNS:
        case IF_RWR_RRD_ARD_RRD:
        {
            assert(IsSimdInstruction(ins));

            code = insCodeRM(ins);
            emitGetInsAmdCns(id, &cnsVal);

            if (insFmt == IF_RWR_RRD_ARD_RRD)
            {
                regNumber op3Reg = decodeRegFromIval(cnsVal.cnsVal);

                if (isMaskReg(op3Reg))
                {
                    assert(IsAvx512OnlyInstruction(ins));
                    assert(EncodedBySSE38orSSE3A(ins));

                    dst = emitOutputAM(dst, id, code);
                    sz  = emitSizeOfInsDsc_AMD(id);
                    break;
                }

                assert(isLowSimdReg(op3Reg));
                cnsVal.cnsVal = static_cast<int8_t>((cnsVal.cnsVal - XMMBASE) << 4);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputAM(dst, id, code, &cnsVal);
            }
            else
            {
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputAM(dst, id, code | regcode, &cnsVal);
            }

            sz = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_ARD_RRD:
        case IF_AWR_RRD:
        case IF_ARW_RRD:
        case IF_ARW_RRW:
        {
            code = insCodeMR(ins);

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputAM(dst, id, code);
            }
            else
            {
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputAM(dst, id, code | regcode);
            }

            sz = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_AWR_RRD_RRD:
        {
            code = insCodeMR(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            dst  = emitOutputAM(dst, id, code);
            sz   = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_ARD_CNS:
        case IF_AWR_CNS:
        case IF_ARW_CNS:
        {
            emitGetInsAmdCns(id, &cnsVal);
            dst = emitOutputAM(dst, id, insCodeMI(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_AMD(id);
            break;
        }

        case IF_ARW_SHF:
        {
            emitGetInsAmdCns(id, &cnsVal);
            dst = emitOutputAM(dst, id, insCodeMR(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_AMD(id);
            break;
        }

            /********************************************************************/
            /*                      Stack-based operand                         */
            /********************************************************************/

        case IF_SRD:
        case IF_SWR:
        case IF_SRW:
        {
            assert(ins != INS_pop_hide);
            if (ins == INS_pop)
            {
                // The offset in "pop [ESP+xxx]" is relative to the new ESP value

#if !FEATURE_FIXED_OUT_ARGS
                emitCurStackLvl -= sizeof(int);
#endif
                dst = emitOutputSV(dst, id, insCodeMR(ins));

#if !FEATURE_FIXED_OUT_ARGS
                emitCurStackLvl += sizeof(int);
#endif
                break;
            }

            dst = emitCodeWithInstructionSize(dst, emitOutputSV(dst, id, insCodeMR(ins)), &callInstrSize);

            if (ins == INS_call)
            {
                goto IND_CALL;
            }
            break;
        }

        case IF_SRD_CNS:
        case IF_SWR_CNS:
        case IF_SRW_CNS:
        {
            emitGetInsCns(id, &cnsVal);
            dst = emitOutputSV(dst, id, insCodeMI(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_SRW_SHF:
        {
            emitGetInsCns(id, &cnsVal);
            dst = emitOutputSV(dst, id, insCodeMR(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_SRD_RRD_CNS:
        case IF_SWR_RRD_CNS:
        case IF_SRW_RRD_CNS:
        {
            assert(IsSimdInstruction(ins) || (ins == INS_shld) || (ins == INS_shrd));
            emitGetInsAmdCns(id, &cnsVal);
            dst = emitOutputSV(dst, id, insCodeMR(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_RRD_SRD_CNS:
        case IF_RWR_SRD_CNS:
        case IF_RRW_SRD_CNS:
        {
            assert(IsSimdInstruction(ins));
            emitGetInsCns(id, &cnsVal);

            if (hasCodeMI(ins))
            {
                assert(TakesEvexPrefix(id));
                assert(!EncodedBySSE38orSSE3A(ins));

                code    = insCodeMI(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, getSseShiftRegNumber(ins), size, &code);
            }
            else
            {
                code    = insCodeRM(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, id->idReg1(), size, &code);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputSV(dst, id, code, &cnsVal);
            }
            else
            {
                // In case of AVX instructions that take 3 operands, encode reg1 as first source.
                // Note that reg1 is both a source and a destination.
                //
                // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
                // now we use the single source as source1 and source2.
                // For this format, moves do not support a third operand, so we only need to handle the binary ops.
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                dst = emitOutputSV(dst, id, code | (regcode << 8), &cnsVal);
            }

            sz = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_RRD_SRD:
        case IF_RWR_SRD:
        case IF_RRW_SRD:
        {
            code = insCodeRM(ins);

            if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputSV(dst, id, code);
            }
            else
            {
                code = AddX86PrefixIfNeeded(id, code, size);

                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputSV(dst, id, code | regcode);
            }
            sz = sizeof(instrDesc);
            break;
        }

        case IF_RRD_RRD_SRD:
        case IF_RWR_RRD_SRD:
        case IF_RRW_RRD_SRD:
        case IF_RWR_RWR_SRD:
        {
            assert(IsVexOrEvexEncodableInstruction(ins) || IsApxExtendedEvexInstruction(ins));

            if (IsApxNddEncodableInstruction(ins) && id->idIsEvexNdContextSet())
            {
                // EVEX.vvvv has different semantic for APX-EVEX NDD instructions.
                code    = insCodeRM(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                code    = insEncodeReg3456(id, id->idReg1(), size, code);
                regcode = (insEncodeReg345(id, id->idReg2(), size, &code) << 8);
                dst     = emitOutputSV(dst, id, code | regcode);
                sz      = sizeof(instrDesc);
                break;
            }

            code = insCodeRM(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeReg3456(id, id->idReg2(), size,
                                    code); // encode source operand reg in 'vvvv' bits in 1's complement form

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputSV(dst, id, code);
            }
            else
            {
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputSV(dst, id, code | regcode);
            }
            sz = sizeof(instrDesc);
            break;
        }

        case IF_RWR_RRD_SRD_CNS:
        case IF_RWR_RRD_SRD_RRD:
        {
            // This should only be called on AVX instructions
            assert(IsVexOrEvexEncodableInstruction(ins));

            code = insCodeRM(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeReg3456(id, id->idReg2(), size, code);
            emitGetInsCns(id, &cnsVal);

            if (insFmt == IF_RWR_RRD_SRD_RRD)
            {
                regNumber op3Reg = decodeRegFromIval(cnsVal.cnsVal);

                if (isMaskReg(op3Reg))
                {
                    assert(IsAvx512OnlyInstruction(ins));
                    assert(EncodedBySSE38orSSE3A(ins));

                    dst = emitOutputSV(dst, id, code);
                    sz  = emitSizeOfInsDsc_CNS(id);
                    break;
                }

                assert(isLowSimdReg(op3Reg));
                cnsVal.cnsVal = static_cast<int8_t>((cnsVal.cnsVal - XMMBASE) << 4);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputSV(dst, id, code, &cnsVal);
            }
            else
            {
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputSV(dst, id, code | regcode, &cnsVal);
            }

            sz = emitSizeOfInsDsc_CNS(id);
            break;
        }

        case IF_SRD_RRD:
        case IF_SWR_RRD:
        case IF_SRW_RRD:
        case IF_SRW_RRW:
        {
            code = insCodeMR(ins);

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputSV(dst, id, code);
            }
            else
            {
                code = AddX86PrefixIfNeeded(id, code, size);

                // In case of AVX instructions that take 3 operands, encode reg1 as first source.
                // Note that reg1 is both a source and a destination.
                //
                // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
                // now we use the single source as source1 and source2.
                // For this format, moves do not support a third operand, so we only need to handle the binary ops.
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputSV(dst, id, code | regcode);
            }

            sz = sizeof(instrDesc);
            break;
        }

        case IF_RRD_SRD_RRD:
        case IF_RWR_SRD_RRD:
        case IF_RRW_SRD_RRD:
        {
            assert(IsAVX2GatherInstruction(ins));
            unreached();
        }

        case IF_SWR_RRD_RRD:
        {
            unreached();
        }

            /********************************************************************/
            /*                    Direct memory address                         */
            /********************************************************************/

        case IF_MRD:
        case IF_MRW:
        case IF_MWR:
        {
            noway_assert(ins != INS_call);
            dst = emitOutputCV(dst, id, insCodeMR(ins) | 0x0500);
            if (id->idInsFmt() == IF_MRD)
            {
                sz = emitSizeOfInsDsc_SPEC(id);
            }
            else
            {
                sz = emitSizeOfInsDsc_DSP(id);
            }
            break;
        }

        case IF_MRD_OFF:
        {
            dst = emitOutputCV(dst, id, insCodeMI(ins));
            sz  = sizeof(instrDesc);
            break;
        }

        case IF_RRD_MRD_CNS:
        case IF_RWR_MRD_CNS:
        case IF_RRW_MRD_CNS:
        {
            assert(IsSimdInstruction(ins));
            emitGetInsDcmCns(id, &cnsVal);

            if (hasCodeMI(ins))
            {
                assert(TakesEvexPrefix(id));
                assert(!EncodedBySSE38orSSE3A(ins));

                code    = insCodeMI(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, getSseShiftRegNumber(ins), size, &code);
            }
            else
            {
                code    = insCodeRM(ins);
                code    = AddX86PrefixIfNeeded(id, code, size);
                regcode = insEncodeReg345(id, id->idReg1(), size, &code);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputCV(dst, id, code, &cnsVal);
            }
            else
            {
                // In case of AVX instructions that take 3 operands, encode reg1 as first source.
                // Note that reg1 is both a source and a destination.
                //
                // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
                // now we use the single source as source1 and source2.
                // For this format, moves do not support a third operand, so we only need to handle the binary ops.
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                dst = emitOutputCV(dst, id, code | (regcode << 8) | 0x0500, &cnsVal);
            }

            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_MRD_RRD_CNS:
        case IF_MWR_RRD_CNS:
        case IF_MRW_RRD_CNS:
        {
            assert((ins == INS_vextractf32x4) || (ins == INS_vextractf32x8) || (ins == INS_vextractf64x2) ||
                   (ins == INS_vextractf64x4) || (ins == INS_vextracti32x4) || (ins == INS_vextracti32x8) ||
                   (ins == INS_vextracti64x2) || (ins == INS_vextracti64x4));
            assert(UseSimdEncoding());
            emitGetInsDcmCns(id, &cnsVal);
            // we do not need VEX.vvvv to encode the register operand
            dst = emitOutputCV(dst, id, insCodeMR(ins), &cnsVal);
            sz  = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_RRD_MRD:
        case IF_RWR_MRD:
        case IF_RRW_MRD:
        {
            code = insCodeRM(ins);

            if (EncodedBySSE38orSSE3A(ins) || (ins == INS_crc32))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputCV(dst, id, code);
            }
            else
            {
                code = AddX86PrefixIfNeeded(id, code, size);

                // In case of AVX instructions that take 3 operands, encode reg1 as first source.
                // Note that reg1 is both a source and a destination.
                //
                // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
                // now we use the single source as source1 and source2.
                // For this format, moves do not support a third operand, so we only need to handle the binary ops.
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                regcode                   = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                CORINFO_FIELD_HANDLE fldh = id->idAddr()->iiaFieldHnd;

                if (fldh == FLD_GLOBAL_GS)
                {
                    dst = emitOutputCV(dst, id, code | regcode | 0x0400);
                }
                else
                {
                    dst = emitOutputCV(dst, id, code | regcode | 0x0500);
                }
            }

            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_RRD_RRD_MRD:
        case IF_RWR_RRD_MRD:
        case IF_RRW_RRD_MRD:
        case IF_RWR_RWR_MRD:
        {
            // This should only be called on AVX instructions
            assert(IsVexOrEvexEncodableInstruction(ins));

            code = insCodeRM(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeReg3456(id, id->idReg2(), size,
                                    code); // encode source operand reg in 'vvvv' bits in 1's complement form

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputCV(dst, id, code);
            }
            else
            {
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputCV(dst, id, code | regcode | 0x0500);
            }
            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_RWR_RRD_MRD_CNS:
        case IF_RWR_RRD_MRD_RRD:
        {
            // This should only be called on AVX instructions
            assert(IsVexOrEvexEncodableInstruction(ins));

            code = insCodeRM(ins);
            code = AddX86PrefixIfNeeded(id, code, size);
            code = insEncodeReg3456(id, id->idReg2(), size, code);
            emitGetInsCns(id, &cnsVal);

            if (insFmt == IF_RWR_RRD_MRD_RRD)
            {
                regNumber op3Reg = decodeRegFromIval(cnsVal.cnsVal);

                if (isMaskReg(op3Reg))
                {
                    assert(IsAvx512OnlyInstruction(ins));
                    assert(EncodedBySSE38orSSE3A(ins));

                    dst = emitOutputCV(dst, id, code);
                    sz  = emitSizeOfInsDsc_DSP(id);
                    break;
                }

                assert(isLowSimdReg(op3Reg));
                cnsVal.cnsVal = static_cast<int8_t>((cnsVal.cnsVal - XMMBASE) << 4);
            }

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputCV(dst, id, code, &cnsVal);
            }
            else
            {
                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputCV(dst, id, code | regcode | 0x0500, &cnsVal);
            }
            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_RWR_MRD_OFF:
        {
            code = insCode(ins);
            code = AddX86PrefixIfNeeded(id, code, size);

            // In case of AVX instructions that take 3 operands, encode reg1 as first source.
            // Note that reg1 is both a source and a destination.
            //
            // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
            // now we use the single source as source1 and source2.
            // For this format, moves do not support a third operand, so we only need to handle the binary ops.
            if (IsDstDstSrcAVXInstruction(ins))
            {
                // encode source operand reg in 'vvvv' bits in 1's complement form
                code = insEncodeReg3456(id, id->idReg1(), size, code);
            }

            regcode = insEncodeReg012(id, id->idReg1(), size, &code);
            dst     = emitOutputCV(dst, id, code | 0x30 | regcode);

            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_MRD_RRD:
        case IF_MWR_RRD:
        case IF_MRW_RRD:
        case IF_MRW_RRW:
        {
            code = insCodeMR(ins);

            if (EncodedBySSE38orSSE3A(ins))
            {
                // Special case 4-byte AVX instructions as the
                // regcode position conflicts with the opcode byte
                dst = emitOutputCV(dst, id, code);
            }
            else
            {
                code = AddX86PrefixIfNeeded(id, code, size);

                // In case of AVX instructions that take 3 operands, encode reg1 as first source.
                // Note that reg1 is both a source and a destination.
                //
                // TODO-XArch-CQ: Eventually we need to support 3 operand instruction formats. For
                // now we use the single source as source1 and source2.
                // For this format, moves do not support a third operand, so we only need to handle the binary ops.
                if (IsDstDstSrcAVXInstruction(ins))
                {
                    // encode source operand reg in 'vvvv' bits in 1's complement form
                    code = insEncodeReg3456(id, id->idReg1(), size, code);
                }

                regcode = (insEncodeReg345(id, id->idReg1(), size, &code) << 8);
                dst     = emitOutputCV(dst, id, code | regcode | 0x0500);
            }

            sz = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_MRD_CNS:
        case IF_MWR_CNS:
        case IF_MRW_CNS:
        {
            emitGetInsDcmCns(id, &cnsVal);
            dst = emitOutputCV(dst, id, insCodeMI(ins) | 0x0500, &cnsVal);
            sz  = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_MRW_SHF:
        {
            emitGetInsDcmCns(id, &cnsVal);
            dst = emitOutputCV(dst, id, insCodeMR(ins) | 0x0500, &cnsVal);
            sz  = emitSizeOfInsDsc_DSP(id);
            break;
        }

        case IF_RRD_MRD_RRD:
        case IF_RWR_MRD_RRD:
        case IF_RRW_MRD_RRD:
        {
            assert(IsAVX2GatherInstruction(ins));
            unreached();
        }

        case IF_MWR_RRD_RRD:
        {
            unreached();
        }

            /********************************************************************/
            /*                            oops                                  */
            /********************************************************************/

        default:

#ifdef DEBUG
            printf("unexpected format %s\n", emitIfName(id->idInsFmt()));
            assert(!"don't know how to encode this instruction");
#endif
            break;
    }

// Make sure we set the instruction descriptor size correctly
#ifdef TARGET_AMD64
    // If a jump is replaced by a nop, its instrDesc is temporarily modified so the nop
    // is displayed correctly in disasms. Check for this discrepancy to avoid triggering this assert.
    assert(((ins == INS_jmp) && (id->idIns() == INS_nop)) || (sz == emitSizeOfInsDsc(id)));
#else  // !TARGET_AMD64
    assert(sz == emitSizeOfInsDsc(id));
#endif // !TARGET_AMD64

#if !FEATURE_FIXED_OUT_ARGS
    bool updateStackLevel = !emitIGisInProlog(ig) && !emitIGisInEpilog(ig);

    updateStackLevel = updateStackLevel && !emitIGisInFuncletProlog(ig) && !emitIGisInFuncletEpilog(ig);

    // Make sure we keep the current stack level up to date
    if (updateStackLevel)
    {
        switch (ins)
        {
            case INS_push:
                // Please note: {INS_push_hide,IF_LABEL} is used to push the address of the
                // finally block for calling it locally for an op_leave.
                emitStackPush(dst, id->idGCref());
                break;

            case INS_pop:
                emitStackPop(dst, false, /*callInstrSize*/ 0, 1);
                break;

            case INS_sub:
                // Check for "sub ESP, icon"
                if (id->idInsFmt() == IF_RRW_CNS && id->idReg1() == REG_ESP)
                {
                    assert((size_t)emitGetInsSC(id) < 0x00000000FFFFFFFFLL);
                    emitStackPushN(dst, (unsigned)(emitGetInsSC(id) / TARGET_POINTER_SIZE));
                }
                break;

            case INS_add:
                // Check for "add ESP, icon"
                if (id->idInsFmt() == IF_RRW_CNS && id->idReg1() == REG_ESP)
                {
                    assert((size_t)emitGetInsSC(id) < 0x00000000FFFFFFFFLL);
                    emitStackPop(dst, /*isCall*/ false, /*callInstrSize*/ 0,
                                 (unsigned)(emitGetInsSC(id) / TARGET_POINTER_SIZE));
                }
                break;

            default:
                break;
        }
    }

#endif // !FEATURE_FIXED_OUT_ARGS

    assert((int)emitCurStackLvl >= 0);

    // Only epilog "instructions", some pseudo-instrs and blocks that ends with a jump to the next block

    assert(*dp != dst || emitInstHasNoCode(id));

#ifdef DEBUG
    if ((emitComp->opts.disAsm || emitComp->verbose) && (!emitJmpInstHasNoCode(id) || convertedJmpToNop))
    {
#ifdef TARGET_AMD64
        // convertedJmpToNop indicates this instruction is a removable jump that was replaced by a nop.
        // The instrDesc still describes a jump, so in order to print the nop in the disasm correctly,
        // set the instruction and format accordingly (and reset them after to avoid triggering asserts).
        if (convertedJmpToNop)
        {
            id->idIns(INS_nop);
            id->idInsFmt(IF_NONE);

            emitDispIns(id, false, dspOffs, true, emitCurCodeOffs(*dp), *dp, (dst - *dp));

            id->idIns(ins);
            id->idInsFmt(insFmt);
        }
        else
#endif // TARGET_AMD64
        {
            emitDispIns(id, false, dspOffs, true, emitCurCodeOffs(*dp), *dp, (dst - *dp));
        }
    }
#else
    if (emitComp->opts.disAsm && (!emitJmpInstHasNoCode(id) || convertedJmpToNop))
    {
#ifdef TARGET_AMD64
        if (convertedJmpToNop)
        {
            id->idIns(INS_nop);
            id->idInsFmt(IF_NONE);

            emitDispIns(id, false, 0, true, emitCurCodeOffs(*dp), *dp, (dst - *dp));

            id->idIns(ins);
            id->idInsFmt(insFmt);
        }
        else
#endif // TARGET_AMD64
        {
            emitDispIns(id, false, 0, true, emitCurCodeOffs(*dp), *dp, (dst - *dp));
        }
    }
#endif

#if FEATURE_LOOP_ALIGN
    // Only compensate over-estimated instructions if emitCurIG is before
    // the last IG that needs alignment.
    if (emitCurIG->igNum <= emitLastAlignedIgNum)
    {
        int diff = id->idCodeSize() - ((UNATIVE_OFFSET)(dst - *dp));
        assert(diff >= 0);
        if (diff != 0)
        {

#ifdef DEBUG
            // should never over-estimate align instruction
            assert(id->idIns() != INS_align);
            JITDUMP("Added over-estimation compensation: %d\n", diff);

            if (emitComp->opts.disAsm)
            {
                emitDispInsAddr(dst);
                printf("\t\t  ;; NOP compensation instructions of %d bytes.\n", diff);
            }
#endif

            dst = emitOutputNOP(dst, diff);
        }
        assert((id->idCodeSize() - ((UNATIVE_OFFSET)(dst - *dp))) == 0);
    }
#endif

#ifdef DEBUG
    if (emitComp->compDebugBreak)
    {
        // set JitEmitPrintRefRegs=1 will print out emitThisGCrefRegs and emitThisByrefRegs
        // at the beginning of this method.
        if (JitConfig.JitEmitPrintRefRegs() != 0)
        {
            printf("Before emitOutputInstr for id->idDebugOnlyInfo()->idNum=0x%02x\n", id->idDebugOnlyInfo()->idNum);
            printf("  emitThisGCrefRegs(0x%p)=", emitComp->dspPtr(&emitThisGCrefRegs));
            printRegMaskInt(emitThisGCrefRegs);
            emitDispRegSet(emitThisGCrefRegs);
            printf("\n");
            printf("  emitThisByrefRegs(0x%p)=", emitComp->dspPtr(&emitThisByrefRegs));
            printRegMaskInt(emitThisByrefRegs);
            emitDispRegSet(emitThisByrefRegs);
            printf("\n");
        }

        // For example, set JitBreakEmitOutputInstr=a6 will break when this method is called for
        // emitting instruction a6, (i.e. IN00a6 in jitdump).
        if ((unsigned)JitConfig.JitBreakEmitOutputInstr() == id->idDebugOnlyInfo()->idNum)
        {
            assert(!"JitBreakEmitOutputInstr reached");
        }
    }
#endif

    *dp = dst;

#ifdef DEBUG
    if (ins == INS_mulEAX || ins == INS_imulEAX)
    {
        // INS_mulEAX has implicit target of Edx:Eax. Make sure
        // that we detected this cleared its GC-status.

        assert(((RBM_EAX | RBM_EDX) & (emitThisGCrefRegs | emitThisByrefRegs)) == 0);
    }

    if (instrIs3opImul(ins))
    {
        // The target of the 3-operand imul is implicitly encoded. Make sure
        // that we detected the implicit register and cleared its GC-status.

        regMaskTP regMask = genRegMask(inst3opImulReg(ins));
        assert((regMask & (emitThisGCrefRegs | emitThisByrefRegs)) == 0);
    }

    // Output any delta in GC info.
    if (EMIT_GC_VERBOSE || emitComp->opts.disasmWithGC)
    {
        emitDispGCInfoDelta();
    }
#endif

    return sz;
}

emitter::insFormat emitter::getMemoryOperation(instrDesc* id) const
{
    instruction ins    = id->idIns();
    insFormat   insFmt = id->idInsFmt();

    if (ins == INS_lea)
    {
        // an INS_lea instruction doesn't actually read memory
        return IF_NONE;
    }

    return ExtractMemoryFormat(insFmt);
}

emitter::insFormat emitter::ExtractMemoryFormat(insFormat insFmt) const
{
    IS_INFO isInfo = emitGetSchedInfo(insFmt);

    IS_INFO mask = static_cast<IS_INFO>(isInfo & (IS_GM_RD | IS_GM_RW | IS_GM_WR));
    if (mask != 0)
    {
        static_assert_no_msg(0 == (IS_GM_RD >> 13));
        static_assert_no_msg(1 == (IS_GM_WR >> 13));
        static_assert_no_msg(2 == (IS_GM_RW >> 13));

        insFormat result = static_cast<insFormat>(IF_MRD + (mask >> 13));
        assert((result == IF_MRD) || (result == IF_MWR) || (result == IF_MRW));
        return result;
    }

    mask = static_cast<IS_INFO>(isInfo & (IS_SF_RD | IS_SF_RW | IS_SF_WR));
    if (mask != 0)
    {
        static_assert_no_msg(0 == (IS_SF_RD >> 16));
        static_assert_no_msg(1 == (IS_SF_WR >> 16));
        static_assert_no_msg(2 == (IS_SF_RW >> 16));

        insFormat result = static_cast<insFormat>(IF_SRD + (mask >> 16));
        assert((result == IF_SRD) || (result == IF_SWR) || (result == IF_SRW));
        return result;
    }

    mask = static_cast<IS_INFO>(isInfo & (IS_AM_RD | IS_AM_RW | IS_AM_WR));
    if (mask != 0)
    {
        static_assert_no_msg(0 == (IS_AM_RD >> 19));
        static_assert_no_msg(1 == (IS_AM_WR >> 19));
        static_assert_no_msg(2 == (IS_AM_RW >> 19));

        insFormat result = static_cast<insFormat>(IF_ARD + (mask >> 19));
        assert((result == IF_ARD) || (result == IF_AWR) || (result == IF_ARW));
        return result;
    }

    return IF_NONE;
}

#ifdef TARGET_AMD64
// true if this 'imm' can be encoded as a input operand to a ccmp instruction
/*static*/ bool emitter::emitIns_valid_imm_for_ccmp(INT64 imm)
{
    return (((INT32)imm) == imm);
}
#endif

#if defined(DEBUG) || defined(LATE_DISASM)

// clang-format off
const static float insLatencyInfos[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) PERFSCORE_LATENCY_##lat,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};

const static float insThroughputInfos[] =
{
    #define INST0(id, nm, um, mr,                 lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #define INST1(id, nm, um, mr,                 lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #define INST2(id, nm, um, mr, mi,             lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #define INST3(id, nm, um, mr, mi, rm,         lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #define INST4(id, nm, um, mr, mi, rm, a4,     lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #define INST5(id, nm, um, mr, mi, rm, a4, rr, lat, tp, tt, flags) PERFSCORE_THROUGHPUT_##tp,
    #include "instrs.h"
    #undef  INST0
    #undef  INST1
    #undef  INST2
    #undef  INST3
    #undef  INST4
    #undef  INST5
};
// clang-format on

//----------------------------------------------------------------------------------------
// getInsExecutionCharacteristics:
//    Returns the current instruction execution characteristics
//
// Arguments:
//    id  - The current instruction descriptor to be evaluated
//
// Return Value:
//    A struct containing the current instruction execution characteristics
//
// Notes:
//    The instruction latencies and throughput values returned by this function
//    are for the Intel Skylake-X processor and are from either:
//      1.  Agner.org - https://www.agner.org/optimize/instruction_tables.pdf
//      2.  uops.info - https://uops.info/table.html
//
emitter::insExecutionCharacteristics emitter::getInsExecutionCharacteristics(instrDesc* id)
{
    insExecutionCharacteristics result;
    instruction                 ins    = id->idIns();
    insFormat                   insFmt = id->idInsFmt();
    emitAttr                    opSize = id->idOpSize();
    insFormat                   memFmt = getMemoryOperation(id);
    unsigned                    memAccessKind;

    result.insThroughput = PERFSCORE_THROUGHPUT_ILLEGAL;
    result.insLatency    = PERFSCORE_LATENCY_ILLEGAL;

    // Model the memory latency
    switch (memFmt)
    {
        // Model a read from stack location, possible def to use latency from L0 cache
        case IF_SRD:
            result.insLatency = PERFSCORE_LATENCY_RD_STACK;
            memAccessKind     = PERFSCORE_MEMORY_READ;
            break;

        case IF_SWR:
            result.insLatency = PERFSCORE_LATENCY_WR_STACK;
            memAccessKind     = PERFSCORE_MEMORY_WRITE;
            break;

        case IF_SRW:
            result.insLatency = PERFSCORE_LATENCY_RD_WR_STACK;
            memAccessKind     = PERFSCORE_MEMORY_READ_WRITE;
            break;

        // Model a read from a constant location, possible def to use latency from L0 cache
        case IF_MRD:
            result.insLatency = PERFSCORE_LATENCY_RD_CONST_ADDR;
            memAccessKind     = PERFSCORE_MEMORY_READ;
            break;

        case IF_MWR:
            result.insLatency = PERFSCORE_LATENCY_WR_CONST_ADDR;
            memAccessKind     = PERFSCORE_MEMORY_WRITE;
            break;

        case IF_MRW:
            result.insLatency = PERFSCORE_LATENCY_RD_WR_CONST_ADDR;
            memAccessKind     = PERFSCORE_MEMORY_READ_WRITE;
            break;

        // Model a read from memory location, possible def to use latency from L0 or L1 cache
        case IF_ARD:
            result.insLatency = PERFSCORE_LATENCY_RD_GENERAL;
            memAccessKind     = PERFSCORE_MEMORY_READ;
            break;

        case IF_AWR:
            result.insLatency = PERFSCORE_LATENCY_WR_GENERAL;
            memAccessKind     = PERFSCORE_MEMORY_WRITE;
            break;

        case IF_ARW:
            result.insLatency = PERFSCORE_LATENCY_RD_WR_GENERAL;
            memAccessKind     = PERFSCORE_MEMORY_READ_WRITE;
            break;

        case IF_NONE:
            result.insLatency = PERFSCORE_LATENCY_ZERO;
            memAccessKind     = PERFSCORE_MEMORY_NONE;
            break;

        default:
            assert(!"Unhandled insFmt for switch (memFmt)");
            result.insLatency = PERFSCORE_LATENCY_ZERO;
            memAccessKind     = PERFSCORE_MEMORY_NONE;
            break;
    }
    result.insMemoryAccessKind = memAccessKind;

    switch (ins)
    {
        case INS_align:
        {
            assert(memFmt == IF_NONE);

#if FEATURE_LOOP_ALIGN
            if ((id->idCodeSize() == 0) || ((instrDescAlign*)id)->isPlacedAfterJmp)
            {
                // Either we're not going to generate 'align' instruction, or the 'align'
                // instruction is placed immediately after unconditional jmp.
                // In both cases, don't count for PerfScore.

                result.insThroughput = PERFSCORE_THROUGHPUT_ZERO;
                result.insLatency    = PERFSCORE_LATENCY_ZERO;
                break;
            }
#endif

            result.insThroughput = PERFSCORE_THROUGHPUT_4X;
            result.insLatency    = PERFSCORE_LATENCY_ZERO;
            break;
        }

        case INS_push:
        case INS_push_hide:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (insFmt == IF_RRD) // push  reg
            {
                // For pushes (stack writes) we assume that the full latency will be covered
                result.insLatency = PERFSCORE_LATENCY_ZERO;
            }
            break;
        }

        case INS_push2:
        {
            // TODO-XArch-APX: to be verified.
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (insFmt == IF_RRD_RRD) // push2  reg1, reg2
            {
                result.insLatency = PERFSCORE_LATENCY_ZERO;
            }
            break;
        }

        case INS_pop:
        case INS_pop_hide:
        {
            if (insFmt == IF_RWR) // pop   reg
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                // For pops (stack reads) we assume that the full latency will be covered
                result.insLatency = PERFSCORE_LATENCY_ZERO;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_pop2:
        {
            // TODO-XArch-APX: to be verified.
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (insFmt == IF_RRD_RRD) // pop2  reg1, reg2
            {
                result.insLatency = PERFSCORE_LATENCY_ZERO;
            }
            break;
        }

        case INS_inc:
        case INS_dec:
        case INS_neg:
        case INS_not:
        {
            if (memFmt == IF_NONE)
            {
                // ins   reg
                result.insThroughput = PERFSCORE_THROUGHPUT_4X;
                result.insLatency    = PERFSCORE_LATENCY_1C;
            }
            else
            {
                // ins   mem
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                // no additional R/W latency
            }
            break;
        }

#ifdef TARGET_AMD64
        case INS_movsxd:
#endif
        case INS_mov:
        case INS_movsx:
        case INS_movzx:
        case INS_cwde:
        case INS_cmp:
        case INS_test:
        case INS_cmovo:
        case INS_cmovno:
        case INS_cmovb:
        case INS_cmovae:
        case INS_cmove:
        case INS_cmovne:
        case INS_cmovbe:
        case INS_cmova:
        case INS_cmovs:
        case INS_cmovns:
        case INS_cmovp:
        case INS_cmovnp:
        case INS_cmovl:
        case INS_cmovge:
        case INS_cmovle:
        case INS_cmovg:
#ifdef TARGET_AMD64
        // todo-xarch-apx: we need to double check the logic for ccmp
        case INS_ccmpo:
        case INS_ccmpno:
        case INS_ccmpb:
        case INS_ccmpae:
        case INS_ccmpe:
        case INS_ccmpne:
        case INS_ccmpbe:
        case INS_ccmpa:
        case INS_ccmps:
        case INS_ccmpns:
        case INS_ccmpt:
        case INS_ccmpf:
        case INS_ccmpl:
        case INS_ccmpge:
        case INS_ccmple:
        case INS_ccmpg:
#endif
        {

            if (memFmt == IF_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_4X;
            }
            else if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                if (ins == INS_cmp || ins == INS_test || insIsCMOV(ins))
                {
                    result.insLatency += PERFSCORE_LATENCY_1C;
                }
                else if (ins == INS_movsx
#ifdef TARGET_AMD64
                         || ins == INS_movsxd
#endif
                )
                {
                    result.insLatency += PERFSCORE_LATENCY_2C;
                }
            }
            else // writes
            {
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                assert(ins == INS_mov);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_adc:
        case INS_sbb:
        {
            if (memAccessKind != PERFSCORE_MEMORY_READ_WRITE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += PERFSCORE_LATENCY_1C;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                // no additional R/W latency
            }
            break;
        }

        case INS_add:
        case INS_sub:
        case INS_sub_hide:
        case INS_and:
        case INS_or:
        case INS_xor:
        {
            if (memFmt == IF_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_4X;
                result.insLatency    = PERFSCORE_LATENCY_1C;
            }
            else if (memAccessKind == PERFSCORE_MEMORY_READ_WRITE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                // no additional R/W latency
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += PERFSCORE_LATENCY_1C;
            }
            break;
        }

        case INS_lea:
        {
            // uops.info
            result.insThroughput = PERFSCORE_THROUGHPUT_2X; // one or two components
            result.insLatency    = PERFSCORE_LATENCY_1C;

            if (insFmt == IF_RWR_LABEL)
            {
                // RIP relative addressing
                //
                // - throughput is only 1 per cycle
                //
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            else if (insFmt != IF_RWR_SRD)
            {
                if (id->idAddr()->iiaAddrMode.amIndxReg != REG_NA)
                {
                    regNumber baseReg = id->idAddr()->iiaAddrMode.amBaseReg;
                    if (baseReg != REG_NA)
                    {
                        ssize_t dsp = emitGetInsAmdAny(id);

                        if ((dsp != 0) || baseRegisterRequiresDisplacement(baseReg))
                        {
                            // three components
                            //
                            // - throughput is only 1 per cycle
                            //
                            result.insThroughput = PERFSCORE_THROUGHPUT_1C;

                            if (baseRegisterRequiresDisplacement(baseReg) || id->idIsDspReloc())
                            {
                                // Increased Latency for these cases
                                //  - see https://reviews.llvm.org/D32277
                                //
                                result.insLatency = PERFSCORE_LATENCY_3C;
                            }
                        }
                    }
                }
            }
            break;
        }

        case INS_div:
        {
            // The integer divide instructions have long latencies
            if (opSize == EA_8BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_52C;
                result.insLatency    = PERFSCORE_LATENCY_62C;
            }
            else
            {
                assert(opSize == EA_4BYTE);
                result.insThroughput = PERFSCORE_THROUGHPUT_6C;
                result.insLatency    = PERFSCORE_LATENCY_26C;
            }
            break;
        }

        case INS_idiv:
        {
            // The integer divide instructions have long latenies
            if (opSize == EA_8BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_57C;
                result.insLatency    = PERFSCORE_LATENCY_69C;
            }
            else
            {
                assert(opSize == EA_4BYTE);
                result.insThroughput = PERFSCORE_THROUGHPUT_6C;
                result.insLatency    = PERFSCORE_LATENCY_26C;
            }
            break;
        }

        case INS_shl:
        case INS_shr:
        case INS_sar:
        case INS_ror:
        case INS_rol:
        {
            switch (insFmt)
            {
                case IF_RRW_CNS:
                    // ins   reg, cns
                    result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                    result.insLatency    = PERFSCORE_LATENCY_1C;
                    break;

                case IF_MRW_CNS:
                case IF_SRW_CNS:
                case IF_ARW_CNS:
                    // ins   [mem], cns
                    result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                    result.insLatency += PERFSCORE_LATENCY_1C;
                    break;

                case IF_RRW:
                // TODO-XArch-APX: to be verified if this data is correct for NDD form.
                case IF_RWR_RRD:
                    // ins   reg, cl
                    result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                    result.insLatency    = PERFSCORE_LATENCY_2C;
                    break;

                case IF_MRW:
                case IF_SRW:
                case IF_ARW:
                    // ins   [mem], cl
                    result.insThroughput = PERFSCORE_THROUGHPUT_4C;
                    result.insLatency += PERFSCORE_LATENCY_2C;
                    break;

                default:
                    // unhandled instruction insFmt combination
                    perfScoreUnhandledInstruction(id, &result);
                    break;
            }
            break;
        }

        case INS_shl_1:
        case INS_shr_1:
        case INS_sar_1:
        {
            result.insLatency += PERFSCORE_LATENCY_1C;
            switch (insFmt)
            {
                case IF_RRW:
                // TODO-XArch-APX: to be verified if this data is correct for NDD form.
                case IF_RWR_RRD:
                    // ins   reg, 1
                    result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                    break;

                case IF_MRW:
                case IF_SRW:
                case IF_ARW:
                    // ins   [mem], 1
                    result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                    break;

                default:
                    // unhandled instruction insFmt combination
                    perfScoreUnhandledInstruction(id, &result);
                    break;
            }
            break;
        }

        case INS_shl_N:
        case INS_shr_N:
        case INS_sar_N:
        case INS_ror_N:
        case INS_rol_N:
        {
            result.insLatency += PERFSCORE_LATENCY_1C;
            switch (insFmt)
            {
                case IF_RRW_SHF:
                case IF_RWR_RRD_SHF:
                    // ins   reg, cns
                    result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                    break;

                case IF_MRW_SHF:
                case IF_SRW_SHF:
                case IF_ARW_SHF:
                    // ins   [mem], cns
                    result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                    break;

                default:
                    // unhandled instruction insFmt combination
                    perfScoreUnhandledInstruction(id, &result);
                    break;
            }
            break;
        }

        case INS_shld:
        case INS_shrd:
        {
            result.insLatency += PERFSCORE_LATENCY_3C;
            if (insFmt == IF_RRW_RRD_CNS)
            {
                // ins   reg, reg, cns
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            else
            {
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE); // _SHF form never emitted
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
            }
            break;
        }

        case INS_bt:
        {
            result.insLatency += PERFSCORE_LATENCY_1C;
            if ((insFmt == IF_RRD_RRD) || (insFmt == IF_RRD_CNS))
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_seto:
        case INS_setno:
        case INS_setb:
        case INS_setae:
        case INS_sete:
        case INS_setne:
        case INS_setbe:
        case INS_seta:
        case INS_sets:
        case INS_setns:
        case INS_setp:
        case INS_setnp:
        case INS_setl:
        case INS_setge:
        case INS_setle:
        case INS_setg:
#ifdef TARGET_AMD64
        case INS_seto_apx:
        case INS_setno_apx:
        case INS_setb_apx:
        case INS_setae_apx:
        case INS_sete_apx:
        case INS_setne_apx:
        case INS_setbe_apx:
        case INS_seta_apx:
        case INS_sets_apx:
        case INS_setns_apx:
        case INS_setp_apx:
        case INS_setnp_apx:
        case INS_setl_apx:
        case INS_setge_apx:
        case INS_setle_apx:
        case INS_setg_apx:
#endif
        {
            result.insLatency += PERFSCORE_LATENCY_1C;
            if (insFmt == IF_RRD)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_jmp:
        {
            if (emitInstHasNoCode(id))
            {
                // a removed jmp to the next instruction
                result.insThroughput = PERFSCORE_THROUGHPUT_ZERO;
                result.insLatency    = PERFSCORE_LATENCY_ZERO;
            }
            else
            {
                // branch to a constant address
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                result.insLatency    = PERFSCORE_LATENCY_BRANCH_DIRECT;
            }
            break;
        }

        case INS_call:
        {
            // uops.info
            result.insLatency = PERFSCORE_LATENCY_ZERO;
            switch (insFmt)
            {
                case IF_LABEL:
                    result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                    break;

                case IF_METHOD:
                    result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                    break;

                case IF_METHPTR:
                    result.insThroughput = PERFSCORE_THROUGHPUT_3C;
                    break;

                case IF_SRD:
                case IF_ARD:
                case IF_MRD:
                    result.insThroughput = PERFSCORE_THROUGHPUT_3C;
                    break;

                default:
                    // unhandled instruction, insFmt combination
                    perfScoreUnhandledInstruction(id, &result);
                    break;
            }
            break;
        }

        case INS_ret:
        {
            if (insFmt == IF_CNS)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
            }
            else
            {
                assert(insFmt == IF_NONE);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_xchg:
        {
            // uops.info
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (memFmt == IF_NONE)
            {
                result.insLatency = PERFSCORE_LATENCY_1C;
            }
            else
            {
                result.insLatency = PERFSCORE_LATENCY_23C;
            }
            break;
        }

#ifdef TARGET_X86
        case INS_fld:
        case INS_fstp:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                result.insLatency = PERFSCORE_LATENCY_1C;
            }
            break;
        }
#endif // TARGET_X86

        case INS_movd32:
        case INS_movd64:
        case INS_movq:
        {
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                if (isFloatReg(id->idReg1()) && isFloatReg(id->idReg2()))
                {
                    // movq   xmm, xmm
                    result.insThroughput = PERFSCORE_THROUGHPUT_3X;
                    result.insLatency    = PERFSCORE_LATENCY_1C;
                }
                else
                {
                    // movd   r32/64, xmm   or  xmm, r32/64
                    result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                    result.insLatency    = PERFSCORE_LATENCY_3C;
                }
            }
            else if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                // ins   xmm, m32/64
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += PERFSCORE_LATENCY_2C;
            }
            else
            {
                // ins   m32/64, xmm
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_2C;
            }
            break;
        }

        case INS_movdqa32:
        case INS_vmovdqa64:
        case INS_movdqu32:
        case INS_vmovdqu8:
        case INS_vmovdqu16:
        case INS_vmovdqu64:
        case INS_vmovd_simd:
        case INS_vmovw_simd:
        case INS_movaps:
        case INS_movups:
        case INS_movapd:
        case INS_movupd:
        {
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                // ins   reg, reg
                result.insThroughput = PERFSCORE_THROUGHPUT_4X;
                result.insLatency    = PERFSCORE_LATENCY_ZERO;
            }
            else if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                // ins   reg, mem
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_3C : PERFSCORE_LATENCY_2C;
            }
            else
            {
                // ins   mem, reg
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_2C;
            }
            break;
        }

        case INS_movhps:
        case INS_movhpd:
        case INS_movlps:
        case INS_movlpd:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                result.insLatency += PERFSCORE_LATENCY_3C;
            }
            else
            {
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                result.insLatency += PERFSCORE_LATENCY_2C;
            }
            break;
        }

        case INS_movntdqa:
        {
            assert(memAccessKind == PERFSCORE_MEMORY_READ);
            result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_3C : PERFSCORE_LATENCY_2C;
            break;
        }

        case INS_movss:
        case INS_movsd_simd:
        case INS_movddup:
        {
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency    = PERFSCORE_LATENCY_1C;
            }
            else if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_3C : PERFSCORE_LATENCY_2C;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_2C;
            }
            break;
        }

        case INS_lddqu:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_3C : PERFSCORE_LATENCY_2C;
            break;
        }

        case INS_vpmovdb:
        case INS_vpmovdw:
        case INS_vpmovqb:
        case INS_vpmovqd:
        case INS_vpmovqw:
        case INS_vpmovsdb:
        case INS_vpmovsdw:
        case INS_vpmovsqb:
        case INS_vpmovsqd:
        case INS_vpmovsqw:
        case INS_vpmovswb:
        case INS_vpmovusdb:
        case INS_vpmovusdw:
        case INS_vpmovusqb:
        case INS_vpmovusqd:
        case INS_vpmovusqw:
        case INS_vpmovuswb:
        case INS_vpmovwb:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_2C;
            result.insLatency += (opSize == EA_16BYTE) ? PERFSCORE_LATENCY_2C : PERFSCORE_LATENCY_4C;
            break;
        }

        case INS_vrcp14pd:
        case INS_vrcp14ps:
        case INS_vrcp14sd:
        case INS_vrcp14ss:
        case INS_vrsqrt14pd:
        case INS_vrsqrt14sd:
        case INS_vrsqrt14ps:
        case INS_vrsqrt14ss:
        {
            if (opSize == EA_64BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                result.insLatency += PERFSCORE_LATENCY_8C;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_4C;
            }
            break;
        }

        case INS_vpconflictd:
        {
            if (opSize == EA_16BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_6C;
                result.insLatency += PERFSCORE_LATENCY_12C;
            }
            else if (opSize == EA_32BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_10C;
                result.insLatency += PERFSCORE_LATENCY_16C;
            }
            else
            {
                assert(opSize == EA_64BYTE);

                result.insThroughput = PERFSCORE_THROUGHPUT_19C;
                result.insLatency += PERFSCORE_LATENCY_26C;
            }
            break;
        }

        case INS_vpconflictq:
        {
            if (opSize == EA_16BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                result.insLatency += PERFSCORE_LATENCY_4C;
            }
            else if (opSize == EA_32BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_6C;
                result.insLatency += PERFSCORE_LATENCY_12C;
            }
            else
            {
                assert(opSize == EA_64BYTE);

                result.insThroughput = PERFSCORE_THROUGHPUT_10C;
                result.insLatency += PERFSCORE_LATENCY_16C;
            }
            break;
        }

        case INS_cvttss2si32:
        case INS_cvttss2si64:
        case INS_cvtss2si32:
        case INS_cvtss2si64:
        case INS_vcvtss2usi32:
        case INS_vcvtss2usi64:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            result.insLatency += opSize == EA_8BYTE ? PERFSCORE_LATENCY_8C : PERFSCORE_LATENCY_7C;
            break;
        }

        case INS_paddb:
        case INS_psubb:
        case INS_paddw:
        case INS_psubw:
        case INS_paddd:
        case INS_psubd:
        case INS_paddq:
        case INS_psubq:
        case INS_paddsb:
        case INS_psubsb:
        case INS_paddsw:
        case INS_psubsw:
        case INS_paddusb:
        case INS_psubusb:
        case INS_paddusw:
        case INS_psubusw:
        case INS_pandd:
        case INS_vpandq:
        case INS_pandnd:
        case INS_vpandnq:
        case INS_pord:
        case INS_vporq:
        case INS_pxord:
        case INS_vpxorq:
        case INS_andpd:
        case INS_andps:
        case INS_andnpd:
        case INS_andnps:
        case INS_orpd:
        case INS_orps:
        case INS_xorpd:
        case INS_xorps:
        case INS_blendps:
        case INS_blendpd:
        case INS_vpblendd:
        {
            result.insLatency += PERFSCORE_LATENCY_1C;
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_3X;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            break;
        }

        case INS_pslld:
        case INS_psllw:
        case INS_psllq:
        case INS_psrlw:
        case INS_psrld:
        case INS_psrlq:
        case INS_psrad:
        case INS_psraw:
        case INS_vpsraq:
        {
            if (insFmt == IF_RWR_CNS)
            {
                result.insLatency    = PERFSCORE_LATENCY_1C;
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            else
            {
                result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_4C : PERFSCORE_LATENCY_2C;
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            }
            break;
        }

        case INS_vblendmps:
        case INS_vblendmpd:
        case INS_vpblendmd:
        case INS_vpblendmq:
        {
            if (opSize == EA_64BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_3X;
            }
            result.insLatency += PERFSCORE_LATENCY_1C;
            break;
        }

        case INS_vpblendmb:
        case INS_vpblendmw:
        {
            if (opSize == EA_64BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_3X;
            }
            result.insLatency += PERFSCORE_LATENCY_3C;
            break;
        }

        case INS_bswap:
        {
            if (opSize == EA_8BYTE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency    = PERFSCORE_LATENCY_2C;
            }
            else
            {
                assert(opSize == EA_4BYTE);
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency    = PERFSCORE_LATENCY_1C;
            }
            break;
        }

        case INS_pmovmskb:
        case INS_movmskpd:
        case INS_movmskps:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            if (opSize == EA_32BYTE)
            {
                result.insLatency += ins == INS_pmovmskb ? PERFSCORE_LATENCY_4C : PERFSCORE_LATENCY_5C;
            }
            else
            {
                result.insLatency += PERFSCORE_LATENCY_3C;
            }
            break;
        }

        case INS_pmovsxbw:
        case INS_pmovsxbd:
        case INS_pmovsxbq:
        case INS_pmovsxwd:
        case INS_pmovsxwq:
        case INS_pmovsxdq:
        case INS_pmovzxbw:
        case INS_pmovzxbd:
        case INS_pmovzxbq:
        case INS_pmovzxwd:
        case INS_pmovzxwq:
        case INS_pmovzxdq:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_3C : PERFSCORE_LATENCY_1C;
            break;
        }

        case INS_ptest:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_6C : PERFSCORE_LATENCY_4C;
            break;
        }

        case INS_cvtsd2ss:
        case INS_cvtps2pd:
        case INS_cvtpd2dq:
        case INS_cvtdq2pd:
        case INS_cvtpd2ps:
        case INS_cvttpd2dq:
        case INS_vcvtpd2udq:
        case INS_vcvtps2qq:
        case INS_vcvtps2uqq:
        case INS_vcvtqq2ps:
        case INS_vcvttpd2udq:
        case INS_vcvttps2qq:
        case INS_vcvttps2uqq:
        case INS_vcvtudq2pd:
        case INS_vcvtuqq2ps:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_7C : PERFSCORE_LATENCY_5C;
            break;
        }

        case INS_vtestps:
        case INS_vtestpd:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_1C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_5C : PERFSCORE_LATENCY_3C;
            break;
        }

        case INS_vpbroadcastb:
        case INS_vpbroadcastb_gpr:
        case INS_vpbroadcastw:
        case INS_vpbroadcastw_gpr:
        case INS_vpbroadcastd:
        case INS_vpbroadcastd_gpr:
        case INS_vpbroadcastq:
        case INS_vpbroadcastq_gpr:
        case INS_vbroadcasti32x4:
        case INS_vbroadcastf32x4:
        case INS_vbroadcastf64x2:
        case INS_vbroadcasti64x2:
        case INS_vbroadcastf64x4:
        case INS_vbroadcasti64x4:
        case INS_vbroadcastf32x2:
        case INS_vbroadcasti32x2:
        case INS_vbroadcastf32x8:
        case INS_vbroadcasti32x8:
        case INS_vbroadcastss:
        case INS_vbroadcastsd:
        {
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency    = opSize == EA_16BYTE ? PERFSCORE_LATENCY_1C : PERFSCORE_LATENCY_3C;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += opSize == EA_16BYTE ? PERFSCORE_LATENCY_2C : PERFSCORE_LATENCY_3C;
                if (ins == INS_vpbroadcastb || ins == INS_vpbroadcastw)
                {
                    result.insLatency += PERFSCORE_LATENCY_1C;
                }
            }
            break;
        }

        case INS_pinsrb:
        case INS_pinsrw:
        case INS_pinsrd:
        case INS_pinsrq:
        {
            if (memAccessKind == PERFSCORE_MEMORY_NONE)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2C;
                result.insLatency    = PERFSCORE_LATENCY_4C;
            }
            else
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_3C;
            }
            break;
        }

        case INS_vmaskmovpd:
        case INS_vmaskmovps:
        case INS_vpmaskmovd:
        case INS_vpmaskmovq:
        {
            if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_4C : PERFSCORE_LATENCY_3C;
            }
            else
            {
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += PERFSCORE_LATENCY_12C;
            }
            break;
        }

        case INS_vpgatherdd:
        case INS_vgatherdps:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_4C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_13C : PERFSCORE_LATENCY_11C;
            break;
        }

        case INS_vpgatherdq:
        case INS_vpgatherqd:
        case INS_vpgatherqq:
        case INS_vgatherdpd:
        case INS_vgatherqps:
        case INS_vgatherqpd:
        {
            result.insThroughput = PERFSCORE_THROUGHPUT_4C;
            result.insLatency += opSize == EA_32BYTE ? PERFSCORE_LATENCY_11C : PERFSCORE_LATENCY_9C;
            break;
        }

        case INS_movbe:
#ifdef TARGET_AMD64
        case INS_movbe_apx:
#endif
        {
            if (memAccessKind == PERFSCORE_MEMORY_READ)
            {
                result.insThroughput = PERFSCORE_THROUGHPUT_2X;
                result.insLatency += opSize == EA_8BYTE ? PERFSCORE_LATENCY_2C : PERFSCORE_LATENCY_1C;
            }
            else
            {
                assert(memAccessKind == PERFSCORE_MEMORY_WRITE);
                result.insThroughput = PERFSCORE_THROUGHPUT_1C;
                result.insLatency += opSize == EA_8BYTE ? PERFSCORE_LATENCY_2C : PERFSCORE_LATENCY_1C;
            }
            break;
        }

        default:
        {
            assert((unsigned)ins < ArrLen(insThroughputInfos));
            float insThroughput = insThroughputInfos[ins];

            assert((unsigned)ins < ArrLen(insLatencyInfos));
            float insLatency = insLatencyInfos[ins];

            if ((insLatency == PERFSCORE_LATENCY_ILLEGAL) || (insThroughput == PERFSCORE_THROUGHPUT_ILLEGAL))
            {
                // unhandled instruction insFmt combination
                perfScoreUnhandledInstruction(id, &result);
            }

            result.insLatency += insLatency;
            result.insThroughput = insThroughput;
            break;
        }
    }

    return result;
}

#endif // defined(DEBUG) || defined(LATE_DISASM)

/*****************************************************************************/
/*****************************************************************************/

#endif // defined(TARGET_XARCH)
