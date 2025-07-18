// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
/*****************************************************************************/

#ifndef _EMITINL_H_
#define _EMITINL_H_

#ifdef TARGET_XARCH

/* static */
inline bool emitter::instrIs3opImul(instruction ins)
{
#ifdef TARGET_X86
    return ((ins >= INS_imul_AX) && (ins <= INS_imul_DI));
#else // TARGET_AMD64
    return ((ins >= INS_imul_AX) && (ins <= INS_imul_31));
#endif
}

/* static */
inline bool emitter::instrIsExtendedReg3opImul(instruction ins)
{
#ifdef TARGET_X86
    return false;
#else // TARGET_AMD64
    return ((ins >= INS_imul_08) && (ins <= INS_imul_31));
#endif
}

/* static */
inline bool emitter::instrHasImplicitRegPairDest(instruction ins)
{
    return (ins == INS_mulEAX) || (ins == INS_imulEAX) || (ins == INS_div) || (ins == INS_idiv);
}

// Because we don't actually have support for encoding these 3-op
// multiplies we fake it with special opcodes.  Make sure they are
// contiguous.
/* static */
inline void emitter::check3opImulValues()
{
    assert(INS_imul_AX - INS_imul_AX == REG_EAX);
    assert(INS_imul_BX - INS_imul_AX == REG_EBX);
    assert(INS_imul_CX - INS_imul_AX == REG_ECX);
    assert(INS_imul_DX - INS_imul_AX == REG_EDX);
    assert(INS_imul_BP - INS_imul_AX == REG_EBP);
    assert(INS_imul_SI - INS_imul_AX == REG_ESI);
    assert(INS_imul_DI - INS_imul_AX == REG_EDI);
#ifdef TARGET_AMD64
    assert(INS_imul_08 - INS_imul_AX == REG_R8);
    assert(INS_imul_09 - INS_imul_AX == REG_R9);
    assert(INS_imul_10 - INS_imul_AX == REG_R10);
    assert(INS_imul_11 - INS_imul_AX == REG_R11);
    assert(INS_imul_12 - INS_imul_AX == REG_R12);
    assert(INS_imul_13 - INS_imul_AX == REG_R13);
    assert(INS_imul_14 - INS_imul_AX == REG_R14);
    assert(INS_imul_15 - INS_imul_AX == REG_R15);
    assert(INS_imul_16 - INS_imul_AX == REG_R16);
    assert(INS_imul_17 - INS_imul_AX == REG_R17);
    assert(INS_imul_18 - INS_imul_AX == REG_R18);
    assert(INS_imul_19 - INS_imul_AX == REG_R19);
    assert(INS_imul_20 - INS_imul_AX == REG_R20);
    assert(INS_imul_21 - INS_imul_AX == REG_R21);
    assert(INS_imul_22 - INS_imul_AX == REG_R22);
    assert(INS_imul_23 - INS_imul_AX == REG_R23);
    assert(INS_imul_24 - INS_imul_AX == REG_R24);
    assert(INS_imul_25 - INS_imul_AX == REG_R25);
    assert(INS_imul_26 - INS_imul_AX == REG_R26);
    assert(INS_imul_27 - INS_imul_AX == REG_R27);
    assert(INS_imul_28 - INS_imul_AX == REG_R28);
    assert(INS_imul_29 - INS_imul_AX == REG_R29);
    assert(INS_imul_30 - INS_imul_AX == REG_R30);
    assert(INS_imul_31 - INS_imul_AX == REG_R31);
#endif
}

/*****************************************************************************
 *
 *  Return the instruction that uses the given register in the imul instruction
 */

/* static */
inline instruction emitter::inst3opImulForReg(regNumber reg)
{
    assert(genIsValidIntReg(reg));

    instruction ins = instruction(reg + INS_imul_AX);
    check3opImulValues();
    assert(instrIs3opImul(ins));

    return ins;
}

/*****************************************************************************
 *
 *  Return the register which is used implicitly by the IMUL_REG instruction
 */

/* static */
inline regNumber emitter::inst3opImulReg(instruction ins)
{
    regNumber reg = ((regNumber)(ins - INS_imul_AX));

    assert(genIsValidIntReg(reg));

    /* Make sure we return the appropriate register */

    check3opImulValues();

    return reg;
}
#endif

/*****************************************************************************
 *
 *  The following helpers should be used to access the various values that
 *  get stored in different places within the instruction descriptor.
 */

#ifdef TARGET_XARCH

inline ssize_t emitter::emitGetInsAmd(instrDesc* id) const
{
    return id->idIsLargeDsp() ? ((instrDescAmd*)id)->idaAmdVal : id->idAddr()->iiaAddrMode.amDisp;
}

inline int emitter::emitGetInsCDinfo(instrDesc* id)
{
    if (id->idIsLargeCall())
    {
        return ((instrDescCGCA*)id)->idcArgCnt;
    }
    else
    {
        assert(!id->idIsLargeDsp());
        assert(!id->idIsLargeCns());
        ssize_t cns = emitGetInsCns(id);

        // We only encode 32-bit ints, so this is safe
        noway_assert((int)cns == cns);

        return (int)cns;
    }
}

inline void emitter::emitGetInsCns(const instrDesc* id, CnsVal* cv) const
{
    cv->cnsReloc = id->idIsCnsReloc();
    if (id->idIsLargeCns())
    {
        cv->cnsVal = ((instrDescCns*)id)->idcCnsVal;
    }
    else
    {
        cv->cnsVal = id->idSmallCns();
    }
}

inline ssize_t emitter::emitGetInsAmdCns(const instrDesc* id, CnsVal* cv) const
{
    cv->cnsReloc = id->idIsCnsReloc();
    if (id->idIsLargeDsp())
    {
        if (id->idIsLargeCns())
        {
            cv->cnsVal = ((instrDescCnsAmd*)id)->idacCnsVal;
            return ((instrDescCnsAmd*)id)->idacAmdVal;
        }
        else
        {
            cv->cnsVal = id->idSmallCns();
            return ((instrDescAmd*)id)->idaAmdVal;
        }
    }
    else
    {
        if (id->idIsLargeCns())
        {
            cv->cnsVal = ((instrDescCns*)id)->idcCnsVal;
        }
        else
        {
            cv->cnsVal = id->idSmallCns();
        }

        return id->idAddr()->iiaAddrMode.amDisp;
    }
}

inline void emitter::emitGetInsDcmCns(const instrDesc* id, CnsVal* cv) const
{
    cv->cnsReloc = id->idIsCnsReloc();
    if (id->idIsLargeCns())
    {
        if (id->idIsLargeDsp())
        {
            cv->cnsVal = ((instrDescCnsDsp*)id)->iddcCnsVal;
        }
        else
        {
            cv->cnsVal = ((instrDescCns*)id)->idcCnsVal;
        }
    }
    else
    {
        cv->cnsVal = id->idSmallCns();
    }
}

inline ssize_t emitter::emitGetInsAmdAny(const instrDesc* id) const
{
    if (id->idIsLargeDsp())
    {
        if (id->idIsLargeCns())
        {
            return ((instrDescCnsAmd*)id)->idacAmdVal;
        }
        return ((instrDescAmd*)id)->idaAmdVal;
    }

    return id->idAddr()->iiaAddrMode.amDisp;
}

#endif // TARGET_XARCH

/*****************************************************************************
 *
 *  Convert between a register mask and a smaller version for storage.
 */
/*static*/ inline void emitter::emitEncodeCallGCregs(regMaskTP regmask, instrDesc* id)
{
    unsigned encodeMask;

#ifdef TARGET_X86
    assert(REGNUM_BITS >= 3);
    encodeMask = 0;

    if ((regmask & RBM_ESI) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_EDI) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_EBX) != RBM_NONE)
        encodeMask |= 0x04;

    id->idReg1((regNumber)encodeMask); // Save in idReg1

#elif defined(TARGET_AMD64)
    assert(REGNUM_BITS >= 4);
    encodeMask = 0;

    if ((regmask & RBM_RSI) != RBM_NONE)
    {
        encodeMask |= 0x01;
    }
    if ((regmask & RBM_RDI) != RBM_NONE)
    {
        encodeMask |= 0x02;
    }
    if ((regmask & RBM_RBX) != RBM_NONE)
    {
        encodeMask |= 0x04;
    }
    if ((regmask & RBM_RBP) != RBM_NONE)
    {
        encodeMask |= 0x08;
    }

    id->idReg1((regNumber)encodeMask); // Save in idReg1

    encodeMask = 0;

    if ((regmask & RBM_R12) != RBM_NONE)
    {
        encodeMask |= 0x01;
    }
    if ((regmask & RBM_R13) != RBM_NONE)
    {
        encodeMask |= 0x02;
    }
    if ((regmask & RBM_R14) != RBM_NONE)
    {
        encodeMask |= 0x04;
    }
    if ((regmask & RBM_R15) != RBM_NONE)
    {
        encodeMask |= 0x08;
    }

    id->idReg2((regNumber)encodeMask); // Save in idReg2

#elif defined(TARGET_ARM)
    assert(REGNUM_BITS >= 4);
    encodeMask = 0;

    if ((regmask & RBM_R4) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_R5) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_R6) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_R7) != RBM_NONE)
        encodeMask |= 0x08;

    id->idReg1((regNumber)encodeMask); // Save in idReg1

    encodeMask = 0;

    if ((regmask & RBM_R8) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_R9) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_R10) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_R11) != RBM_NONE)
        encodeMask |= 0x08;

    id->idReg2((regNumber)encodeMask); // Save in idReg2

#elif defined(TARGET_ARM64)
    assert(REGNUM_BITS >= 5);
    encodeMask = 0;

    if ((regmask & RBM_R19) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_R20) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_R21) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_R22) != RBM_NONE)
        encodeMask |= 0x08;
    if ((regmask & RBM_R23) != RBM_NONE)
        encodeMask |= 0x10;

    id->idReg1((regNumber)encodeMask); // Save in idReg1

    encodeMask = 0;

    if ((regmask & RBM_R24) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_R25) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_R26) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_R27) != RBM_NONE)
        encodeMask |= 0x08;
    if ((regmask & RBM_R28) != RBM_NONE)
        encodeMask |= 0x10;

    id->idReg2((regNumber)encodeMask); // Save in idReg2

#elif defined(TARGET_LOONGARCH64)
    assert(REGNUM_BITS >= 5);
    encodeMask = 0;

    if ((regmask & RBM_S0) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_S1) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_S2) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_S3) != RBM_NONE)
        encodeMask |= 0x08;
    if ((regmask & RBM_S4) != RBM_NONE)
        encodeMask |= 0x10;

    id->idReg1((regNumber)encodeMask); // Save in idReg1

    encodeMask = 0;

    if ((regmask & RBM_S5) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_S6) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_S7) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_S8) != RBM_NONE)
        encodeMask |= 0x08;

    id->idReg2((regNumber)encodeMask); // Save in idReg2

#elif defined(TARGET_RISCV64)
    assert(REGNUM_BITS >= 6);
    encodeMask = 0;

    if ((regmask & RBM_S1) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_S2) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_S3) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_S4) != RBM_NONE)
        encodeMask |= 0x08;
    if ((regmask & RBM_S5) != RBM_NONE)
        encodeMask |= 0x10;
    if ((regmask & RBM_S6) != RBM_NONE)
        encodeMask |= 0x20;

    id->idReg1((regNumber)encodeMask); // Save in idReg1

    encodeMask = 0;

    if ((regmask & RBM_S7) != RBM_NONE)
        encodeMask |= 0x01;
    if ((regmask & RBM_S8) != RBM_NONE)
        encodeMask |= 0x02;
    if ((regmask & RBM_S9) != RBM_NONE)
        encodeMask |= 0x04;
    if ((regmask & RBM_S10) != RBM_NONE)
        encodeMask |= 0x08;
    if ((regmask & RBM_S11) != RBM_NONE)
        encodeMask |= 0x10;

    id->idReg2((regNumber)encodeMask); // Save in idReg2

#else
    NYI("unknown target");
#endif
}

/*static*/ inline unsigned emitter::emitDecodeCallGCregs(instrDesc* id)
{
    regMaskTP regmask = RBM_NONE;
    unsigned  encodeMask;

#ifdef TARGET_X86
    assert(REGNUM_BITS >= 3);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_ESI;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_EDI;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_EBX;
#elif defined(TARGET_AMD64)
    assert(REGNUM_BITS >= 4);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
    {
        regmask |= RBM_RSI;
    }
    if ((encodeMask & 0x02) != 0)
    {
        regmask |= RBM_RDI;
    }
    if ((encodeMask & 0x04) != 0)
    {
        regmask |= RBM_RBX;
    }
    if ((encodeMask & 0x08) != 0)
    {
        regmask |= RBM_RBP;
    }

    encodeMask = id->idReg2();

    if ((encodeMask & 0x01) != 0)
    {
        regmask |= RBM_R12;
    }
    if ((encodeMask & 0x02) != 0)
    {
        regmask |= RBM_R13;
    }
    if ((encodeMask & 0x04) != 0)
    {
        regmask |= RBM_R14;
    }
    if ((encodeMask & 0x08) != 0)
    {
        regmask |= RBM_R15;
    }

#elif defined(TARGET_ARM)
    assert(REGNUM_BITS >= 4);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_R4;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_R5;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_R6;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_R7;

    encodeMask = id->idReg2();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_R8;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_R9;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_R10;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_R11;

#elif defined(TARGET_ARM64)
    assert(REGNUM_BITS >= 5);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_R19;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_R20;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_R21;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_R22;
    if ((encodeMask & 0x10) != 0)
        regmask |= RBM_R23;

    encodeMask = id->idReg2();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_R24;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_R25;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_R26;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_R27;
    if ((encodeMask & 0x10) != 0)
        regmask |= RBM_R28;

#elif defined(TARGET_LOONGARCH64)
    assert(REGNUM_BITS >= 5);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_S0;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_S1;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_S2;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_S3;
    if ((encodeMask & 0x10) != 0)
        regmask |= RBM_S4;

    encodeMask = id->idReg2();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_S5;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_S6;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_S7;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_S8;

#elif defined(TARGET_RISCV64)
    assert(REGNUM_BITS >= 6);
    encodeMask = id->idReg1();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_S1;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_S2;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_S3;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_S4;
    if ((encodeMask & 0x10) != 0)
        regmask |= RBM_S5;
    if ((encodeMask & 0x20) != 0)
        regmask |= RBM_S6;

    encodeMask = id->idReg2();

    if ((encodeMask & 0x01) != 0)
        regmask |= RBM_S7;
    if ((encodeMask & 0x02) != 0)
        regmask |= RBM_S8;
    if ((encodeMask & 0x04) != 0)
        regmask |= RBM_S9;
    if ((encodeMask & 0x08) != 0)
        regmask |= RBM_S10;
    if ((encodeMask & 0x10) != 0)
        regmask |= RBM_S11;

#else
    NYI("unknown target");
#endif

    return (unsigned int)regmask.getLow();
}

#ifdef TARGET_XARCH
inline bool insIsCMOV(instruction ins)
{
    return ((ins >= INS_cmovo) && (ins <= INS_cmovg));
}
#endif

/*****************************************************************************
 *
 *  Call the specified function pointer for each insGroup in the current
 *  method that is marked IGF_NOGCINTERRUPT. Stops if the callback returns
 *  false. Returns the final result of the callback.
 */
template <typename Callback>
bool emitter::emitGenNoGCLst(Callback& cb, bool skipMainPrologsAndEpilogs /* = false */)
{
    for (insGroup* ig = emitIGlist; ig; ig = ig->igNext)
    {
        if (skipMainPrologsAndEpilogs)
        {
            if (ig == emitPrologIG)
                continue;
            if (ig->igFlags & IGF_EPILOG)
                continue;
        }
        if ((ig->igFlags & IGF_NOGCINTERRUPT) && ig->igSize > 0)
        {
            emitter::instrDesc* id = emitFirstInstrDesc(ig->igData);
            assert(id != nullptr);
            assert(id->idCodeSize() > 0);
            if (!cb(ig->igFuncIdx, ig->igOffs, ig->igSize, id->idCodeSize(), ig->igFlags & (IGF_FUNCLET_PROLOG)))
            {
                return false;
            }
        }
    }

    return true;
}

/*****************************************************************************/
#endif //_EMITINL_H_
/*****************************************************************************/
