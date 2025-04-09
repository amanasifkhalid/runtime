// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.



inline BOOL ExecutionManager::IsCollectibleMethod(const METHODTOKEN& MethodToken)
{
    WRAPPER_NO_CONTRACT;
    return MethodToken.m_pRangeSection->_flags & RangeSection::RANGE_SECTION_COLLECTIBLE;
}

inline TADDR IJitManager::JitTokenToModuleBase(const METHODTOKEN& MethodToken)
{
    if (MethodToken.IsCold())
    {
        ColdCodeHeader * pColdCodeHeader = (ColdCodeHeader*)MethodToken.m_pCodeHeader;
        CodeHeader * pCodeHeader = (CodeHeader*)pColdCodeHeader->pCodeHeader;
        RangeSection* pHotRangeSection = ExecutionManager::FindCodeRange(pCodeHeader->GetCodeStartAddress(), ExecutionManager::GetScanFlags());
        return pHotRangeSection->_range.RangeStart();
    }

    return MethodToken.m_pRangeSection->_range.RangeStart();
}
