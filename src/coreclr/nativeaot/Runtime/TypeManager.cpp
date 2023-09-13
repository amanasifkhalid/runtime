// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "CommonTypes.h"
#include "CommonMacros.h"
#include "daccess.h"
#include "PalRedhawkCommon.h"
#include "PalRedhawk.h"
#include "holder.h"
#include "rhassert.h"
#include "slist.h"
#include "gcrhinterface.h"
#include "shash.h"
#include "varint.h"
#include "rhbinder.h"
#include "regdisplay.h"
#include "StackFrameIterator.h"
#include "thread.h"
#include "event.h"
#include "threadstore.h"
#include "TypeManager.h"

/* static */
TypeManager * TypeManager::Create(HANDLE osModule, void * pModuleHeader, void** pClasslibFunctions, uint32_t nClasslibFunctions)
{
    ReadyToRunHeader * pReadyToRunHeader = (ReadyToRunHeader *)pModuleHeader;

    // Sanity check the signature magic
    ASSERT(pReadyToRunHeader->Signature == ReadyToRunHeaderConstants::Signature);
    if (pReadyToRunHeader->Signature != ReadyToRunHeaderConstants::Signature)
        return nullptr;

    // Only the current major version is supported currently
    ASSERT(pReadyToRunHeader->MajorVersion == ReadyToRunHeaderConstants::CurrentMajorVersion);
    if (pReadyToRunHeader->MajorVersion != ReadyToRunHeaderConstants::CurrentMajorVersion)
        return nullptr;

    return new (nothrow) TypeManager(osModule, pReadyToRunHeader, pClasslibFunctions, nClasslibFunctions);
}

TypeManager::TypeManager(HANDLE osModule, ReadyToRunHeader * pHeader, void** pClasslibFunctions, uint32_t nClasslibFunctions)
    : m_osModule(osModule), m_pHeader(pHeader),
      m_pClasslibFunctions(pClasslibFunctions), m_nClasslibFunctions(nClasslibFunctions)
{
    int length;
    m_pStaticsGCDataSection = (uint8_t*)GetModuleSection(ReadyToRunSectionType::GCStaticRegion, &length);
    m_pThreadStaticsDataSection = (uint8_t*)GetModuleSection(ReadyToRunSectionType::ThreadStaticRegion, &length);
}

void * TypeManager::GetModuleSection(ReadyToRunSectionType sectionId, int * length)
{
   return LookupModuleSection(m_pHeader, sectionId, length);
}

void * TypeManager::GetClasslibFunction(ClasslibFunctionId functionId)
{
    uint32_t id = (uint32_t)functionId;

    if (id >= m_nClasslibFunctions)
        return nullptr;

    return m_pClasslibFunctions[id];
}

HANDLE TypeManager::GetOsModuleHandle()
{
    return m_osModule;
}

TypeManager* TypeManagerHandle::AsTypeManager()
{
    return (TypeManager*)_value;
}
