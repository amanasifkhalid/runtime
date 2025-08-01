// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// ===========================================================================
// File: CEELOAD.CPP
//

//

// CEELOAD reads in the PE file format using LoadLibrary
// ===========================================================================


#include "common.h"

#include "array.h"
#include "ceeload.h"
#include "hash.h"
#include "vars.hpp"
#include "reflectclasswriter.h"
#include "method.hpp"
#include "stublink.h"
#include "cgensys.h"
#include "excep.h"
#include "dbginterface.h"
#include "dllimport.h"
#include "eeprofinterfaces.h"
#include "encee.h"
#include "jitinterface.h"
#include "eeconfig.h"
#include "dllimportcallback.h"
#include "contractimpl.h"
#include "typehash.h"
#include "instmethhash.h"
#include "virtualcallstub.h"
#include "typestring.h"
#include "stringliteralmap.h"
#include <formattype.h>
#include "fieldmarshaler.h"
#include "sigbuilder.h"
#include "inlinetracking.h"
#include "threads.h"
#include "nativeimage.h"

#include "CachedInterfaceDispatchPal.h"
#include "CachedInterfaceDispatch.h"

#ifdef FEATURE_COMINTEROP
#include "runtimecallablewrapper.h"
#include "comcallablewrapper.h"
#endif //FEATURE_COMINTEROP

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4724)
#endif // _MSC_VER

#include "dacenumerablehash.inl"

#ifdef _MSC_VER
#pragma warning(pop)
#endif // _MSC_VER


#include "ecall.h"
#include "../md/compiler/custattr.h"
#include "typekey.h"
#include "peimagelayout.inl"

#include "interpexec.h"

#ifdef TARGET_64BIT
#define COR_VTABLE_PTRSIZED     COR_VTABLE_64BIT
#define COR_VTABLE_NOT_PTRSIZED COR_VTABLE_32BIT
#else // !TARGET_64BIT
#define COR_VTABLE_PTRSIZED     COR_VTABLE_32BIT
#define COR_VTABLE_NOT_PTRSIZED COR_VTABLE_64BIT
#endif // !TARGET_64BIT

#define CEE_FILE_GEN_GROWTH_COLLECTIBLE 2048

#define NGEN_STATICS_ALLCLASSES_WERE_LOADED -1

BOOL Module::HasReadyToRunInlineTrackingMap()
{
    LIMITED_METHOD_DAC_CONTRACT;
#ifdef FEATURE_READYTORUN
    if (IsReadyToRun() && GetReadyToRunInfo()->HasReadyToRunInlineTrackingMap())
    {
        return TRUE;
    }
#endif
    return FALSE;
}

COUNT_T Module::GetReadyToRunInliners(PTR_Module inlineeOwnerMod, mdMethodDef inlineeTkn, COUNT_T inlinersSize, MethodInModule inliners[], BOOL *incompleteData)
{
    WRAPPER_NO_CONTRACT;
#ifdef FEATURE_READYTORUN
    if(HasReadyToRunInlineTrackingMap())
    {
        return GetReadyToRunInfo()->GetInliners(inlineeOwnerMod, inlineeTkn, inlinersSize, inliners, incompleteData);
    }
#endif
    return 0;
}

#if defined(PROFILING_SUPPORTED) && !defined(DACCESS_COMPILE)
BOOL Module::HasJitInlineTrackingMap()
{
    LIMITED_METHOD_CONTRACT;

    return m_pJitInlinerTrackingMap != NULL;
}

void Module::AddInlining(MethodDesc *inliner, MethodDesc *inlinee)
{
    STANDARD_VM_CONTRACT;
    _ASSERTE(inliner != NULL && inlinee != NULL);
    _ASSERTE(inlinee->GetModule() == this);

    if (m_pJitInlinerTrackingMap != NULL)
    {
        m_pJitInlinerTrackingMap->AddInlining(inliner, inlinee);
    }
}
#endif // defined(PROFILING_SUPPORTED) && !defined(DACCESS_COMPILE)

#ifndef DACCESS_COMPILE
// ===========================================================================
// Module
// ===========================================================================

//---------------------------------------------------------------------------------------------------
// This wrapper just invokes the real initialization inside a try/hook.
// szName is not null only for dynamic modules
//---------------------------------------------------------------------------------------------------
void Module::DoInit(AllocMemTracker *pamTracker, LPCWSTR szName)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
    }
    CONTRACTL_END;

#ifdef PROFILING_SUPPORTED
    {
        BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
        GCX_COOP();
        (&g_profControlBlock)->ModuleLoadStarted((ModuleID) this);
        END_PROFILER_CALLBACK();
    }
    // Need TRY/HOOK instead of holder so we can get HR of exception thrown for profiler callback
    EX_TRY
#endif
    {
        Initialize(pamTracker, szName);
    }
#ifdef PROFILING_SUPPORTED


    EX_HOOK
    {
        {
            BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
            (&g_profControlBlock)->ModuleLoadFinished((ModuleID) this, GET_EXCEPTION()->GetHR());
            END_PROFILER_CALLBACK();
        }
    }
    EX_END_HOOK;

#endif
}

// Set the given bit on m_dwTransientFlags. Return true if we won the race to set the bit.
BOOL Module::SetTransientFlagInterlocked(DWORD dwFlag)
{
    LIMITED_METHOD_CONTRACT;

    for (;;)
    {
        DWORD dwTransientFlags = m_dwTransientFlags;
        if ((dwTransientFlags & dwFlag) != 0)
            return FALSE;
        if ((DWORD)InterlockedCompareExchange((LONG*)&m_dwTransientFlags, dwTransientFlags | dwFlag, dwTransientFlags) == dwTransientFlags)
            return TRUE;
    }
}

#if defined(PROFILING_SUPPORTED) || defined(FEATURE_METADATA_UPDATER)
void Module::UpdateNewlyAddedTypes()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        INJECT_FAULT(COMPlusThrowOM(););
    }
    CONTRACTL_END

    DWORD countTypesAfterProfilerUpdate = GetMDImport()->GetCountWithTokenKind(mdtTypeDef);
    DWORD countExportedTypesAfterProfilerUpdate = GetMDImport()->GetCountWithTokenKind(mdtExportedType);
    DWORD countCustomAttributeCount = GetMDImport()->GetCountWithTokenKind(mdtCustomAttribute);

    if (m_dwTypeCount == countTypesAfterProfilerUpdate
        && m_dwExportedTypeCount == countExportedTypesAfterProfilerUpdate
        && m_dwCustomAttributeCount == countCustomAttributeCount)
    {
        // The profiler added no new types, do not create the in memory hashes
        return;
    }

    // R2R pre-computes an export table and tries to avoid populating a class hash at runtime. However the profiler can
    // still add new types on the fly by calling here. If that occurs we fallback to the slower path of creating the
    // in memory hashtable as usual.
    if (GetAvailableClassHash() == NULL)
    {
        // This call will populate the hash tables with anything that is in metadata already.
        GetClassLoader()->LazyPopulateCaseSensitiveHashTablesDontHaveLock();
    }
    else
    {
        // If the hash tables already exist (either R2R and we've previously populated the ) we need to manually add the types.

        // typeDefs rids 0 and 1 aren't included in the count, thus X typeDefs before means rid X+1 was valid and our incremental addition should start at X+2
        for (DWORD typeDefRid = m_dwTypeCount + 2; typeDefRid < countTypesAfterProfilerUpdate + 2; typeDefRid++)
        {
            GetAssembly()->AddType(this, TokenFromRid(typeDefRid, mdtTypeDef));
        }

        // exportedType rid 0 isn't included in the count, thus X exportedTypes before means rid X was valid and our incremental addition should start at X+1
        for (DWORD exportedTypeDef = m_dwExportedTypeCount + 1; exportedTypeDef < countExportedTypesAfterProfilerUpdate + 1; exportedTypeDef++)
        {
            GetAssembly()->AddExportedType(TokenFromRid(exportedTypeDef, mdtExportedType));
        }

        if ((countCustomAttributeCount != m_dwCustomAttributeCount) && IsReadyToRun())
        {
            // Set of custom attributes has changed. Disable the cuckoo filter from ready to run, and do normal custom attribute parsing
            GetReadyToRunInfo()->DisableCustomAttributeFilter();
        }
    }

    m_dwTypeCount = countTypesAfterProfilerUpdate;
    m_dwExportedTypeCount = countExportedTypesAfterProfilerUpdate;
    m_dwCustomAttributeCount = countCustomAttributeCount;
}
#endif // PROFILING_SUPPORTED || FEATURE_METADATA_UPDATER

#if PROFILING_SUPPORTED
void Module::NotifyProfilerLoadFinished(HRESULT hr)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        INJECT_FAULT(COMPlusThrowOM());
        MODE_ANY;
    }
    CONTRACTL_END;

    // Note that in general we wil reuse shared modules.  So we need to make sure we only notify
    // the profiler once.
    if (SetTransientFlagInterlocked(IS_PROFILER_NOTIFIED))
    {
        // Record how many types are already present
        m_dwTypeCount = GetMDImport()->GetCountWithTokenKind(mdtTypeDef);
        m_dwExportedTypeCount = GetMDImport()->GetCountWithTokenKind(mdtExportedType);
        m_dwCustomAttributeCount = GetMDImport()->GetCountWithTokenKind(mdtCustomAttribute);

        BOOL profilerCallbackHappened = FALSE;
        // Notify the profiler, this may cause metadata to be updated
        {
            BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
            {
                GCX_PREEMP();
                (&g_profControlBlock)->ModuleLoadFinished((ModuleID) this, hr);

                if (SUCCEEDED(hr))
                {
                    (&g_profControlBlock)->ModuleAttachedToAssembly((ModuleID) this,
                                                                                (AssemblyID)m_pAssembly);
                }

                profilerCallbackHappened = TRUE;
            }
            END_PROFILER_CALLBACK();
        }

        // If there are more types than before, add these new types to the
        // assembly
        if (profilerCallbackHappened)
        {
            UpdateNewlyAddedTypes();
        }

        {
            BEGIN_PROFILER_CALLBACK(CORProfilerTrackAssemblyLoads());
            {
                GCX_COOP();
                (&g_profControlBlock)->AssemblyLoadFinished((AssemblyID) m_pAssembly, hr);
            }
            END_PROFILER_CALLBACK();
        }
    }
}
#endif // PROFILING_SUPPORTED

void Module::NotifyEtwLoadFinished(HRESULT hr)
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
    }
    CONTRACTL_END

    // we report only successful loads
    if (SUCCEEDED(hr) &&
        ETW_TRACING_CATEGORY_ENABLED(MICROSOFT_WINDOWS_DOTNETRUNTIME_PROVIDER_DOTNET_Context,
                                     TRACE_LEVEL_INFORMATION,
                                     KEYWORDZERO))
    {
        BOOL fSharedModule = !SetTransientFlagInterlocked(IS_ETW_NOTIFIED);
        ETW::LoaderLog::ModuleLoad(this, fSharedModule);
    }
}

// Module initialization occurs in two phases: the constructor phase and the Initialize phase.
//
// The constructor phase initializes just enough so that Destruct() can be safely called.
// It cannot throw or fail.
//
Module::Module(Assembly *pAssembly, PEAssembly *pPEAssembly)
    : m_pPEAssembly{pPEAssembly}
    , m_dwTransientFlags{CLASSES_FREED}
    , m_pAssembly{pAssembly}
    , m_pDynamicMethodTable{NULL}
    , m_hExposedObject{}
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        FORBID_FAULT;
    }
    CONTRACTL_END

    _ASSERTE(m_pAssembly != NULL);

    m_loaderAllocator = NULL;
    m_pDynamicMetadata = (TADDR)NULL;

    m_pPEAssembly->AddRef();
}

uint32_t Module::GetNativeMetadataAssemblyCount()
{
    if (m_pNativeImage != NULL)
    {
        return m_pNativeImage->GetManifestAssemblyCount();
    }
    else
    {
        return GetNativeAssemblyImport()->GetCountWithTokenKind(mdtAssemblyRef);
    }
}

void Module::SetNativeMetadataAssemblyRefInCache(DWORD rid, PTR_Assembly pAssembly)
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    if (m_NativeMetadataAssemblyRefMap == NULL)
    {
        uint32_t dwMaxRid = GetNativeMetadataAssemblyCount();
        _ASSERTE(dwMaxRid > 0);

        S_SIZE_T dwAllocSize = S_SIZE_T(sizeof(PTR_Assembly)) * S_SIZE_T(dwMaxRid);

        AllocMemTracker amTracker;
        PTR_Assembly* NativeMetadataAssemblyRefMap = (PTR_Assembly*)amTracker.Track(GetLoaderAllocator()->GetLowFrequencyHeap()->AllocMem(dwAllocSize));

        // Note: Memory allocated on loader heap is zero filled

        if (InterlockedCompareExchangeT<PTR_Assembly*>(&m_NativeMetadataAssemblyRefMap, NativeMetadataAssemblyRefMap, NULL) == NULL)
            amTracker.SuppressRelease();
    }
    _ASSERTE(m_NativeMetadataAssemblyRefMap != NULL);

    _ASSERTE(rid <= GetNativeMetadataAssemblyCount());
    VolatileStore(&m_NativeMetadataAssemblyRefMap[rid - 1], pAssembly);
}

// Module initialization occurs in two phases: the constructor phase and the Initialize phase.
//
// The Initialize() phase completes the initialization after the constructor has run.
// It can throw exceptions but whether it throws or succeeds, it must leave the Module
// in a state where Destruct() can be safely called.
//
// szName is only used by dynamic modules, see ReflectionModule::Initialize
//
void Module::Initialize(AllocMemTracker *pamTracker, LPCWSTR szName)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
        PRECONDITION(szName == NULL);
        PRECONDITION(m_pPEAssembly->IsLoaded());
    }
    CONTRACTL_END;

    m_loaderAllocator = GetAssembly()->GetLoaderAllocator();
    m_pSimpleName = m_pPEAssembly->GetSimpleName();
    m_path = m_pPEAssembly->GetPath().GetUnicode();
    m_fileName = m_pPEAssembly->GetModuleFileNameHint();
    _ASSERTE(m_path != NULL);
    m_baseAddress = m_pPEAssembly->HasLoadedPEImage() ? m_pPEAssembly->GetLoadedLayout()->GetBase() : NULL;
    if (m_pPEAssembly->IsReflectionEmit())
        m_dwTransientFlags |= IS_REFLECTION_EMIT;

    m_Crst.Init(CrstModule);
    m_LookupTableCrst.Init(CrstModuleLookupTable, CrstFlags(CRST_UNSAFE_ANYMODE | CRST_DEBUGGER_THREAD));
    m_InstMethodHashTableCrst.Init(CrstInstMethodHashTable, CRST_REENTRANCY);
    m_ISymUnmanagedReaderCrst.Init(CrstISymUnmanagedReader, CRST_DEBUGGER_THREAD);

    AllocateMaps();
    m_dwTransientFlags &= ~((DWORD)CLASSES_FREED);  // Set flag indicating LookupMaps are now in a consistent and destructable state

#ifdef FEATURE_READYTORUN
    m_pNativeImage = NULL;
    if ((m_pReadyToRunInfo = ReadyToRunInfo::Initialize(this, pamTracker)) != NULL)
    {
        m_pNativeImage = m_pReadyToRunInfo->GetNativeImage();
        if (m_pNativeImage != NULL)
        {
            m_NativeMetadataAssemblyRefMap = m_pNativeImage->GetManifestMetadataAssemblyRefMap();
        }
        else
        {
            // For composite images, manifest metadata gets loaded as part of the native image
            COUNT_T cMeta = 0;
            if (GetPEAssembly()->GetPEImage()->GetNativeManifestMetadata(&cMeta) != NULL)
            {
                // Load the native assembly import
                GetNativeAssemblyImport(TRUE /* loadAllowed */);
            }
        }
    }
#endif

    // Initialize the instance fields that we need for all Modules
    if (m_pAvailableClasses == NULL && !IsReadyToRun())
    {
        m_pAvailableClasses = EEClassHashTable::Create(this,
            GetAssembly()->IsCollectible() ? AVAILABLE_CLASSES_HASH_BUCKETS_COLLECTIBLE : AVAILABLE_CLASSES_HASH_BUCKETS,
                                                        NULL, pamTracker);
    }

    if (m_pAvailableParamTypes == NULL)
    {
        m_pAvailableParamTypes = EETypeHashTable::Create(GetLoaderAllocator(), this, PARAMTYPES_HASH_BUCKETS, pamTracker);
    }

    if (m_pInstMethodHashTable == NULL)
    {
        m_pInstMethodHashTable = InstMethodHashTable::Create(GetLoaderAllocator(), this, PARAMMETHODS_HASH_BUCKETS, pamTracker);
    }

    // These will be initialized in NotifyProfilerLoadFinished, set them to
    // a safe initial value now.
    m_dwTypeCount = 0;
    m_dwExportedTypeCount = 0;
    m_dwCustomAttributeCount = 0;
#ifdef PROFILING_SUPPORTED
    // set profiler related JIT flags
    if (CORProfilerDisableInlining())
    {
        m_dwTransientFlags |= PROF_DISABLE_INLINING;
    }
    if (CORProfilerDisableOptimizations())
    {
        m_dwTransientFlags |= PROF_DISABLE_OPTIMIZATIONS;
    }

    m_pJitInlinerTrackingMap = NULL;
    if (ReJitManager::IsReJITInlineTrackingEnabled())
    {
        m_pJitInlinerTrackingMap = new JITInlineTrackingMap(GetLoaderAllocator());
    }
#endif // PROFILING_SUPPORTED

    LOG((LF_CLASSLOADER, LL_INFO10, "Loaded pModule: \"%s\".\n", GetDebugName()));
}

#endif // DACCESS_COMPILE


void Module::SetDebuggerInfoBits(DebuggerAssemblyControlFlags newBits)
{
    LIMITED_METHOD_CONTRACT;
    SUPPORTS_DAC;

    _ASSERTE(((newBits << DEBUGGER_INFO_SHIFT_PRIV) &
              ~DEBUGGER_INFO_MASK_PRIV) == 0);

    m_dwTransientFlags &= ~DEBUGGER_INFO_MASK_PRIV;
    m_dwTransientFlags |= (newBits << DEBUGGER_INFO_SHIFT_PRIV);

#ifdef DEBUGGING_SUPPORTED
    if (IsEditAndContinueCapable())
    {
        BOOL setEnC = (newBits & DACF_ENC_ENABLED) != 0 || g_pConfig->ForceEnc() || (g_pConfig->DebugAssembliesModifiable() && AreJITOptimizationsDisabled());
        if (setEnC)
        {
            EnableEditAndContinue();
        }
    }
#endif // DEBUGGING_SUPPORTED

#if defined(DACCESS_COMPILE)
    // Now that we've changed m_dwTransientFlags, update that in the target too.
    // This will fail for read-only target.
    // If this fails, it will throw an exception.
    // @dbgtodo dac write: finalize on plans for how DAC writes to the target.
    HRESULT hrDac;
    hrDac = DacWriteHostInstance(this, true);
    _ASSERTE(SUCCEEDED(hrDac)); // would throw if there was an error.
#endif // DACCESS_COMPILE
}

#ifndef DACCESS_COMPILE
static BOOL IsEditAndContinueCapable(Assembly *pAssembly, PEAssembly *pPEAssembly)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    _ASSERTE(pAssembly != NULL && pPEAssembly != NULL);

    // Some modules are never EnC-capable
    return ! (pAssembly->GetDebuggerInfoBits() & DACF_ALLOW_JIT_OPTS ||
              pPEAssembly->IsSystem() ||
              pPEAssembly->IsReflectionEmit());
}

/* static */
Module *Module::Create(Assembly *pAssembly, PEAssembly *pPEAssembly, AllocMemTracker *pamTracker)
{
    CONTRACT(Module *)
    {
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(pAssembly));
        PRECONDITION(CheckPointer(pPEAssembly));
        POSTCONDITION(CheckPointer(RETVAL));
        POSTCONDITION(RETVAL->GetAssembly() == pAssembly);
        POSTCONDITION(RETVAL->GetPEAssembly() == pPEAssembly);
    }
    CONTRACT_END;

    // Hoist CONTRACT into separate routine because of EX incompatibility

    Module *pModule = NULL;

    // Create the module

#ifdef FEATURE_METADATA_UPDATER
    if (::IsEditAndContinueCapable(pAssembly, pPEAssembly))
    {
        // if file is EnCCapable, always create an EnC-module, but EnC won't necessarily be enabled.
        // Debugger enables this by calling SetJITCompilerFlags on LoadModule callback.

        void* pMemory = pamTracker->Track(pAssembly->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(EditAndContinueModule))));
        pModule = new (pMemory) EditAndContinueModule(pAssembly, pPEAssembly);
    }
    else
#endif // FEATURE_METADATA_UPDATER
    {
        void* pMemory = pamTracker->Track(pAssembly->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(Module))));
        pModule = new (pMemory) Module(pAssembly, pPEAssembly);
    }

    _ASSERTE(pModule != NULL);
    ModuleHolder pModuleSafe(pModule);
    pModuleSafe->DoInit(pamTracker, NULL);

    RETURN pModuleSafe.Extract();
}

void Module::ApplyMetaData()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    LOG((LF_CLASSLOADER, LL_INFO100, "Module::ApplyNewMetaData this:%p\n", this));

    HRESULT hr = S_OK;
    ULONG ulCount;

#if defined(PROFILING_SUPPORTED) || defined(FEATURE_METADATA_UPDATER)
    UpdateNewlyAddedTypes();
#endif // PROFILING_SUPPORTED || FEATURE_METADATA_UPDATER

    // Ensure for TypeRef
    ulCount = GetMDImport()->GetCountWithTokenKind(mdtTypeRef) + 1;
    EnsureTypeRefCanBeStored(TokenFromRid(ulCount, mdtTypeRef));

    // Ensure for AssemblyRef
    ulCount = GetMDImport()->GetCountWithTokenKind(mdtAssemblyRef) + 1;
    EnsureAssemblyRefCanBeStored(TokenFromRid(ulCount, mdtAssemblyRef));

    // Ensure for MethodDef
    ulCount = GetMDImport()->GetCountWithTokenKind(mdtMethodDef) + 1;
    EnsureMethodDefCanBeStored(TokenFromRid(ulCount, mdtMethodDef));
}

//
// Destructor for Module
//

void Module::Destruct()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_TRIGGERS;
        MODE_PREEMPTIVE;
    }
    CONTRACTL_END;

    LOG((LF_EEMEM, INFO3, "Deleting module %x\n", this));
#ifdef PROFILING_SUPPORTED
    {
        BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
        if (!IsBeingUnloaded())
        {
            // Profiler is causing some peripheral class loads. Probably this just needs
            // to be turned into a Fault_not_fatal and moved to a specific place inside the profiler.
            EX_TRY
            {
                GCX_PREEMP();
                (&g_profControlBlock)->ModuleUnloadStarted((ModuleID) this);
            }
            EX_CATCH
            {
            }
            EX_END_CATCH
        }
        END_PROFILER_CALLBACK();
    }
#endif // PROFILING_SUPPORTED


    DACNotify::DoModuleUnloadNotification(this);

    // Free classes in the class table
    FreeClassTables();



#ifdef DEBUGGING_SUPPORTED
    if (g_pDebugInterface)
    {
        GCX_PREEMP();
        g_pDebugInterface->DestructModule(this);
    }

#endif // DEBUGGING_SUPPORTED

    ReleaseISymUnmanagedReader();

    // Clean up sig cookies
    VASigCookieBlock    *pVASigCookieBlock = m_pVASigCookieBlock;
    while (pVASigCookieBlock)
    {
        VASigCookieBlock    *pNext = pVASigCookieBlock->m_Next;
        delete pVASigCookieBlock;

        pVASigCookieBlock = pNext;
    }

    // Clean up the IL stub cache
    if (m_pILStubCache != NULL)
    {
        delete m_pILStubCache;
    }



#ifdef PROFILING_SUPPORTED
    {
        BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
        // Profiler is causing some peripheral class loads. Probably this just needs
        // to be turned into a Fault_not_fatal and moved to a specific place inside the profiler.
        EX_TRY
        {
            GCX_PREEMP();
            (&g_profControlBlock)->ModuleUnloadFinished((ModuleID) this, S_OK);
        }
        EX_CATCH
        {
        }
        EX_END_CATCH
        END_PROFILER_CALLBACK();
    }
#endif // PROFILING_SUPPORTED

    //
    // Warning - deleting the zap file will cause the module to be unmapped
    //
    ClearInMemorySymbolStream();

    m_Crst.Destroy();
    m_LookupTableCrst.Destroy();
    m_InstMethodHashTableCrst.Destroy();
    m_ISymUnmanagedReaderCrst.Destroy();


    if (m_debuggerSpecificData.m_pDynamicILCrst)
    {
        delete m_debuggerSpecificData.m_pDynamicILCrst;
    }

    if (m_debuggerSpecificData.m_pDynamicILBlobTable)
    {
        delete m_debuggerSpecificData.m_pDynamicILBlobTable;
    }

    if (m_debuggerSpecificData.m_pILOffsetMappingTable)
    {
        for (ILOffsetMappingTable::Iterator pCurElem = m_debuggerSpecificData.m_pILOffsetMappingTable->Begin(),
                                            pEndElem = m_debuggerSpecificData.m_pILOffsetMappingTable->End();
             pCurElem != pEndElem;
             pCurElem++)
        {
            ILOffsetMappingEntry entry = *pCurElem;
            entry.m_mapping.Clear();
        }
        delete m_debuggerSpecificData.m_pILOffsetMappingTable;
    }

    m_pPEAssembly->Release();
    if (m_pDynamicMethodTable)
        m_pDynamicMethodTable->Destroy();

#if defined(PROFILING_SUPPORTED)
    delete m_pJitInlinerTrackingMap;
#endif
}

bool Module::NeedsGlobalMethodTable()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    IMDInternalImport * pImport = GetMDImport();
    if (pImport->IsValidToken(COR_GLOBAL_PARENT_TOKEN))
    {
        {
            HENUMInternalHolder funcEnum(pImport);
            funcEnum.EnumGlobalFunctionsInit();
            if (pImport->EnumGetCount(&funcEnum) != 0)
                return true;
        }

        {
            HENUMInternalHolder fieldEnum(pImport);
            fieldEnum.EnumGlobalFieldsInit();
            if (pImport->EnumGetCount(&fieldEnum) != 0)
                return true;
        }
    }

    // resource module or no global statics nor global functions
    return false;
}


MethodTable *Module::GetGlobalMethodTable()
{
    CONTRACT (MethodTable *)
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        INJECT_FAULT(CONTRACT_RETURN NULL;);
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
    }
    CONTRACT_END;


    if ((m_dwPersistedFlags & COMPUTED_GLOBAL_CLASS) == 0)
    {
        MethodTable *pMT = NULL;

        if (NeedsGlobalMethodTable())
        {
            pMT = ClassLoader::LoadTypeDefThrowing(this, COR_GLOBAL_PARENT_TOKEN,
                                                   ClassLoader::ThrowIfNotFound,
                                                   ClassLoader::FailIfUninstDefOrRef).AsMethodTable();
        }

        InterlockedOr((LONG*)&m_dwPersistedFlags, COMPUTED_GLOBAL_CLASS);
        RETURN pMT;
    }
    else
    {
        RETURN LookupTypeDef(COR_GLOBAL_PARENT_TOKEN).AsMethodTable();
    }
}


#endif // !DACCESS_COMPILE

BOOL Module::IsCollectible()
{
    LIMITED_METHOD_DAC_CONTRACT;
    return GetAssembly()->IsCollectible();
}

DomainAssembly* Module::GetDomainAssembly()
{
    LIMITED_METHOD_DAC_CONTRACT;

    return m_pDomainAssembly;
}

#ifndef DACCESS_COMPILE
#include "staticallocationhelpers.inl"

// initialize Crst controlling the Dynamic IL hashtable
void Module::InitializeDynamicILCrst()
{
    Crst * pCrst = new Crst(CrstDynamicIL, CrstFlags(CRST_UNSAFE_ANYMODE | CRST_DEBUGGER_THREAD));
    if (InterlockedCompareExchangeT(
            &m_debuggerSpecificData.m_pDynamicILCrst, pCrst, NULL) != NULL)
    {
        delete pCrst;
    }
}

// Add a (token, address) pair to the table of IL blobs for reflection/dynamics
// Arguments:
//     Input:
//         token        method token or field token (See SetDynamicRvaField)
//         blobAddress  address of the start of the IL blob address, including the header
//     Output: not explicit, but if the pair was not already in the table it will be added.
//             Does not add duplicate tokens to the table.

void Module::SetDynamicIL(mdToken token, TADDR blobAddress)
{
    DynamicILBlobEntry entry = {mdToken(token), TADDR(blobAddress)};

    // Lazily allocate a Crst to serialize update access to the info structure.
    // Carefully synchronize to ensure we don't leak a Crst in race conditions.
    if (m_debuggerSpecificData.m_pDynamicILCrst == NULL)
    {
        InitializeDynamicILCrst();
    }

    CrstHolder ch(m_debuggerSpecificData.m_pDynamicILCrst);

    // Lazily allocate the hash table.
    if (m_debuggerSpecificData.m_pDynamicILBlobTable == NULL)
    {
        m_debuggerSpecificData.m_pDynamicILBlobTable = PTR_DynamicILBlobTable(new DynamicILBlobTable);
    }
    m_debuggerSpecificData.m_pDynamicILBlobTable->AddOrReplace(entry);
}

#endif // !DACCESS_COMPILE

// Get the stored address of the IL blob for reflection/dynamics
// Arguments:
//     Input:
//         token        method token
//         fAllowTemporary also check the temporary overrides
// Return Value: starting (target) address of the IL blob corresponding to the input token

TADDR Module::GetDynamicIL(mdToken token)
{
    SUPPORTS_DAC;

#ifndef DACCESS_COMPILE
    // The Crst to serialize update access to the info structure is lazily allocated.
    // If it hasn't been allocated yet, then we don't have any IL blobs (temporary or otherwise)
    if (m_debuggerSpecificData.m_pDynamicILCrst == NULL)
    {
        return TADDR(NULL);
    }

    CrstHolder ch(m_debuggerSpecificData.m_pDynamicILCrst);
#endif

    // The hash table is lazily allocated, so if it is NULL
    // then we have no IL blobs

    if (m_debuggerSpecificData.m_pDynamicILBlobTable == NULL)
    {
        return TADDR(NULL);
    }

    DynamicILBlobEntry entry = m_debuggerSpecificData.m_pDynamicILBlobTable->Lookup(token);
    // If the lookup fails, it returns the 'NULL' entry
    // The 'NULL' entry has m_il set to NULL, so either way we're safe
    return entry.m_il;
}

#ifndef DACCESS_COMPILE
void Module::SetDynamicRvaField(mdToken token, TADDR blobAddress)
{
    CONTRACTL
    {
        THROWS;
        GC_NOTRIGGER;
        MODE_COOPERATIVE;
    }
    CONTRACTL_END;

    // Reuse existing dynamic IL mechanism to store/map the data.
    SetDynamicIL(token, blobAddress);
}
#endif // !DACCESS_COMPILE

TADDR Module::GetDynamicRvaField(mdToken token)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END

    // Reuse existing dynamic IL mechanism to store/map the data.
    return GetDynamicIL(token);
}

#if !defined(DACCESS_COMPILE)
//---------------------------------------------------------------------------------------
//
// Add instrumented IL offset mapping for the specified method.
//
// Arguments:
//    token   - the MethodDef token of the method in question
//    mapping - the mapping information between original IL offsets and instrumented IL offsets
//
// Notes:
//    * Once added, the mapping stays valid until the Module containing the method is destructed.
//    * The profiler may potentially update the mapping more than once.
//

void Module::SetInstrumentedILOffsetMapping(mdMethodDef token, InstrumentedILOffsetMapping mapping)
{
    ILOffsetMappingEntry entry(token, mapping);

    // Lazily allocate a Crst to serialize update access to the hash table.
    // Carefully synchronize to ensure we don't leak a Crst in race conditions.
    if (m_debuggerSpecificData.m_pDynamicILCrst == NULL)
    {
        InitializeDynamicILCrst();
    }

    CrstHolder ch(m_debuggerSpecificData.m_pDynamicILCrst);

    // Lazily allocate the hash table.
    if (m_debuggerSpecificData.m_pILOffsetMappingTable == NULL)
    {
        m_debuggerSpecificData.m_pILOffsetMappingTable = PTR_ILOffsetMappingTable(new ILOffsetMappingTable);
    }

    ILOffsetMappingEntry currentEntry = m_debuggerSpecificData.m_pILOffsetMappingTable->Lookup(ILOffsetMappingTraits::GetKey(entry));
    if (!ILOffsetMappingTraits::IsNull(currentEntry))
        currentEntry.m_mapping.Clear();

    m_debuggerSpecificData.m_pILOffsetMappingTable->AddOrReplace(entry);
}
#endif // DACCESS_COMPILE

//---------------------------------------------------------------------------------------
//
// Retrieve the instrumented IL offset mapping for the specified method.
//
// Arguments:
//    token   - the MethodDef token of the method in question
//
// Return Value:
//    Return the mapping information between original IL offsets and instrumented IL offsets.
//    Check InstrumentedILOffsetMapping::IsNull() to see if any mapping is available.
//
// Notes:
//    * Once added, the mapping stays valid until the Module containing the method is destructed.
//    * The profiler may potentially update the mapping more than once.
//

InstrumentedILOffsetMapping Module::GetInstrumentedILOffsetMapping(mdMethodDef token)
{
    CONTRACTL
    {
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    // Lazily allocate a Crst to serialize update access to the hash table.
    // If the Crst is NULL, then we couldn't possibly have added any mapping yet, so just return NULL.
    if (m_debuggerSpecificData.m_pDynamicILCrst == NULL)
    {
        InstrumentedILOffsetMapping emptyMapping;
        return emptyMapping;
    }

    CrstHolder ch(m_debuggerSpecificData.m_pDynamicILCrst);

    // If the hash table hasn't been created, then we couldn't possibly have added any mapping yet,
    // so just return NULL.
    if (m_debuggerSpecificData.m_pILOffsetMappingTable == NULL)
    {
        InstrumentedILOffsetMapping emptyMapping;
        return emptyMapping;
    }

    ILOffsetMappingEntry entry = m_debuggerSpecificData.m_pILOffsetMappingTable->Lookup(token);
    return entry.m_mapping;
}

#undef DECODE_TYPEID
#undef ENCODE_TYPEID
#undef IS_ENCODED_TYPEID



#ifndef DACCESS_COMPILE

BOOL Module::HasDefaultDllImportSearchPathsAttribute()
{
    CONTRACTL
    {
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END;

    if(IsDefaultDllImportSearchPathsAttributeCached())
    {
        return (m_dwPersistedFlags & DEFAULT_DLL_IMPORT_SEARCH_PATHS_STATUS) != 0 ;
    }

    BOOL attributeIsFound = FALSE;
    attributeIsFound = GetDefaultDllImportSearchPathsAttributeValue(this, TokenFromRid(1, mdtAssembly),&m_DefaultDllImportSearchPathsAttributeValue);
    if(attributeIsFound)
    {
        InterlockedOr((LONG*)&m_dwPersistedFlags, DEFAULT_DLL_IMPORT_SEARCH_PATHS_IS_CACHED | DEFAULT_DLL_IMPORT_SEARCH_PATHS_STATUS);
    }
    else
    {
        InterlockedOr((LONG*)&m_dwPersistedFlags, DEFAULT_DLL_IMPORT_SEARCH_PATHS_IS_CACHED);
    }

    return (m_dwPersistedFlags & DEFAULT_DLL_IMPORT_SEARCH_PATHS_STATUS) != 0 ;
}

// Returns a BOOL to indicate if we have computed whether compiler has instructed us to
// wrap the non-CLS compliant exceptions or not.
BOOL Module::IsRuntimeWrapExceptionsStatusComputed()
{
    LIMITED_METHOD_CONTRACT;

    return (m_dwPersistedFlags & COMPUTED_WRAP_EXCEPTIONS);
}

BOOL Module::IsRuntimeWrapExceptionsDuringEH()
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END

    // This method assumes that the runtime wrap exceptions status has already been computed.
    // IsRuntimeWrapExceptionsStatusComputed() returns TRUE before calling this method, but
    // that should be done as part of Module activation, so we shouldn't need to worry about that.
    _ASSERTE(IsRuntimeWrapExceptionsStatusComputed());
    return (m_dwPersistedFlags & WRAP_EXCEPTIONS) != 0;
}

BOOL Module::IsRuntimeWrapExceptions()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END

    if (!(IsRuntimeWrapExceptionsStatusComputed()))
    {
        UpdateCachedIsRuntimeWrapExceptions();
    }
    return !!(m_dwPersistedFlags & WRAP_EXCEPTIONS);
}

void Module::UpdateCachedIsRuntimeWrapExceptions()
{
    HRESULT hr;
    BOOL fRuntimeWrapExceptions = FALSE;

    IMDInternalImport *mdImport = GetAssembly()->GetMDImport();

    mdToken token;
    IfFailGo(mdImport->GetAssemblyFromScope(&token));

    const BYTE *pVal;
    ULONG       cbVal;

    hr = mdImport->GetCustomAttributeByName(token,
                    RUNTIMECOMPATIBILITY_TYPE,
                    (const void**)&pVal, &cbVal);

    // Parse the attribute
    if (hr == S_OK)
    {
        CustomAttributeParser ca(pVal, cbVal);
        CaNamedArg namedArgs[1] = {{0}};

        // First, the void constructor:
        IfFailGo(ParseKnownCaArgs(ca, NULL, 0));

        // Then, find the named argument
        namedArgs[0].InitBoolField("WrapNonExceptionThrows");

        IfFailGo(ParseKnownCaNamedArgs(ca, namedArgs, ARRAY_SIZE(namedArgs)));

        if (namedArgs[0].val.boolean)
            fRuntimeWrapExceptions = TRUE;
    }
ErrExit:
    InterlockedOr((LONG*)&m_dwPersistedFlags, COMPUTED_WRAP_EXCEPTIONS |
        (fRuntimeWrapExceptions ? WRAP_EXCEPTIONS : 0));
}

BOOL Module::IsRuntimeMarshallingEnabled()
{
    CONTRACTL
    {
        THROWS;
        if (IsRuntimeMarshallingEnabledCached()) GC_NOTRIGGER; else GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END

    if (IsRuntimeMarshallingEnabledCached())
    {
        return !!(m_dwPersistedFlags & RUNTIME_MARSHALLING_ENABLED);
    }

    HRESULT hr;

    IMDInternalImport *mdImport = GetAssembly()->GetMDImport();

    mdToken token;
    if (SUCCEEDED(hr = mdImport->GetAssemblyFromScope(&token)))
    {
        const BYTE *pVal;
        ULONG       cbVal;

        hr = mdImport->GetCustomAttributeByName(token,
                        g_DisableRuntimeMarshallingAttribute,
                        (const void**)&pVal, &cbVal);
    }

    InterlockedOr((LONG*)&m_dwPersistedFlags, RUNTIME_MARSHALLING_ENABLED_IS_CACHED |
        (hr == S_OK ? 0 : RUNTIME_MARSHALLING_ENABLED));

    return hr != S_OK;
}

void Module::SetDomainAssembly(DomainAssembly *pDomainAssembly)
{
    LIMITED_METHOD_CONTRACT;

    m_pDomainAssembly = pDomainAssembly;
}

//---------------------------------------------------------------------------------------
//
// Returns managed representation of the module (Module or ModuleBuilder).
// Returns NULL if the managed scout was already collected (see code:LoaderAllocator#AssemblyPhases).
//
OBJECTREF Module::GetExposedObject()
{
    CONTRACT(OBJECTREF)
    {
        INSTANCE_CHECK;
        POSTCONDITION(RETVAL != NULL);
        THROWS;
        GC_TRIGGERS;
        MODE_COOPERATIVE;
    }
    CONTRACT_END;

        LoaderAllocator * pLoaderAllocator = GetLoaderAllocator();

    if (m_hExposedObject == (LOADERHANDLE)NULL)
    {
        // Atomically create a handle
        LOADERHANDLE handle = pLoaderAllocator->AllocateHandle(NULL);

        InterlockedCompareExchangeT(&m_hExposedObject, handle, static_cast<LOADERHANDLE>(0));
    }

    if (pLoaderAllocator->GetHandleValue(m_hExposedObject) == NULL)
    {
        REFLECTMODULEBASEREF refClass = NULL;

        // Will be true only if LoaderAllocator managed object was already collected and therefore we should
        // return NULL
        bool fIsLoaderAllocatorCollected = false;

        GCPROTECT_BEGIN(refClass);

        refClass = (REFLECTMODULEBASEREF) AllocateObject(CoreLibBinder::GetClass(CLASS__MODULE));
        refClass->SetModule(this);

        // Attach the reference to the assembly to keep the LoaderAllocator for this collectible type
        // alive as long as a reference to the module is kept alive.
        if (GetAssembly() != NULL)
        {
            OBJECTREF refAssembly = GetAssembly()->GetExposedObject();
            if ((refAssembly == NULL) && GetAssembly()->IsCollectible())
            {
                fIsLoaderAllocatorCollected = true;
            }
            refClass->SetAssembly(refAssembly);
        }

        pLoaderAllocator->CompareExchangeValueInHandle(m_hExposedObject, (OBJECTREF)refClass, NULL);
        GCPROTECT_END();

        if (fIsLoaderAllocatorCollected)
        {   // The LoaderAllocator managed object was already collected, we cannot re-create it
            // Note: We did not publish the allocated Module/ModuleBuilder object, it will get collected
            // by GC
            return NULL;
        }
    }

    RETURN pLoaderAllocator->GetHandleValue(m_hExposedObject);
}

OBJECTREF Module::GetExposedObjectIfExists()
{
    LIMITED_METHOD_CONTRACT;

    OBJECTREF objRet = NULL;
    GET_LOADERHANDLE_VALUE_FAST(GetLoaderAllocator(), m_hExposedObject, &objRet);
    return objRet;
}

//
// AllocateMap allocates the RID maps based on the size of the current
// metadata (if any)
//

void Module::AllocateMaps()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END;

    enum
    {
        TYPEDEF_MAP_INITIAL_SIZE = 5,
        TYPEREF_MAP_INITIAL_SIZE = 5,
        MEMBERREF_MAP_INITIAL_SIZE = 10,
        MEMBERDEF_MAP_INITIAL_SIZE = 10,
        GENERICPARAM_MAP_INITIAL_SIZE = 5,
        GENERICTYPEDEF_MAP_INITIAL_SIZE = 5,
        FILEREFERENCES_MAP_INITIAL_SIZE = 5,
        ASSEMBLYREFERENCES_MAP_INITIAL_SIZE = 5,
    };

    PTR_TADDR pTable = NULL;

    if (IsReflectionEmit())
    {
        // For dynamic modules, it is essential that we at least have a TypeDefToMethodTable
        // map with an initial block.  Otherwise, all the iterators will abort on an
        // initial empty table and we will e.g. corrupt the backpatching chains during
        // an appdomain unload.
        m_TypeDefToMethodTableMap.dwCount = TYPEDEF_MAP_INITIAL_SIZE;

        // The above is essential.  The following ones are precautionary.
        m_TypeRefToMethodTableMap.dwCount = TYPEREF_MAP_INITIAL_SIZE;
        m_MemberRefMap.dwCount = MEMBERREF_MAP_INITIAL_SIZE;
        m_MethodDefToDescMap.dwCount = MEMBERDEF_MAP_INITIAL_SIZE;
        m_ILCodeVersioningStateMap.dwCount = MEMBERDEF_MAP_INITIAL_SIZE;
        m_FieldDefToDescMap.dwCount = MEMBERDEF_MAP_INITIAL_SIZE;
        m_GenericParamToDescMap.dwCount = GENERICPARAM_MAP_INITIAL_SIZE;
        m_ManifestModuleReferencesMap.dwCount = ASSEMBLYREFERENCES_MAP_INITIAL_SIZE;
    }
    else
    {
        IMDInternalImport * pImport = GetMDImport();

        // Get # TypeDefs (add 1 for COR_GLOBAL_PARENT_TOKEN)
        m_TypeDefToMethodTableMap.dwCount = pImport->GetCountWithTokenKind(mdtTypeDef)+2;

        // Get # TypeRefs
        m_TypeRefToMethodTableMap.dwCount = pImport->GetCountWithTokenKind(mdtTypeRef)+1;

        // Get # MemberRefs
        m_MemberRefMap.dwCount = pImport->GetCountWithTokenKind(mdtMemberRef)+1;

        // Get # MethodDefs
        m_MethodDefToDescMap.dwCount = pImport->GetCountWithTokenKind(mdtMethodDef)+1;

        // IL code versions are relatively rare so keep small.
        m_ILCodeVersioningStateMap.dwCount = 1;

        // Get # FieldDefs
        m_FieldDefToDescMap.dwCount = pImport->GetCountWithTokenKind(mdtFieldDef)+1;

        // Get # GenericParams
        m_GenericParamToDescMap.dwCount = pImport->GetCountWithTokenKind(mdtGenericParam)+1;

        // Get the number of AssemblyReferences in the map
        m_ManifestModuleReferencesMap.dwCount = pImport->GetCountWithTokenKind(mdtAssemblyRef)+1;
    }

    S_SIZE_T nTotal;

    nTotal += m_TypeDefToMethodTableMap.dwCount;
    nTotal += m_TypeRefToMethodTableMap.dwCount;
    nTotal += m_MemberRefMap.dwCount;
    nTotal += m_MethodDefToDescMap.dwCount;
    nTotal += m_ILCodeVersioningStateMap.dwCount;
    nTotal += m_FieldDefToDescMap.dwCount;
    nTotal += m_GenericParamToDescMap.dwCount;
    nTotal += m_ManifestModuleReferencesMap.dwCount;

    _ASSERTE (m_pAssembly && m_pAssembly->GetLowFrequencyHeap());
    pTable = (PTR_TADDR)(void*)m_pAssembly->GetLowFrequencyHeap()->AllocMem(nTotal * S_SIZE_T(sizeof(TADDR)));

    // Note: Memory allocated on loader heap is zero filled
    // memset(pTable, 0, nTotal * sizeof(void*));

    m_TypeDefToMethodTableMap.pNext  = NULL;
    m_TypeDefToMethodTableMap.supportedFlags = TYPE_DEF_MAP_ALL_FLAGS;
    m_TypeDefToMethodTableMap.pTable = pTable;

    m_TypeRefToMethodTableMap.pNext  = NULL;
    m_TypeRefToMethodTableMap.supportedFlags = TYPE_REF_MAP_ALL_FLAGS;
    m_TypeRefToMethodTableMap.pTable = &pTable[m_TypeDefToMethodTableMap.dwCount];

    m_MemberRefMap.pNext = NULL;
    m_MemberRefMap.supportedFlags = MEMBER_REF_MAP_ALL_FLAGS;
    m_MemberRefMap.pTable = &m_TypeRefToMethodTableMap.pTable[m_TypeRefToMethodTableMap.dwCount];

    m_MethodDefToDescMap.pNext  = NULL;
    m_MethodDefToDescMap.supportedFlags = METHOD_DEF_MAP_ALL_FLAGS;
    m_MethodDefToDescMap.pTable = &m_MemberRefMap.pTable[m_MemberRefMap.dwCount];

    m_ILCodeVersioningStateMap.pNext  = NULL;
    m_ILCodeVersioningStateMap.supportedFlags = METHOD_DEF_MAP_ALL_FLAGS;
    m_ILCodeVersioningStateMap.pTable = &m_MethodDefToDescMap.pTable[m_MethodDefToDescMap.dwCount];

    m_FieldDefToDescMap.pNext  = NULL;
    m_FieldDefToDescMap.supportedFlags = FIELD_DEF_MAP_ALL_FLAGS;
    m_FieldDefToDescMap.pTable = &m_ILCodeVersioningStateMap.pTable[m_ILCodeVersioningStateMap.dwCount];

    m_GenericParamToDescMap.pNext  = NULL;
    m_GenericParamToDescMap.supportedFlags = GENERIC_PARAM_MAP_ALL_FLAGS;
    m_GenericParamToDescMap.pTable = &m_FieldDefToDescMap.pTable[m_FieldDefToDescMap.dwCount];

    m_ManifestModuleReferencesMap.pNext  = NULL;
    m_ManifestModuleReferencesMap.supportedFlags = MANIFEST_MODULE_MAP_ALL_FLAGS;
    m_ManifestModuleReferencesMap.pTable = &m_GenericParamToDescMap.pTable[m_GenericParamToDescMap.dwCount];
}


//
// FreeClassTables frees the classes in the module
//

void Module::FreeClassTables()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    if (m_dwTransientFlags & CLASSES_FREED)
        return;

    InterlockedOr((LONG*)&m_dwTransientFlags, CLASSES_FREED);

#if _DEBUG
    DebugLogRidMapOccupancy();
#endif

    //
    // Free the types filled out in the TypeDefToEEClass map
    //

    // Go through each linked block
    LookupMap<PTR_MethodTable>::Iterator typeDefIter(&m_TypeDefToMethodTableMap);
    while (typeDefIter.Next())
    {
        MethodTable * pMT = typeDefIter.GetElement();
        if (pMT != NULL)
        {
            ClassLoader::NotifyUnload(pMT, true);
            pMT->GetClass()->Destruct();
            ClassLoader::NotifyUnload(pMT, false);
        }
    }

    // Now do the same for constructed types (arrays and instantiated generic types)
    if (IsTenured())  // If we're destructing because of an error during the module's creation, we'll play it safe and not touch this table as its memory is freed by a
    {                 // separate AllocMemTracker. Though you're supposed to destruct everything else before destructing the AllocMemTracker, this is an easy invariant to break so
                      // we'll play extra safe on this end.
        if (m_pAvailableParamTypes != NULL)
        {
            EETypeHashTable::Iterator it(m_pAvailableParamTypes);
            EETypeHashEntry *pEntry;
            while (m_pAvailableParamTypes->FindNext(&it, &pEntry))
            {
                TypeHandle th = pEntry->GetTypeHandle();

                // Array EEClass doesn't need notification and there is no work for Destruct()
                if (th.IsTypeDesc())
                    continue;

                MethodTable * pMT = th.AsMethodTable();
                ClassLoader::NotifyUnload(pMT, true);

                // We need to call destruct on instances of EEClass whose "canonical" dependent lives in this table
                if (pMT->IsCanonicalMethodTable())
                {
                    pMT->GetClass()->Destruct();
                }

                ClassLoader::NotifyUnload(pMT, false);
            }
        }
    }
}

#endif // !DACCESS_COMPILE

ClassLoader *Module::GetClassLoader()
{
    WRAPPER_NO_CONTRACT;
    SUPPORTS_DAC;
    _ASSERTE(m_pAssembly != NULL);
    return m_pAssembly->GetLoader();
}

#ifndef DACCESS_COMPILE

void Module::StartUnload()
{
    WRAPPER_NO_CONTRACT;
#ifdef PROFILING_SUPPORTED
    {
        BEGIN_PROFILER_CALLBACK(CORProfilerTrackModuleLoads());
        if (!IsBeingUnloaded())
        {
            // Profiler is causing some peripheral class loads. Probably this just needs
            // to be turned into a Fault_not_fatal and moved to a specific place inside the profiler.
            EX_TRY
            {
                GCX_PREEMP();
                (&g_profControlBlock)->ModuleUnloadStarted((ModuleID) this);
            }
            EX_CATCH
            {
            }
            EX_END_CATCH
        }
        END_PROFILER_CALLBACK();
    }
#endif // PROFILING_SUPPORTED

    SetBeingUnloaded();
}

#if defined(FEATURE_READYTORUN)
//---------------------------------------------------------------------------------------
// Check if the target module is in the same version bubble as this one
// The current implementation uses the presence of an AssemblyRef for the target module's assembly in
// the native manifest metadata.
//
// Arguments:
//      * target - target module to check
//
// Return Value:
//      TRUE if the target module is in the same version bubble as this one
//
BOOL Module::IsInSameVersionBubble(Module *target)
{
    STANDARD_VM_CONTRACT;

    if (this == target)
    {
        return TRUE;
    }

    if (!IsReadyToRun())
    {
        return FALSE;
    }

    NativeImage *nativeImage = this->GetCompositeNativeImage();

    if (nativeImage != NULL)
    {
        if (nativeImage == target->GetCompositeNativeImage())
        {
            // Fast path for modules contained within the same native image
            return TRUE;
        }
    }

    IMDInternalImport* pMdImport = GetReadyToRunInfo()->GetNativeManifestModule()->GetMDImport();
    if (pMdImport == NULL)
        return FALSE;

    LPCUTF8 targetName = target->GetAssembly()->GetSimpleName();

    HENUMInternal assemblyEnum;
    HRESULT hr = pMdImport->EnumAllInit(mdtAssemblyRef, &assemblyEnum);
    mdAssemblyRef assemblyRef;
    while (pMdImport->EnumNext(&assemblyEnum, &assemblyRef))
    {
        LPCSTR assemblyName;
        hr = pMdImport->GetAssemblyRefProps(assemblyRef, NULL, NULL, &assemblyName, NULL, NULL, NULL, NULL);
        if (strcmp(assemblyName, targetName) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}
#endif // FEATURE_READYTORUN

//---------------------------------------------------------------------------------------
//
// Wrapper for Module::GetRWImporter + QI when writing is not needed.
//
// Arguments:
//      * dwOpenFlags - Combo from CorOpenFlags. Better not contain ofWrite!
//      * riid - Public IID requested
//      * ppvInterface - [out] Requested interface. On success, *ppvInterface is returned
//          refcounted; caller responsible for Release.
//
// Return Value:
//      HRESULT indicating success or failure.
//
HRESULT Module::GetReadablePublicMetaDataInterface(DWORD dwOpenFlags, REFIID riid, LPVOID * ppvInterface)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        CAN_TAKE_LOCK;
        MODE_ANY;
    }
    CONTRACTL_END;

    _ASSERTE((dwOpenFlags & ofWrite) == 0);

    // Temporary place to store the IUnknown from which we'll do the final QI to get the
    // requested public interface.  Any assignment to pIUnk assumes pIUnk does not need
    // to do a Release() (either the interface was internal and not AddRef'd, or was
    // public and will be released by the above holder).
    IUnknown * pIUnk = NULL;

    HRESULT hr = S_OK;

    // Normally, we just get an RWImporter to do the QI on, and we're on our way.
    EX_TRY
    {
        pIUnk = GetRWImporter();
    }
    EX_CATCH_HRESULT_NO_ERRORINFO(hr);

    // Get the requested interface
    if (SUCCEEDED(hr) && (ppvInterface != NULL))
    {
        _ASSERTE(pIUnk != NULL);
        hr = pIUnk->QueryInterface(riid, (void **) ppvInterface);
    }

    return hr;
}

// a special token that indicates no reader could be created - don't try again
static ISymUnmanagedReader* const k_pInvalidSymReader = (ISymUnmanagedReader*)0x1;

#if defined(FEATURE_ISYM_READER)
ISymUnmanagedReader *Module::GetISymUnmanagedReaderNoThrow(void)
{
    CONTRACT(ISymUnmanagedReader *)
    {
        INSTANCE_CHECK;
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
        NOTHROW;
        WRAPPER(GC_TRIGGERS);
        MODE_ANY;
    }
    CONTRACT_END;

    ISymUnmanagedReader *ret = NULL;

    EX_TRY
    {
        ret = GetISymUnmanagedReader();
    }
    EX_SWALLOW_NONTERMINAL
    // We swallow any exception and say that we simply couldn't get a reader by returning NULL.
    // The only type of error that should be possible here is OOM.
    RETURN (ret);
}

#if defined(HOST_AMD64)
#define NATIVE_SYMBOL_READER_DLL W("Microsoft.DiaSymReader.Native.amd64.dll")
#elif defined(HOST_X86)
#define NATIVE_SYMBOL_READER_DLL W("Microsoft.DiaSymReader.Native.x86.dll")
#elif defined(HOST_ARM)
#define NATIVE_SYMBOL_READER_DLL W("Microsoft.DiaSymReader.Native.arm.dll")
#elif defined(HOST_ARM64)
#define NATIVE_SYMBOL_READER_DLL W("Microsoft.DiaSymReader.Native.arm64.dll")
#endif

ISymUnmanagedReader *Module::GetISymUnmanagedReader(void)
{
    CONTRACT(ISymUnmanagedReader *)
    {
        INSTANCE_CHECK;
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
        THROWS;
        WRAPPER(GC_TRIGGERS);
        MODE_ANY;
    }
    CONTRACT_END;

    if (g_fEEShutDown)
        RETURN NULL;

    // Verify that symbol reading is permitted for this module.
    // If we know we've already created a symbol reader, don't bother checking.  There is
    // no advantage to allowing symbol reading to be turned off if we've already created the reader.
    // Note that we can't just put this code in the creation block below because we might have to
    // call managed code to resolve security policy, and we can't do that while holding a lock.
    // There is no disadvantage other than a minor perf cost to calling this unnecessarily, so the
    // race on m_pISymUnmanagedReader here is OK.  The perf cost is minor because the only real
    // work is done by the security system which caches the result.
    if( m_pISymUnmanagedReader == NULL && !IsSymbolReadingEnabled() )
        RETURN NULL;

    // Take the lock for the m_pISymUnmanagedReader
    // This ensures that we'll only ever attempt to create one reader at a time, and we won't
    // create a reader if we're in the middle of destroying one that has become stale.
    // Actual access to the reader can safely occur outside the lock as long as it has its own
    // AddRef which we take inside the lock at the bottom of this method.
    CrstHolder holder(&m_ISymUnmanagedReaderCrst);

    // If we haven't created a reader yet, do so now
    if (m_pISymUnmanagedReader == NULL)
    {
        // Mark our reader as invalid so that if we fail to create the reader
        // (including if an exception is thrown), we won't keep trying.
        m_pISymUnmanagedReader = k_pInvalidSymReader;

        // There are 4 main cases here:
        //  1. Assembly is on disk and we'll get the symbols from a file next to the assembly
        //  2. Assembly was loaded in-memory (by byte array or ref-emit), and symbols were
        //      provided along with it.
        //  3. Assembly was loaded in-memory but no symbols were provided.

        // Determine whether we should be looking in memory for the symbols (case 2)
        bool fInMemorySymbols = GetInMemorySymbolStream();
        if( !fInMemorySymbols && m_pPEAssembly->GetPath().IsEmpty() )
        {
            // Case 3.  We don't have a module path or an in memory symbol stream,
            // so there is no-where to try and get symbols from.
            RETURN (NULL);
        }

        // Create a binder to find the reader.
        //
        // <REVISIT_TODO>@perf: this is slow, creating and destroying the binder every
        // time. We should cache this somewhere, but I'm not 100% sure
        // where right now...</REVISIT_TODO>
        HRESULT hr = S_OK;

        SafeComHolder<ISymUnmanagedBinder> pBinder;

        if (g_pDebugInterface == NULL)
        {
            // @TODO: this is reachable when debugging!
            UNREACHABLE_MSG("About to CoCreateInstance!  This code should not be "
                            "reachable or needs to be reimplemented for CoreCLR!");
        }

        PathString symbolReaderPath;
        hr = GetClrModuleDirectory(symbolReaderPath);
        if (FAILED(hr))
        {
            RETURN (NULL);
        }
        symbolReaderPath.Append(NATIVE_SYMBOL_READER_DLL);
        hr = FakeCoCreateInstanceEx(CLSID_CorSymBinder_SxS, symbolReaderPath.GetUnicode(), IID_ISymUnmanagedBinder, (void**)&pBinder, NULL);
        if (FAILED(hr))
        {
            RETURN (NULL);
        }

        LOG((LF_CORDB, LL_INFO10, "M::GISUR: Created binder\n"));

        // Note: we change the error mode here so we don't get any popups as the PDB symbol reader attempts to search the
        // hard disk for files.
        ErrorModeHolder errorMode{};

        SafeComHolder<ISymUnmanagedReader> pReader;

        if (fInMemorySymbols)
        {
            SafeComHolder<IStream> pIStream( NULL );

            // If debug stream is already specified, don't bother to go through fusion
            // This is the common case for case 2 (hosted modules) and case 3 (Ref.Emit).
            if (GetInMemorySymbolStream() )
            {

                if( IsReflectionEmit() )
                {
                    // If this is Reflection.Emit, we must clone the stream because another thread may
                    // update it when someone is using the reader we create here leading to AVs.
                    // Note that the symbol stream should be up to date since we flush the writer
                    // after every addition in Module::AddClass.
                    IfFailThrow(GetInMemorySymbolStream()->Clone(&pIStream));
                }
                else
                {
                    // The stream is not changing. Just add-ref to it.
                    pIStream = GetInMemorySymbolStream();
                    pIStream->AddRef();
                }
            }
            if (SUCCEEDED(hr))
            {
                hr = pBinder->GetReaderFromStream(GetRWImporter(), pIStream, &pReader);
            }
        }
        else
        {
            // The assembly is on disk, so try and load symbols based on the path to the assembly (case 1)
            const SString &path = m_pPEAssembly->GetPath();

            // Call Fusion to ensure that any PDB's are shadow copied before
            // trying to get a symbol reader. This has to be done once per
            // Assembly.
            ReleaseHolder<IUnknown> pUnk = NULL;
            hr = GetReadablePublicMetaDataInterface(ofReadOnly, IID_IMetaDataImport, &pUnk);
            if (SUCCEEDED(hr))
                hr = pBinder->GetReaderForFile(pUnk, path, NULL, &pReader);
        }

        if (SUCCEEDED(hr))
        {
            m_pISymUnmanagedReader = pReader.Extract();
            LOG((LF_CORDB, LL_INFO10, "M::GISUR: Loaded symbols for module %s\n", GetDebugName()));
        }
        else
        {
            // We failed to create the reader, don't try again next time
            LOG((LF_CORDB, LL_INFO10, "M::GISUR: Failed to load symbols for module %s\n", GetDebugName()));
            _ASSERTE( m_pISymUnmanagedReader == k_pInvalidSymReader );
        }

    } // if( m_pISymUnmanagedReader == NULL )

    // If we previously failed to create the reader, return NULL
    if (m_pISymUnmanagedReader == k_pInvalidSymReader)
    {
        RETURN (NULL);
    }

    // Success - return an AddRef'd copy of the reader
    m_pISymUnmanagedReader->AddRef();
    RETURN (m_pISymUnmanagedReader);
}
#endif // FEATURE_ISYM_READER

BOOL Module::IsSymbolReadingEnabled()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

#ifdef DEBUGGING_SUPPORTED
    if (!g_pDebugInterface)
    {
        // if debugging is disabled (no debug pack installed), do not load symbols
        // This is done for two reasons.  We don't completely trust the security of
        // the diasymreader.dll code, so we don't want to use it in mainline scenarios.
        // Secondly, there's not reason that diasymreader.dll will even necssarily be
        // be on the machine if the debug pack isn't installed.
        return FALSE;
    }
#endif // DEBUGGING_SUPPORTED


    return TRUE;
}

// At this point, this is only called when we're creating an appdomain
// out of an array of bytes, so we'll keep the IStream that we create
// around in case the debugger attaches later (including detach & re-attach!)
void Module::SetSymbolBytes(LPCBYTE pbSyms, DWORD cbSyms)
{
    STANDARD_VM_CONTRACT;

    // Create a IStream from the memory for the syms.
    SafeComHolder<CGrowableStream> pStream(new CGrowableStream());

    // Do not need to AddRef the CGrowableStream because the constructor set it to 1
    // ref count already. The Module will keep a copy for its own use.

    // Make sure to set the symbol stream on the module before
    // attempting to send UpdateModuleSyms messages up for it.
    SetInMemorySymbolStream(pStream);

    // This can only be called when the module is being created.  No-one should have
    // tried to use the symbols yet, and so there should not be a reader.
    // If instead, we wanted to call this when a reader could have been created, we need to
    // serialize access by taking the reader lock, and flush the old reader by calling
    // code:Module.ReleaseISymUnmanagedReader
    _ASSERTE( m_pISymUnmanagedReader == NULL );

#ifdef LOGGING
    LPCUTF8 pName = NULL;
    pName = GetDebugName();
#endif // LOGGING

    ULONG cbWritten;
    DWORD dwError = pStream->Write((const void *)pbSyms,
                               (ULONG)cbSyms,
                                                &cbWritten);
    IfFailThrow(HRESULT_FROM_WIN32(dwError));

#if PROFILING_SUPPORTED
    BEGIN_PROFILER_CALLBACK(CORProfilerInMemorySymbolsUpdatesEnabled());
    {
        (&g_profControlBlock)->ModuleInMemorySymbolsUpdated((ModuleID) this);
    }
    END_PROFILER_CALLBACK();
#endif //PROFILING_SUPPORTED

    ETW::CodeSymbolLog::EmitCodeSymbols(this);

    // Tell the debugger that symbols have been loaded for this
    // module.  We iterate through all domains which contain this
    // module's assembly, and send a debugger notify for each one.
    // <REVISIT_TODO>@perf: it would scale better if we directly knew which domains
    // the assembly was loaded in.</REVISIT_TODO>
    if (CORDebuggerAttached())
    {
        AppDomain *pDomain = AppDomain::GetCurrentDomain();
        if (pDomain->IsDebuggerAttached() && pDomain->ContainsAssembly(m_pAssembly))
        {
            g_pDebugInterface->SendUpdateModuleSymsEventAndBlock(this);
        }
    }
}

// Clear any cached symbol reader
void Module::ReleaseISymUnmanagedReader(void)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        FORBID_FAULT;
    }
    CONTRACTL_END;

    // Caller is responsible for taking the reader lock if the call could occur when
    // other threads are using or creating the reader
    if( m_pISymUnmanagedReader != NULL )
    {
        // If we previously failed to create a reader, don't attempt to release it
        // but do clear it out so that we can try again (eg. symbols may have changed)
        if( m_pISymUnmanagedReader != k_pInvalidSymReader )
        {
            m_pISymUnmanagedReader->Release();
        }
        m_pISymUnmanagedReader = NULL;
    }
}

// Lazily creates a new IL stub cache for this module.
ILStubCache* Module::GetILStubCache()
{
    CONTRACTL
    {
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
        INJECT_FAULT(COMPlusThrowOM(););
    }
    CONTRACTL_END;

    // Use per-LoaderAllocator cache for modules
    if (!IsSystem())
        return GetLoaderAllocator()->GetILStubCache();

    if (m_pILStubCache == NULL)
    {
        ILStubCache *pILStubCache = new ILStubCache(GetLoaderAllocator());

        if (InterlockedCompareExchangeT(&m_pILStubCache, pILStubCache, NULL) != NULL)
        {
            // some thread swooped in and set the field
            delete pILStubCache;
        }
    }
    _ASSERTE(m_pILStubCache != NULL);
    return m_pILStubCache;
}

// Called to finish the process of adding a new class with Reflection.Emit
void Module::AddClass(mdTypeDef classdef)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_PREEMPTIVE;
    }
    CONTRACTL_END;

    // The fake class associated with the module (global fields & functions) needs to be initialized here
    // Normal classes are added to the available class hash when their typedef is first created.
    if (RidFromToken(classdef) == 0)
    {
        BuildClassForModule();
    }
}

//---------------------------------------------------------------------------
// For the global class this builds the table of MethodDescs an adds the rids
// to the MethodDef map.
//---------------------------------------------------------------------------
void Module::BuildClassForModule()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    IMDInternalImport * pImport = GetMDImport();
    DWORD           cFunctions, cFields;

    {
        // Obtain count of global functions
        HENUMInternalHolder hEnum(pImport);
        hEnum.EnumGlobalFunctionsInit();
        cFunctions = pImport->EnumGetCount(&hEnum);
    }

    {
        // Obtain count of global fields
        HENUMInternalHolder hEnum(pImport);
        hEnum.EnumGlobalFieldsInit();
        cFields = pImport->EnumGetCount(&hEnum);
    }

    // If we have any work to do...
    if (cFunctions > 0 || cFields > 0)
    {
        TypeKey typeKey(this, COR_GLOBAL_PARENT_TOKEN);
        TypeHandle typeHnd = GetClassLoader()->LoadTypeHandleForTypeKeyNoLock(&typeKey);
    }
}

#endif // !DACCESS_COMPILE

// Returns true iff the debugger should be notified about this module
//
// Notes:
//   Debugger doesn't need to be notified about modules that can't be executed.
//   (we do not have such cases at the moment)
//
//   This should be immutable for an instance of a module. That ensures that the debugger gets consistent
//   notifications about it. It this value mutates, than the debugger may miss relevant notifications.
BOOL Module::IsVisibleToDebugger()
{
    WRAPPER_NO_CONTRACT;
    SUPPORTS_DAC;

    return TRUE;
}

PEImageLayout * Module::GetReadyToRunImage()
{
    LIMITED_METHOD_CONTRACT;

#ifdef FEATURE_READYTORUN
    if (IsReadyToRun())
        return GetReadyToRunInfo()->GetImage();
#endif

    return NULL;
}

PTR_READYTORUN_IMPORT_SECTION Module::GetImportSections(COUNT_T *pCount)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    return GetReadyToRunInfo()->GetImportSections(pCount);
}

PTR_READYTORUN_IMPORT_SECTION Module::GetImportSectionFromIndex(COUNT_T index)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    return GetReadyToRunInfo()->GetImportSectionFromIndex(index);
}

PTR_READYTORUN_IMPORT_SECTION Module::GetImportSectionForRVA(RVA rva)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    return GetReadyToRunInfo()->GetImportSectionForRVA(rva);
}

TADDR Module::GetIL(RVA target)
{
    WRAPPER_NO_CONTRACT;
    SUPPORTS_DAC;

    if (target == 0)
        return (TADDR)NULL;

    return m_pPEAssembly->GetIL(target);
}

PTR_VOID Module::GetRvaField(DWORD rva)
{
    WRAPPER_NO_CONTRACT;
    SUPPORTS_DAC;

    return m_pPEAssembly->GetRvaField(rva);
}

#ifndef DACCESS_COMPILE

CHECK Module::CheckRvaField(RVA field)
{
    WRAPPER_NO_CONTRACT;
    if (!IsReflectionEmit())
        CHECK(m_pPEAssembly->CheckRvaField(field));
    CHECK_OK;
}

CHECK Module::CheckRvaField(RVA field, COUNT_T size)
{
    CONTRACTL
    {
        STANDARD_VM_CHECK;
        CAN_TAKE_LOCK;
    }
    CONTRACTL_END;

    if (!IsReflectionEmit())
        CHECK(m_pPEAssembly->CheckRvaField(field, size));
    CHECK_OK;
}

#endif // !DACCESS_COMPILE

BOOL Module::HasTls()
{
    WRAPPER_NO_CONTRACT;

    return m_pPEAssembly->HasTls();
}

BOOL Module::IsRvaFieldTls(DWORD rva)
{
    WRAPPER_NO_CONTRACT;

    return m_pPEAssembly->IsRvaFieldTls(rva);
}

UINT32 Module::GetFieldTlsOffset(DWORD rva)
{
    WRAPPER_NO_CONTRACT;

    return m_pPEAssembly->GetFieldTlsOffset(rva);
}

UINT32 Module::GetTlsIndex()
{
    WRAPPER_NO_CONTRACT;

    return m_pPEAssembly->GetTlsIndex();
}


// In DAC builds this function was being called on host addresses which may or may not
// have been marshalled from the target. Such addresses can't be reliably mapped back to
// target addresses, which means we can't tell whether they came from the IL or not
//
// Security note: Any security which you might wish to gain by verifying the origin of
// a signature isn't available in DAC. The attacker can provide a dump which spoofs all
// module ranges. In other words the attacker can make the signature appear to come from
// anywhere, but still violate all the rules that a signature from that location would
// otherwise follow. I am removing this function from DAC in order to prevent anyone from
// getting a false sense of security (in addition to its functional shortcomings)

#ifndef DACCESS_COMPILE
BOOL Module::IsSigInILImpl(PCCOR_SIGNATURE signature)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        FORBID_FAULT;
        MODE_ANY;
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    return m_pPEAssembly->IsPtrInPEImage(signature);
}

void ModuleBase::InitializeStringData(DWORD token, EEStringData *pstrData, CQuickBytes *pqb)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        INJECT_FAULT(COMPlusThrowOM());
        PRECONDITION(TypeFromToken(token) == mdtString);
    }
    CONTRACTL_END;

    BOOL fIs80Plus;
    DWORD dwCharCount;
    LPCWSTR pString;
    if (FAILED(GetMDImport()->GetUserString(token, &dwCharCount, &fIs80Plus, &pString)) ||
        (pString == NULL))
    {
        THROW_BAD_FORMAT(BFA_BAD_STRING_TOKEN_RANGE, this);
    }

#if !BIGENDIAN
    pstrData->SetStringBuffer(pString);
#else // !!BIGENDIAN
    _ASSERTE(pqb != NULL);

    LPWSTR pSwapped;

    pSwapped = (LPWSTR) pqb->AllocThrows(dwCharCount * sizeof(WCHAR));
    memcpy((void*)pSwapped, (void*)pString, dwCharCount*sizeof(WCHAR));
    SwapStringLength(pSwapped, dwCharCount);

    pstrData->SetStringBuffer(pSwapped);
#endif // !!BIGENDIAN

        // MD and String look at this bit in opposite ways.  Here's where we'll do the conversion.
        // MD sets the bit to true if the string contains characters greater than 80.
        // String sets the bit to true if the string doesn't contain characters greater than 80.

    pstrData->SetCharCount(dwCharCount);
    pstrData->SetIsOnlyLowChars(!fIs80Plus);
}


STRINGREF* ModuleBase::ResolveStringRef(DWORD token, void** ppPinnedString)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
        INJECT_FAULT(COMPlusThrowOM());
        PRECONDITION(TypeFromToken(token) == mdtString);
    }
    CONTRACTL_END;

    EEStringData strData;

#if !BIGENDIAN
    InitializeStringData(token, &strData, NULL);
#else // !!BIGENDIAN
    CQuickBytes qb;
    InitializeStringData(token, &strData, &qb);
#endif // !!BIGENDIAN

    GCX_COOP();
    LoaderAllocator* pLoaderAllocator = this->GetLoaderAllocator();
    return pLoaderAllocator->GetStringObjRefPtrFromUnicodeString(&strData, ppPinnedString);
}

mdToken Module::GetEntryPointToken()
{
    WRAPPER_NO_CONTRACT;

    return m_pPEAssembly->GetEntryPointToken();
}

BYTE *Module::GetProfilerBase()
{
    CONTRACT(BYTE*)
    {
        NOTHROW;
        GC_NOTRIGGER;
        CANNOT_TAKE_LOCK;
    }
    CONTRACT_END;

    if (m_pPEAssembly == NULL)  // I'd rather assert this is not the case...
    {
        RETURN NULL;
    }
    else if (m_pPEAssembly->HasLoadedPEImage())
    {
        RETURN  (BYTE*)(m_pPEAssembly->GetLoadedLayout()->GetBase());
    }
    else
    {
        RETURN NULL;
    }
}

#endif //!DACCESS_COMPILE

Assembly *
Module::GetAssemblyIfLoaded(
    mdAssemblyRef       kAssemblyRef,
    IMDInternalImport * pMDImportOverride,  // = NULL
    AssemblyBinder      *pBinderForLoadedAssembly // = NULL
)
{
    CONTRACT(Assembly *)
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        FORBID_FAULT;
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
        SUPPORTS_DAC;
    }
    CONTRACT_END;

    Assembly * pAssembly = NULL;
    BOOL fCanUseRidMap = pMDImportOverride == NULL;

#ifdef _DEBUG
    fCanUseRidMap = fCanUseRidMap && (CLRConfig::GetConfigValue(CLRConfig::INTERNAL_GetAssemblyIfLoadedIgnoreRidMap) == 0);
#endif


    // Don't do a lookup if an override IMDInternalImport is provided, since the lookup is for the
    // standard IMDInternalImport and might result in an incorrect result.
    if (fCanUseRidMap)
    {
        pAssembly = LookupAssemblyRef(kAssemblyRef);
    }

#ifndef DACCESS_COMPILE
    // Check if actually loaded, unless a GC is in progress or the current thread is
    // walking the stack (either its own stack, or another thread's stack) as that works
    // only with loaded assemblies
    //
    // NOTE: The case where the current thread is walking a stack can be problematic for
    // other reasons, as the remaining code of this function uses "GetAppDomain()", when
    // in fact the right AppDomain to use is the one corresponding to the frame being
    // traversed on the walked thread. Dev10 TFS bug# 762348 tracks that issue.
    if ((pAssembly != NULL) && !IsGCThread() && !IsStackWalkerThread())
    {
        _ASSERTE(::GetAppDomain() != NULL);
        if (!pAssembly->IsLoaded())
            pAssembly = NULL;
    }

    if (pAssembly == NULL)
    {
        IMDInternalImport * pMDImport = (pMDImportOverride == NULL) ? (GetMDImport()) : (pMDImportOverride);

        //we have to be very careful here.
        //we are using InitializeSpecInternal so we need to make sure that under no condition
        //the data we pass to it can outlive the assembly spec.
        AssemblySpec spec;
        if (FAILED(spec.InitializeSpecInternal(kAssemblyRef,
                                                pMDImport,
                                                GetAssembly())))
        {
            return NULL;
        }

        // If we have been passed the binding context for the loaded assembly that is being looked up in the
        // cache, then set it up in the AssemblySpec for the cache lookup to use it below.
        if (pBinderForLoadedAssembly != NULL)
        {
            _ASSERTE(spec.GetBinder() == NULL);
            spec.SetBinder(pBinderForLoadedAssembly);
        }

        Assembly * pCachedAssembly = AppDomain::GetCurrentDomain()->FindCachedAssembly(&spec, FALSE /*fThrow*/);

        if (pCachedAssembly && pCachedAssembly->IsLoaded())
            pAssembly = pCachedAssembly;

        // Only store in the rid map if working with the current AppDomain.
        if (fCanUseRidMap && pAssembly)
            StoreAssemblyRef(kAssemblyRef, pAssembly);
    }
#endif //!DACCESS_COMPILE

    // When walking the stack or computing GC information this function should never fail.
    _ASSERTE((pAssembly != NULL) || !(IsStackWalkerThread() || IsGCThread()));

#ifdef DACCESS_COMPILE

    // Note: In rare cases when debugger walks the stack, we could actually have pAssembly=NULL here.
    // To fix that we should DACize the AppDomain-iteration code above (especially AssemblySpec).
    _ASSERTE(pAssembly != NULL);

#endif //DACCESS_COMPILE

    RETURN pAssembly;
} // Module::GetAssemblyIfLoaded

DWORD
ModuleBase::GetAssemblyRefFlags(
    mdAssemblyRef tkAssemblyRef)
{
    CONTRACTL
    {
        if (FORBIDGC_LOADER_USE_ENABLED()) NOTHROW; else THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END;

    _ASSERTE(TypeFromToken(tkAssemblyRef) == mdtAssemblyRef);

    LPCSTR      pszAssemblyName;
    const void *pbPublicKeyOrToken;
    DWORD cbPublicKeyOrToken;

    DWORD dwAssemblyRefFlags;
    IfFailThrow(GetMDImport()->GetAssemblyRefProps(
            tkAssemblyRef,
            &pbPublicKeyOrToken,
            &cbPublicKeyOrToken,
            &pszAssemblyName,
            NULL,
            NULL,
            NULL,
            &dwAssemblyRefFlags));

    return dwAssemblyRefFlags;
} // Module::GetAssemblyRefFlags

#ifndef DACCESS_COMPILE
Assembly * Module::LoadAssemblyImpl(mdAssemblyRef kAssemblyRef)
{
    CONTRACT(Assembly *)
    {
        INSTANCE_CHECK;
        if (FORBIDGC_LOADER_USE_ENABLED()) NOTHROW; else THROWS;
        if (FORBIDGC_LOADER_USE_ENABLED()) GC_NOTRIGGER; else GC_TRIGGERS;
        if (FORBIDGC_LOADER_USE_ENABLED()) FORBID_FAULT; else { INJECT_FAULT(COMPlusThrowOM();); }
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL, NULL_NOT_OK));
    }
    CONTRACT_END;

    ETWOnStartup (LoaderCatchCall_V1, LoaderCatchCallEnd_V1);

    //
    // Early out quickly if the result is cached
    //
    Assembly * pAssembly = LookupAssemblyRef(kAssemblyRef);
    if (pAssembly != NULL)
    {
        ::GetAppDomain()->LoadAssembly(pAssembly, FILE_LOADED);
        RETURN pAssembly;
    }

    {
        PEAssemblyHolder pPEAssembly = GetPEAssembly()->LoadAssembly(kAssemblyRef);
        AssemblySpec spec;
        spec.InitializeSpec(kAssemblyRef, GetMDImport(), GetAssembly());
        // Set the binding context in the AssemblySpec if one is available. This can happen if the LoadAssembly ended up
        // invoking the custom AssemblyLoadContext implementation that returned a reference to an assembly bound to a different
        // AssemblyLoadContext implementation.
        AssemblyBinder *pBinder = pPEAssembly->GetAssemblyBinder();
        if (pBinder != NULL)
        {
            spec.SetBinder(pBinder);
        }
        pAssembly = GetAppDomain()->LoadAssembly(&spec, pPEAssembly, FILE_LOADED);
    }

    _ASSERTE(pAssembly != NULL && pAssembly->IsLoaded());
    _ASSERTE(
        pAssembly->IsSystem() ||                  // GetAssemblyIfLoaded will not find CoreLib (see AppDomain::FindCachedFile)
        GetAssemblyIfLoaded(kAssemblyRef, NULL, pAssembly->GetPEAssembly()->GetHostAssembly()->GetBinder()) != NULL);     // GetAssemblyIfLoaded should find all remaining cases

    StoreAssemblyRef(kAssemblyRef, pAssembly);

    RETURN pAssembly;
}
#else
Assembly * Module::LoadAssemblyImpl(mdAssemblyRef kAssemblyRef)
{
    WRAPPER_NO_CONTRACT;
    ThrowHR(E_FAIL);
}
#endif // !DACCESS_COMPILE

Module *Module::GetModuleIfLoaded(mdFile kFile)
{
    CONTRACT(Module *)
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        PRECONDITION(TypeFromToken(kFile) == mdtFile
                     || TypeFromToken(kFile) == mdtModuleRef);
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
        FORBID_FAULT;
        SUPPORTS_DAC;
    }
    CONTRACT_END;

    ENABLE_FORBID_GC_LOADER_USE_IN_THIS_SCOPE();

    if (kFile == mdFileNil)
        return this;

    // Handle the module ref case
    if (TypeFromToken(kFile) == mdtModuleRef)
    {
        LPCSTR moduleName;
        if (FAILED(GetMDImport()->GetModuleRefProps(kFile, &moduleName)))
        {
            RETURN NULL;
        }

        RETURN GetAssembly()->GetModule()->GetModuleIfLoaded(mdFileNil);
    }

    RETURN NULL;
}

#ifndef DACCESS_COMPILE

Module *ModuleBase::LoadModule(mdFile kFile)
{
    CONTRACT(Module *)
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        PRECONDITION(TypeFromToken(kFile) == mdtFile
                     || TypeFromToken(kFile) == mdtModuleRef);
    }
    CONTRACT_END;

    LPCSTR psModuleName=NULL;
    if (TypeFromToken(kFile) == mdtModuleRef)
    {
        // This is a moduleRef
        IfFailThrow(GetMDImport()->GetModuleRefProps(kFile, &psModuleName));
    }
    else
    {
        // This is mdtFile
        IfFailThrow(GetMDImport()->GetFileProps(kFile,
                                    &psModuleName,
                                    NULL,
                                    NULL,
                                    NULL));
    }

    SString name(SString::Utf8, psModuleName);
    EEFileLoadException::Throw(name, COR_E_MULTIMODULEASSEMBLIESDIALLOWED, NULL);
    RETURN NULL;
}
#endif // !DACCESS_COMPILE

PTR_Module Module::LookupModule(mdToken kFile)
{
    CONTRACT(PTR_Module)
    {
        INSTANCE_CHECK;
        if (FORBIDGC_LOADER_USE_ENABLED()) NOTHROW; else THROWS;
        if (FORBIDGC_LOADER_USE_ENABLED()) GC_NOTRIGGER; else GC_TRIGGERS;
        if (FORBIDGC_LOADER_USE_ENABLED()) FORBID_FAULT;
        else { INJECT_FAULT(COMPlusThrowOM()); }
        MODE_ANY;
        PRECONDITION(TypeFromToken(kFile) == mdtFile
                     || TypeFromToken(kFile) == mdtModuleRef);
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
        SUPPORTS_DAC;
    }
    CONTRACT_END;

    if (TypeFromToken(kFile) == mdtModuleRef)
    {
        LPCSTR moduleName;
        IfFailThrow(GetMDImport()->GetModuleRefProps(kFile, &moduleName));

        RETURN GetAssembly()->GetModule()->LookupModule(mdFileNil);
    }

    PTR_Module pModule = LookupFile(kFile);
    RETURN pModule;
}


TypeHandle ModuleBase::LookupTypeRef(mdTypeRef token)
{
    STATIC_CONTRACT_NOTHROW;
    STATIC_CONTRACT_GC_NOTRIGGER;
    STATIC_CONTRACT_FORBID_FAULT;
    SUPPORTS_DAC;

    _ASSERTE(TypeFromToken(token) == mdtTypeRef);

    TypeHandle entry = TypeHandle::FromTAddr(dac_cast<TADDR>(m_TypeRefToMethodTableMap.GetElement(RidFromToken(token))));

    if (entry.IsNull())
        return TypeHandle();

    return entry;
}

#ifndef DACCESS_COMPILE

//
// Increase the size of one of the maps, such that it can handle a RID of at least "rid".
//
// This function must also check that another thread didn't already add a LookupMap capable
// of containing the same RID.
//
PTR_TADDR LookupMapBase::GrowMap(ModuleBase * pModule, DWORD rid)
{
    CONTRACT(PTR_TADDR)
    {
        INSTANCE_CHECK;
        THROWS;
        GC_NOTRIGGER;
        MODE_ANY;
        INJECT_FAULT(ThrowOutOfMemory(););
        POSTCONDITION(CheckPointer(RETVAL));
    }
    CONTRACT_END;

    LookupMapBase *pMap = this;
    LookupMapBase *pPrev = NULL;
    LookupMapBase *pNewMap = NULL;

    // Initial block size
    DWORD dwIndex = rid;
    DWORD dwBlockSize = 16;

    {
        CrstHolder ch(pModule->GetLookupTableCrst());
        // Check whether we can already handle this RID index
        do
        {
            if (dwIndex < pMap->dwCount)
            {
                // Already there - some other thread must have added it
                RETURN pMap->GetIndexPtr(dwIndex);
            }

            dwBlockSize *= 2;

            dwIndex -= pMap->dwCount;

            pPrev = pMap;
            pMap = pMap->pNext;
        } while (pMap != NULL);

        _ASSERTE(pPrev != NULL); // should never happen, because there's always at least one map

        DWORD dwSizeToAllocate = max(dwIndex + 1, dwBlockSize);

        pNewMap = (LookupMapBase *) (void*)pModule->GetLoaderAllocator()->GetLowFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(LookupMapBase)) + S_SIZE_T(dwSizeToAllocate)*S_SIZE_T(sizeof(TADDR)));

        // Note: Memory allocated on loader heap is zero filled
        // memset(pNewMap, 0, sizeof(LookupMap) + dwSizeToAllocate*sizeof(void*));

        pNewMap->pNext          = NULL;
        pNewMap->dwCount        = dwSizeToAllocate;

        pNewMap->pTable         = dac_cast<ArrayDPTR(TADDR)>(pNewMap + 1);

        // Link ourselves in
        VolatileStore<LookupMapBase*>(&(pPrev->pNext), pNewMap);
    }

    RETURN pNewMap->GetIndexPtr(dwIndex);
}

#endif // DACCESS_COMPILE

PTR_TADDR LookupMapBase::GetElementPtr(DWORD rid)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    LookupMapBase * pMap = this;

    DWORD dwIndex = rid;
    do
    {
        if (dwIndex < pMap->dwCount)
        {
            return pMap->GetIndexPtr(dwIndex);
        }

        dwIndex -= pMap->dwCount;
        pMap = pMap->pNext;
    } while (pMap != NULL);

    return NULL;
}


// Get number of RIDs that this table can store
DWORD LookupMapBase::GetSize()
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    LookupMapBase * pMap = this;
    DWORD dwSize = 0;
    do
    {
        dwSize += pMap->dwCount;
        pMap = pMap->pNext;
    } while (pMap != NULL);

    return dwSize;
}

#ifndef DACCESS_COMPILE

#ifdef _DEBUG
void LookupMapBase::DebugGetRidMapOccupancy(DWORD *pdwOccupied, DWORD *pdwSize)
{
    LIMITED_METHOD_CONTRACT;

    *pdwOccupied = 0;
    *pdwSize     = 0;

    LookupMapBase * pMap = this;

    // Go through each linked block
    for (; pMap != NULL; pMap = pMap->pNext)
    {
        DWORD dwIterCount = pMap->dwCount;

        for (DWORD i = 0; i < dwIterCount; i++)
        {
            if (pMap->pTable[i] != 0)
                (*pdwOccupied)++;
        }

        (*pdwSize) += dwIterCount;
    }
}

void Module::DebugLogRidMapOccupancy()
{
    WRAPPER_NO_CONTRACT;

#define COMPUTE_RID_MAP_OCCUPANCY(var_suffix, map)                                        \
    DWORD dwOccupied##var_suffix, dwSize##var_suffix, dwPercent##var_suffix;              \
    map.DebugGetRidMapOccupancy(&dwOccupied##var_suffix, &dwSize##var_suffix);            \
    dwPercent##var_suffix = dwOccupied##var_suffix ? ((dwOccupied##var_suffix * 100) / dwSize##var_suffix) : 0;

    COMPUTE_RID_MAP_OCCUPANCY(1, m_TypeDefToMethodTableMap);
    COMPUTE_RID_MAP_OCCUPANCY(2, m_TypeRefToMethodTableMap);
    COMPUTE_RID_MAP_OCCUPANCY(3, m_MethodDefToDescMap);
    COMPUTE_RID_MAP_OCCUPANCY(4, m_FieldDefToDescMap);
    COMPUTE_RID_MAP_OCCUPANCY(5, m_GenericParamToDescMap);
    COMPUTE_RID_MAP_OCCUPANCY(6, m_ManifestModuleReferencesMap);

    LOG((
        LF_EEMEM,
        INFO3,
        "   Map occupancy:\n"
        "      TypeDefToMethodTable map: %4d/%4d (%2d %%)\n"
        "      TypeRefToMethodTable map: %4d/%4d (%2d %%)\n"
        "      MethodDefToDesc map:  %4d/%4d (%2d %%)\n"
        "      FieldDefToDesc map:  %4d/%4d (%2d %%)\n"
        "      GenericParamToDesc map:  %4d/%4d (%2d %%)\n"
        "      AssemblyReferences map:  %4d/%4d (%2d %%)\n"
        ,
        dwOccupied1, dwSize1, dwPercent1,
        dwOccupied2, dwSize2, dwPercent2,
        dwOccupied3, dwSize3, dwPercent3,
        dwOccupied4, dwSize4, dwPercent4,
        dwOccupied5, dwSize5, dwPercent5,
        dwOccupied6, dwSize6, dwPercent6
    ));

#undef COMPUTE_RID_MAP_OCCUPANCY
}
#endif // _DEBUG

//
// FindMethod finds a MethodDesc for a global function methoddef or ref
//

MethodDesc *Module::FindMethodThrowing(mdToken pMethod)
{
    CONTRACT (MethodDesc *)
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL));
    }
    CONTRACT_END

    SigTypeContext typeContext;  /* empty type context: methods will not be generic */
    RETURN MemberLoader::GetMethodDescFromMemberDefOrRefOrSpec(this, pMethod,
                                                               &typeContext,
                                                               TRUE, /* strictMetadataChecks */
                                                               FALSE /* dont get code shared between generic instantiations */);
}

//
// FindMethod finds a MethodDesc for a global function methoddef or ref
//

MethodDesc *Module::FindMethod(mdToken pMethod)
{
    CONTRACT (MethodDesc *) {
        INSTANCE_CHECK;
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
    } CONTRACT_END;

    MethodDesc *pMDRet = NULL;

    EX_TRY
    {
        pMDRet = FindMethodThrowing(pMethod);
    }
    EX_CATCH
    {
#ifdef _DEBUG
        CONTRACT_VIOLATION(ThrowsViolation);
        char szMethodName [MAX_CLASSNAME_LENGTH];
        CEEInfo::findNameOfToken(this, pMethod, szMethodName, ARRAY_SIZE(szMethodName));
        // This used to be IJW, but changed to LW_INTEROP to reclaim a bit in our log facilities
        LOG((LF_INTEROP, LL_INFO10, "Failed to find Method: %s for Vtable Fixup\n", szMethodName));
#endif // _DEBUG
    }
    EX_END_CATCH

    RETURN pMDRet;
}

// Return true if this module has any live (jitted) JMC functions.
// If a module has no jitted JMC functions, then it's as if it's a
// non-user module.
bool Module::HasAnyJMCFunctions()
{
    LIMITED_METHOD_CONTRACT;

    // If we have any live JMC funcs in us, then we're a JMC module.
    // We count JMC functions when we either explicitly toggle their status
    // or when we get the code:DebuggerMethodInfo for them (which happens in a jit-complete).
    // Since we don't get the jit-completes for ngen modules, we also check the module's
    // "default" status. This means we may err on the side of believing we have
    // JMC methods.
    return ((m_debuggerSpecificData.m_cTotalJMCFuncs > 0) || m_debuggerSpecificData.m_fDefaultJMCStatus);
}

// Alter our module's count of JMC functions.
// Since these may be called on multiple threads (say 2 threads are jitting
// methods within a module), make it thread safe.
void Module::IncJMCFuncCount()
{
    LIMITED_METHOD_CONTRACT;

    InterlockedIncrement(&m_debuggerSpecificData.m_cTotalJMCFuncs);
}

void Module::DecJMCFuncCount()
{
    LIMITED_METHOD_CONTRACT;

    InterlockedDecrement(&m_debuggerSpecificData.m_cTotalJMCFuncs);
}

// code:DebuggerMethodInfo are lazily created. Let them lookup what the default is.
bool Module::GetJMCStatus()
{
    LIMITED_METHOD_CONTRACT;

    return m_debuggerSpecificData.m_fDefaultJMCStatus;
}

// Set the default JMC status of this module.
void Module::SetJMCStatus(bool fStatus)
{
    LIMITED_METHOD_CONTRACT;

    m_debuggerSpecificData.m_fDefaultJMCStatus = fStatus;
}

// Update the dynamic metadata if needed. Nop for non-dynamic modules
void Module::UpdateDynamicMetadataIfNeeded()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
    }
    CONTRACTL_END;

    // Only need to serializing metadata for dynamic modules. For non-dynamic modules, metadata is already available.
    if (!IsReflectionEmit())
    {
        return;
    }

    // Since serializing metadata to an auxiliary buffer is only needed by the debugger,
    // we should only be doing this for modules that the debugger can see.
    if (!IsVisibleToDebugger())
    {
        return;
    }


    HRESULT hr = S_OK;
    EX_TRY
    {
        GetReflectionModule()->CaptureModuleMetaDataToMemory();
    }
    EX_CATCH_HRESULT(hr);

    // This Metadata buffer is only used for the debugger, so it's a non-fatal exception for regular CLR execution.
    // Just swallow it and keep going. However, with the exception of out-of-memory, we do expect it to
    // succeed, so assert on failures.
    if (hr != E_OUTOFMEMORY)
    {
        SIMPLIFYING_ASSUMPTION_SUCCEEDED(hr);
    }

}

#ifdef DEBUGGING_SUPPORTED


#endif // DEBUGGING_SUPPORTED

BOOL Module::NotifyDebuggerLoad(DomainAssembly * pDomainAssembly, int flags, BOOL attaching)
{
    WRAPPER_NO_CONTRACT;

    // We don't notify the debugger about modules that don't contain any code.
    if (!IsVisibleToDebugger())
        return FALSE;

    // Always capture metadata, even if no debugger is attached. If a debugger later attaches, it will use
    // this data.
    {
        Module * pModule = pDomainAssembly->GetAssembly()->GetModule();
        pModule->UpdateDynamicMetadataIfNeeded();
    }

    //
    // Remaining work is only needed if a debugger is attached
    //
    AppDomain* pDomain = AppDomain::GetCurrentDomain();
    if (!attaching && !pDomain->IsDebuggerAttached())
        return FALSE;


    BOOL result = FALSE;

    if (flags & ATTACH_MODULE_LOAD)
    {
        g_pDebugInterface->LoadModule(this,
                                      m_pPEAssembly->GetPath(),
                                      m_pPEAssembly->GetPath().GetCount(),
                                      GetAssembly(),
                                      pDomainAssembly,
                                      attaching);

        result = TRUE;
    }

    if (flags & ATTACH_CLASS_LOAD)
    {
        LookupMap<PTR_MethodTable>::Iterator typeDefIter(&m_TypeDefToMethodTableMap);
        while (typeDefIter.Next())
        {
            MethodTable * pMT = typeDefIter.GetElement();
            if (pMT != NULL)
            {
                result = TypeHandle(pMT).NotifyDebuggerLoad(attaching) || result;
            }
        }
    }

    return result;
}

void Module::NotifyDebuggerUnload()
{
    LIMITED_METHOD_CONTRACT;

    AppDomain* pDomain = AppDomain::GetCurrentDomain();
    if (!pDomain->IsDebuggerAttached())
        return;

    // We don't notify the debugger about modules that don't contain any code.
    if (!IsVisibleToDebugger())
        return;

    LookupMap<PTR_MethodTable>::Iterator typeDefIter(&m_TypeDefToMethodTableMap);
    while (typeDefIter.Next())
    {
        MethodTable * pMT = typeDefIter.GetElement();
        if (pMT != NULL)
        {
            TypeHandle(pMT).NotifyDebuggerUnload();
        }
    }

    g_pDebugInterface->UnloadModule(this);
}

using GetTokenForVTableEntry_t = mdToken(STDMETHODCALLTYPE*)(HMODULE module, BYTE**ppVTEntry);

static HMODULE GetIJWHostForModule(Module* module)
{
#if !defined(TARGET_UNIX)
    PEDecoder* pe = module->GetPEAssembly()->GetLoadedLayout();

    BYTE* baseAddress = (BYTE*)module->GetPEAssembly()->GetIJWBase();

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)pe->GetDirectoryData(pe->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT));

    if (importDescriptor == nullptr)
    {
        return nullptr;
    }

    for(; importDescriptor->Characteristics != 0; importDescriptor++)
    {
        IMAGE_THUNK_DATA* importNameTable = (IMAGE_THUNK_DATA*)pe->GetRvaData(importDescriptor->OriginalFirstThunk);

        IMAGE_THUNK_DATA* importAddressTable = (IMAGE_THUNK_DATA*)pe->GetRvaData(importDescriptor->FirstThunk);

        for (int thunkIndex = 0; importNameTable[thunkIndex].u1.AddressOfData != 0; thunkIndex++)
        {
            // The most significant bit will be set if the entry points to an ordinal.
            if ((importNameTable[thunkIndex].u1.Ordinal & (1LL << (sizeof(importNameTable[thunkIndex].u1.Ordinal) * CHAR_BIT - 1))) == 0)
            {
                IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(baseAddress + importNameTable[thunkIndex].u1.AddressOfData);
                if (strcmp("_CorDllMain", nameImport->Name) == 0
#ifdef TARGET_X86
                    || strcmp("__CorDllMain@12", nameImport->Name) == 0 // The MSVC compiler can and will bind to the stdcall-decorated name of _CorDllMain if it exists, even if the _CorDllMain symbol also exists.
#endif
                )
                {
                    HMODULE ijwHost;

                    if (GetModuleHandleEx(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCWSTR)importAddressTable[thunkIndex].u1.Function,
                        &ijwHost))
                    {
                        return ijwHost;
                    }

                }
            }
        }
    }
#endif
    return nullptr;
}

static GetTokenForVTableEntry_t GetTokenGetterFromHostModule(HMODULE ijwHost)
{
    if (ijwHost != nullptr)
    {
        return (GetTokenForVTableEntry_t)GetProcAddress(ijwHost, "GetTokenForVTableEntry");
    }

    return nullptr;
}

//=================================================================================
mdToken GetTokenForVTableEntry(HINSTANCE hInst, BYTE **ppVTEntry)
{
    CONTRACTL{
        NOTHROW;
    } CONTRACTL_END;

    mdToken tok =(mdToken)(UINT_PTR)*ppVTEntry;
    _ASSERTE(TypeFromToken(tok) == mdtMethodDef || TypeFromToken(tok) == mdtMemberRef);
    return tok;
}

//=================================================================================
void SetTargetForVTableEntry(HINSTANCE hInst, BYTE **ppVTEntry, BYTE *pTarget)
{
    CONTRACTL{
        THROWS;
    } CONTRACTL_END;

    DWORD oldProtect;
    if (!ClrVirtualProtect(ppVTEntry, sizeof(BYTE*), PAGE_READWRITE, &oldProtect))
    {
        // This is very bad.  We are not going to be able to update header.
        _ASSERTE(!"SetTargetForVTableEntry(): VirtualProtect() changing IJW thunk vtable to R/W failed.\n");
        ThrowLastError();
    }

    *ppVTEntry = pTarget;

    DWORD ignore;
    if (!ClrVirtualProtect(ppVTEntry, sizeof(BYTE*), oldProtect, &ignore))
    {
        // This is not so bad, we're already done the update, we just didn't return the thunk table to read only
        _ASSERTE(!"SetTargetForVTableEntry(): VirtualProtect() changing IJW thunk vtable back to RO failed.\n");
    }
}

//=================================================================================
BYTE * GetTargetForVTableEntry(HINSTANCE hInst, BYTE **ppVTEntry)
{
    CONTRACTL{
        NOTHROW;
    } CONTRACTL_END;

    return *ppVTEntry;
}

//======================================================================================
// Fixup vtables stored in the header to contain pointers to method desc
// prestubs rather than metadata method tokens.
void Module::FixupVTables()
{
    CONTRACTL{
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
    } CONTRACTL_END;


    // If we've already fixed up, or this is not an IJW module, just return.
    // NOTE: This relies on ILOnly files not having fixups. If this changes,
    //       we need to change this conditional.
    if (IsIJWFixedUp() || m_pPEAssembly->IsILOnly()) {
        return;
    }

    // Try getting a callback to the IJW host if it is loaded.
    // The IJW host substitutes in special shims in the vtfixup table
    // so if it is loaded, we need to query it for the tokens that were in the slots.
    // If it is not loaded, then we know that the vtfixup table entries are tokens,
    // so we can resolve them ourselves.
    GetTokenForVTableEntry_t GetTokenForVTableEntryCallback = GetTokenGetterFromHostModule(GetIJWHostForModule(this));

    if (GetTokenForVTableEntryCallback == nullptr)
    {
        GetTokenForVTableEntryCallback = GetTokenForVTableEntry;
    }

    HINSTANCE hInstThis = GetPEAssembly()->GetIJWBase();

    // Get vtable fixup data
    COUNT_T cFixupRecords;
    IMAGE_COR_VTABLEFIXUP *pFixupTable = m_pPEAssembly->GetVTableFixups(&cFixupRecords);

    // No records then return
    if (cFixupRecords == 0) {
        return;
    }

    // Now, we need to take a lock to serialize fixup.
    PEImage::IJWFixupData *pData = PEImage::GetIJWData(m_pPEAssembly->GetIJWBase());

    // If it's already been fixed (in some other appdomain), record the fact and return
    if (pData->IsFixedUp()) {
        SetIsIJWFixedUp();
        return;
    }

    //////////////////////////////////////////////////////
    //
    // This is done in three stages:
    //  1. We enumerate the types we'll need to load
    //  2. We load the types
    //  3. We create and install the thunks
    //

    COUNT_T cVtableThunks = 0;
    struct MethodLoadData
    {
        mdToken     token;
        MethodDesc *pMD;
    };
    MethodLoadData *rgMethodsToLoad = NULL;
    COUNT_T cMethodsToLoad = 0;

    //
    // Stage 1
    //

    // Each fixup entry describes a vtable, so iterate the vtables and sum their counts
    {
        DWORD iFixup;
        for (iFixup = 0; iFixup < cFixupRecords; iFixup++)
            cVtableThunks += pFixupTable[iFixup].Count;
    }

    ACQUIRE_STACKING_ALLOCATOR(pAlloc);

    // Allocate the working array of tokens.
    cMethodsToLoad = cVtableThunks;

    rgMethodsToLoad = new (pAlloc) MethodLoadData[cMethodsToLoad];
    memset(rgMethodsToLoad, 0, cMethodsToLoad * sizeof(MethodLoadData));

    // Now take the IJW module lock and get all the tokens
    {
        // Take the lock
        CrstHolder lockHolder(pData->GetLock());

        // If someone has beaten us, just return
        if (pData->IsFixedUp())
        {
            SetIsIJWFixedUp();
            return;
        }

        COUNT_T iCurMethod = 0;

        if (cFixupRecords != 0)
        {
            for (COUNT_T iFixup = 0; iFixup < cFixupRecords; iFixup++)
            {
                // Vtables can be 32 or 64 bit.
                if ((pFixupTable[iFixup].Type == (COR_VTABLE_PTRSIZED)) ||
                    (pFixupTable[iFixup].Type == (COR_VTABLE_PTRSIZED | COR_VTABLE_FROM_UNMANAGED)) ||
                    (pFixupTable[iFixup].Type == (COR_VTABLE_PTRSIZED | COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN)))
                {
                    const BYTE** pPointers = (const BYTE **)m_pPEAssembly->GetVTable(pFixupTable[iFixup].RVA);
                    for (int iMethod = 0; iMethod < pFixupTable[iFixup].Count; iMethod++)
                    {
                        if (pData->IsMethodFixedUp(iFixup, iMethod))
                            continue;
                        mdToken mdTok = GetTokenForVTableEntryCallback(hInstThis, (BYTE**)(pPointers + iMethod));
                        CONSISTENCY_CHECK(mdTok != mdTokenNil);
                        rgMethodsToLoad[iCurMethod++].token = mdTok;
                    }
                }
            }
        }

    }

    //
    // Stage 2 - Load the types
    //

    {
        for (COUNT_T iCurMethod = 0; iCurMethod < cMethodsToLoad; iCurMethod++)
        {
            mdToken curTok = rgMethodsToLoad[iCurMethod].token;
            if (!GetMDImport()->IsValidToken(curTok))
            {
                _ASSERTE(!"Invalid token in v-table fix-up table");
                ThrowHR(COR_E_BADIMAGEFORMAT);
            }


            // Find the method desc
            MethodDesc *pMD;

            {
                CONTRACT_VIOLATION(LoadsTypeViolation);
                pMD = FindMethodThrowing(curTok);
            }

            CONSISTENCY_CHECK(CheckPointer(pMD));

            rgMethodsToLoad[iCurMethod].pMD = pMD;
        }
    }

    //
    // Stage 3 - Create the thunk data
    //
    {
        // Take the lock
        CrstHolder lockHolder(pData->GetLock());

        // If someone has beaten us, just return
        if (pData->IsFixedUp())
        {
            SetIsIJWFixedUp();
            return;
        }

        // This phase assumes there is only one AppDomain and that thunks
        // can all safely point directly to the method in the current AppDomain

        AppDomain *pAppDomain = GetAppDomain();

        // Used to index into rgMethodsToLoad
        COUNT_T iCurMethod = 0;


        // Each fixup entry describes a vtable (each slot contains a metadata token
        // at this stage).
        DWORD iFixup;
        for (iFixup = 0; iFixup < cFixupRecords; iFixup++)
            cVtableThunks += pFixupTable[iFixup].Count;

        DWORD dwIndex = 0;
        DWORD dwThunkIndex = 0;

        // Now to fill in the thunk table.
        for (iFixup = 0; iFixup < cFixupRecords; iFixup++)
        {
            // Tables may contain zero fixups, in which case the RVA is null, which triggers an assert
            if (pFixupTable[iFixup].Count == 0)
                continue;

            const BYTE** pPointers = (const BYTE **)
                m_pPEAssembly->GetVTable(pFixupTable[iFixup].RVA);

            // Vtables can be 32 or 64 bit.
            if (pFixupTable[iFixup].Type == COR_VTABLE_PTRSIZED)
            {
                for (int iMethod = 0; iMethod < pFixupTable[iFixup].Count; iMethod++)
                {
                    if (pData->IsMethodFixedUp(iFixup, iMethod))
                        continue;

                    mdToken mdTok = rgMethodsToLoad[iCurMethod].token;
                    MethodDesc *pMD = rgMethodsToLoad[iCurMethod].pMD;
                    iCurMethod++;

#ifdef _DEBUG
                    if (pMD->IsPInvoke())
                    {
                        LOG((LF_INTEROP, LL_INFO10, "[0x%lx] <-- PINV thunk for \"%s\" (target = 0x%lx)\n",
                            (size_t)&(pPointers[iMethod]), pMD->m_pszDebugMethodName,
                            (size_t)(((PInvokeMethodDesc*)pMD)->GetPInvokeTarget())));
                    }
#endif // _DEBUG

                    CONSISTENCY_CHECK(dwThunkIndex < cVtableThunks);

                    // Point the local vtable slot to the thunk we created
                    SetTargetForVTableEntry(hInstThis, (BYTE **)&pPointers[iMethod], (BYTE *)pMD->GetMultiCallableAddrOfCode());

                    pData->MarkMethodFixedUp(iFixup, iMethod);

                    dwThunkIndex++;
                }

            }
            else if (pFixupTable[iFixup].Type == (COR_VTABLE_PTRSIZED | COR_VTABLE_FROM_UNMANAGED) ||
                    (pFixupTable[iFixup].Type == (COR_VTABLE_PTRSIZED | COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN)))
            {
                for (int iMethod = 0; iMethod < pFixupTable[iFixup].Count; iMethod++)
                {
                    if (pData->IsMethodFixedUp(iFixup, iMethod))
                        continue;

                    mdToken mdTok = rgMethodsToLoad[iCurMethod].token;
                    MethodDesc *pMD = rgMethodsToLoad[iCurMethod].pMD;
                    iCurMethod++;
                    LOG((LF_INTEROP, LL_INFO10, "[0x%p] <-- VTable  thunk for \"%s\" (pMD = 0x%p)\n",
                        (UINT_PTR)&(pPointers[iMethod]), pMD->m_pszDebugMethodName, pMD));

                    UMEntryThunkData *pUMEntryThunkData = UMEntryThunkData::CreateUMEntryThunk();

                    UMThunkMarshInfo *pUMThunkMarshInfo = (UMThunkMarshInfo*)(void*)(SystemDomain::GetGlobalLoaderAllocator()->GetLowFrequencyHeap()->AllocAlignedMem(sizeof(UMThunkMarshInfo), CODE_SIZE_ALIGN));

                    pUMThunkMarshInfo->LoadTimeInit(pMD);
                    pUMEntryThunkData->LoadTimeInit((PCODE)0, NULL, pUMThunkMarshInfo, pMD);

                    SetTargetForVTableEntry(hInstThis, (BYTE **)&pPointers[iMethod], (BYTE *)pUMEntryThunkData->GetCode());

                    pData->MarkMethodFixedUp(iFixup, iMethod);
                }
            }
            else if ((pFixupTable[iFixup].Type & COR_VTABLE_NOT_PTRSIZED) == COR_VTABLE_NOT_PTRSIZED)
            {
                // fixup type doesn't match the platform
                THROW_BAD_FORMAT(BFA_FIXUP_WRONG_PLATFORM, this);
            }
            else
            {
                _ASSERTE(!"Unknown vtable fixup type");
            }
        }

        // Indicate that this module has been fixed before releasing the lock
        pData->SetIsFixedUp();  // On the data
        SetIsIJWFixedUp();      // On the module
    } // End of Stage 3
}

ModuleBase *Module::GetModuleFromIndex(DWORD ix)
{
    CONTRACT(ModuleBase*)
    {
        INSTANCE_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
    }
    CONTRACT_END;

    if (IsReadyToRun())
    {
        RETURN ZapSig::DecodeModuleFromIndex(this, ix);
    }
    else
    {
        mdAssemblyRef mdAssemblyRefToken = TokenFromRid(ix, mdtAssemblyRef);
        Assembly *pAssembly = this->LookupAssemblyRef(mdAssemblyRefToken);
        if (pAssembly)
        {
            RETURN pAssembly->GetModule();
        }
        else
        {
            // GetModuleFromIndex failed
            RETURN NULL;
        }
    }
}

#endif // !DACCESS_COMPILE

ModuleBase *Module::GetModuleFromIndexIfLoaded(DWORD ix)
{
    CONTRACT(ModuleBase*)
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        PRECONDITION(IsReadyToRun());
        POSTCONDITION(CheckPointer(RETVAL, NULL_OK));
    }
    CONTRACT_END;

#ifndef DACCESS_COMPILE
    RETURN ZapSig::DecodeModuleFromIndexIfLoaded(this, ix);
#else // DACCESS_COMPILE
    DacNotImpl();
    RETURN NULL;
#endif // DACCESS_COMPILE
}

#ifndef DACCESS_COMPILE
IMDInternalImport* Module::GetNativeAssemblyImport(BOOL loadAllowed)
{
    CONTRACT(IMDInternalImport*)
    {
        INSTANCE_CHECK;
        if (loadAllowed) GC_TRIGGERS;                    else GC_NOTRIGGER;
        if (loadAllowed) THROWS;                         else NOTHROW;
        if (loadAllowed) INJECT_FAULT(COMPlusThrowOM()); else FORBID_FAULT;
        MODE_ANY;
        PRECONDITION(IsReadyToRun());
        POSTCONDITION(loadAllowed ?
            CheckPointer(RETVAL) :
            CheckPointer(RETVAL, NULL_OK));
    }
    CONTRACT_END;

    RETURN GetReadyToRunInfo()->GetNativeManifestModule()->GetMDImport();
}

BYTE* Module::GetNativeFixupBlobData(RVA rva)
{
    CONTRACT(BYTE*)
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        POSTCONDITION(CheckPointer(RETVAL));
    }
    CONTRACT_END;

    RETURN(BYTE*) GetReadyToRunImage()->GetRvaData(rva);
}
#endif // DACCESS_COMPILE

#ifndef DACCESS_COMPILE
//-----------------------------------------------------------------------------

void Module::RunEagerFixups()
{
    STANDARD_VM_CONTRACT;

    COUNT_T nSections;
    PTR_READYTORUN_IMPORT_SECTION pSections = GetImportSections(&nSections);

    if (nSections == 0)
        return;

#ifdef _DEBUG
    // Loading types during eager fixup is not a tested scenario. Make bugs out of any attempts to do so in a
    // debug build. Use holder to recover properly in case of exception. We make a narrow exception for
    // System.Private.CoreLib so we can lazily load JIT helpers written in managed code.
    class ForbidTypeLoadHolder
    {
        BOOL _isCoreLib;
    public:
        ForbidTypeLoadHolder(BOOL isCoreLib)
            : _isCoreLib{ isCoreLib }
        {
            if (!_isCoreLib)
                BEGIN_FORBID_TYPELOAD();
        }

        ~ForbidTypeLoadHolder()
        {
            if (!_isCoreLib)
                END_FORBID_TYPELOAD();
        }
    }
    forbidTypeLoad{ GetPEAssembly()->GetHostAssembly()->GetAssemblyName()->IsCoreLib() };
#endif

    // TODO: Verify that eager fixup dependency graphs can contain no cycles
    OVERRIDE_TYPE_LOAD_LEVEL_LIMIT(CLASS_LOADED);

    NativeImage *compositeNativeImage = GetCompositeNativeImage();
    if (compositeNativeImage != NULL)
    {
        // For composite images, multiple modules may request initializing eager fixups
        // from multiple threads so we need to lock their resolution.
        CrstHolder compositeEagerFixups(compositeNativeImage->EagerFixupsLock());
        if (compositeNativeImage->EagerFixupsHaveRun())
        {
            if (compositeNativeImage->ReadyToRunCodeDisabled())
                GetReadyToRunInfo()->DisableAllR2RCode();
            return;
        }
        RunEagerFixupsUnlocked();
        if (GetReadyToRunInfo()->ReadyToRunCodeDisabled())
            compositeNativeImage->DisableAllR2RCode();
        compositeNativeImage->SetEagerFixupsHaveRun();
    }
    else
    {
        // Per-module eager fixups don't need locking
        RunEagerFixupsUnlocked();
    }
}

void Module::RunEagerFixupsUnlocked()
{
    COUNT_T nSections;
    PTR_READYTORUN_IMPORT_SECTION pSections = GetImportSections(&nSections);
    PEImageLayout *pNativeImage = GetReadyToRunImage();

    for (COUNT_T iSection = 0; iSection < nSections; iSection++)
    {
        PTR_READYTORUN_IMPORT_SECTION pSection = pSections + iSection;

        if ((pSection->Flags & ReadyToRunImportSectionFlags::Eager) != ReadyToRunImportSectionFlags::Eager)
            continue;

        COUNT_T tableSize;
        TADDR tableBase = pNativeImage->GetDirectoryData(&pSection->Section, &tableSize);

        PTR_DWORD pSignatures = dac_cast<PTR_DWORD>(pNativeImage->GetRvaData(pSection->Signatures));

        for (SIZE_T * fixupCell = (SIZE_T *)tableBase; fixupCell < (SIZE_T *)(tableBase + tableSize); fixupCell++)
        {
            SIZE_T fixupIndex = fixupCell - (SIZE_T *)tableBase;
            if (!LoadDynamicInfoEntry(this, pSignatures[fixupIndex], fixupCell))
            {
                _ASSERTE(IsReadyToRun());
                GetReadyToRunInfo()->DisableAllR2RCode();
            }
            else
            {
                _ASSERTE(*fixupCell != 0);
            }
        }
    }

    TADDR base = dac_cast<TADDR>(pNativeImage->GetBase());

    ExecutionManager::AddCodeRange(
        base, base + (TADDR)pNativeImage->GetVirtualSize(),
        ExecutionManager::GetReadyToRunJitManager(),
        RangeSection::RANGE_SECTION_NONE,
        this /* pHeapListOrZapModule */);
}
#endif // !DACCESS_COMPILE

#ifndef DACCESS_COMPILE

//-----------------------------------------------------------------------------

BOOL Module::FixupNativeEntry(READYTORUN_IMPORT_SECTION* pSection, SIZE_T fixupIndex, SIZE_T* fixupCell, BOOL mayUsePrecompiledPInvokeMethods)
{
    CONTRACTL
    {
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(fixupCell));
    }
    CONTRACTL_END;

    // Ensure that the compiler won't fetch the value twice
    SIZE_T fixup = VolatileLoadWithoutBarrier(fixupCell);

    if (fixup == 0)
    {
        PTR_DWORD pSignatures = dac_cast<PTR_DWORD>(GetReadyToRunImage()->GetRvaData(pSection->Signatures));

        if (!LoadDynamicInfoEntry(this, pSignatures[fixupIndex], fixupCell, mayUsePrecompiledPInvokeMethods))
            return FALSE;

        _ASSERTE(*fixupCell != 0);
    }

    return TRUE;
}

static LPCWSTR s_pCommandLine = NULL;

// Retrieve the full command line for the current process.
LPCWSTR GetManagedCommandLine()
{
    LIMITED_METHOD_CONTRACT;
    return s_pCommandLine;
}

LPCWSTR GetCommandLineForDiagnostics()
{
    // Get the managed command line.
    LPCWSTR pCmdLine = GetManagedCommandLine();

    // Checkout https://github.com/dotnet/coreclr/pull/24433 for more information about this fall back.
    if (pCmdLine == nullptr)
    {
        // Use the result from GetCommandLineW() instead
        pCmdLine = GetCommandLineW();
    }

    return pCmdLine;
}

void Append_Next_Item(LPWSTR* ppCursor, SIZE_T* pRemainingLen, LPCWSTR pItem, bool addSpace)
{
    // read the writeback args and setup pCursor and remainingLen
    LPWSTR pCursor      = *ppCursor;
    SIZE_T remainingLen = *pRemainingLen;

    // Calculate the length of pItem
    SIZE_T itemLen = u16_strlen(pItem);

    // Append pItem at pCursor
    wcscpy_s(pCursor, remainingLen, pItem);
    pCursor      += itemLen;
    remainingLen -= itemLen;

    // Also append a space after pItem, if requested
    if (addSpace)
    {
        // Append a space at pCursor
        wcscpy_s(pCursor, remainingLen, W(" "));
        pCursor      += 1;
        remainingLen -= 1;
    }

    // writeback and update ppCursor and pRemainingLen
    *ppCursor      = pCursor;
    *pRemainingLen = remainingLen;
}

void SaveManagedCommandLine(LPCWSTR pwzAssemblyPath, int argc, LPCWSTR *argv)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END;

    // Get the command line.
    LPCWSTR osCommandLine = GetCommandLineW();

#ifndef TARGET_UNIX
    // On Windows, osCommandLine contains the executable and all arguments.
    s_pCommandLine = osCommandLine;
#else
    // On UNIX, the PAL doesn't have the command line arguments, so we must build the command line.
    // osCommandLine contains the full path to the executable.
    SIZE_T  commandLineLen = (u16_strlen(osCommandLine) + 1);

    // We will append pwzAssemblyPath to the 'corerun' osCommandLine
    commandLineLen += (u16_strlen(pwzAssemblyPath) + 1);

    for (int i = 0; i < argc; i++)
    {
        commandLineLen += (u16_strlen(argv[i]) + 1);
    }
    commandLineLen++;  // Add 1 for the null-termination

    // Allocate a new string for the command line.
    LPWSTR pNewCommandLine = new WCHAR[commandLineLen];
    SIZE_T remainingLen    = commandLineLen;
    LPWSTR pCursor         = pNewCommandLine;

    Append_Next_Item(&pCursor, &remainingLen, osCommandLine,   true);
    Append_Next_Item(&pCursor, &remainingLen, pwzAssemblyPath, (argc > 0));

    for (int i = 0; i < argc; i++)
    {
        bool moreArgs = (i < (argc-1));
        Append_Next_Item(&pCursor, &remainingLen, argv[i], moreArgs);
    }

    s_pCommandLine = pNewCommandLine;
#endif
}

void Module::SetIsIJWFixedUp()
{
    LIMITED_METHOD_CONTRACT;
    InterlockedOr((LONG*)&m_dwTransientFlags, IS_IJW_FIXED_UP);
}
#endif // !DACCESS_COMPILE

#ifndef DACCESS_COMPILE
void Module::SetBeingUnloaded()
{
    LIMITED_METHOD_CONTRACT;
    InterlockedOr((LONG*)&m_dwTransientFlags, IS_BEING_UNLOADED);
}

// ===========================================================================
// ReflectionModule
// ===========================================================================

/* static */
ReflectionModule *ReflectionModule::Create(Assembly *pAssembly, PEAssembly *pPEAssembly, AllocMemTracker *pamTracker, LPCWSTR szName)
{
    CONTRACT(ReflectionModule *)
    {
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(pAssembly));
        PRECONDITION(CheckPointer(pPEAssembly));
        PRECONDITION(pPEAssembly->IsReflectionEmit());
        POSTCONDITION(CheckPointer(RETVAL));
    }
    CONTRACT_END;

    // Hoist CONTRACT into separate routine because of EX incompatibility

    // Initial memory block for Modules must be zero-initialized (to make it harder
    // to introduce Destruct crashes arising from OOM's during initialization.)

    void* pMemory = pamTracker->Track(pAssembly->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(sizeof(ReflectionModule))));
    ReflectionModuleHolder pModule(new (pMemory) ReflectionModule(pAssembly, pPEAssembly));

    pModule->DoInit(pamTracker, szName);
    pModule->SetIsRuntimeWrapExceptionsCached_ForReflectionEmitModules();

    RETURN pModule.Extract();
}


// Module initialization occurs in two phases: the constructor phase and the Initialize phase.
//
// The constructor phase initializes just enough so that Destruct() can be safely called.
// It cannot throw or fail.
//
ReflectionModule::ReflectionModule(Assembly *pAssembly, PEAssembly *pPEAssembly)
  : Module(pAssembly, pPEAssembly)
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        FORBID_FAULT;
    }
    CONTRACTL_END

    m_pInMemoryWriter = NULL;
    m_sdataSection = NULL;
    m_pCeeFileGen = NULL;
}

HRESULT STDMETHODCALLTYPE CreateICeeGen(REFIID riid, void **pCeeGen);

// Module initialization occurs in two phases: the constructor phase and the Initialize phase.
//
// The Initialize() phase completes the initialization after the constructor has run.
// It can throw exceptions but whether it throws or succeeds, it must leave the Module
// in a state where Destruct() can be safely called.
//
void ReflectionModule::Initialize(AllocMemTracker *pamTracker, LPCWSTR szName)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
        PRECONDITION(szName != NULL);
    }
    CONTRACTL_END;

    Module::Initialize(pamTracker);

    IfFailThrow(CreateICeeGen(IID_ICeeGenInternal, (void **)&m_pCeeFileGen));

    // Collectible modules should try to limit the growth of their associate IL section, as common scenarios for collectible
    // modules include single type modules
    if (IsCollectible())
    {
        ReleaseHolder<ICeeGenInternal> pCeeGenInternal(NULL);
        IfFailThrow(m_pCeeFileGen->QueryInterface(IID_ICeeGenInternal, (void **)&pCeeGenInternal));
        IfFailThrow(pCeeGenInternal->SetInitialGrowth(CEE_FILE_GEN_GROWTH_COLLECTIBLE));
    }

    m_pInMemoryWriter = new RefClassWriter();

    IfFailThrow(m_pInMemoryWriter->Init(GetCeeGen(), GetEmitter(), szName));

    m_CrstLeafLock.Init(CrstLeafLock);
}

void ReflectionModule::Destruct()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        MODE_PREEMPTIVE;
    }
    CONTRACTL_END;

    delete m_pInMemoryWriter;

    if (m_pCeeFileGen)
        m_pCeeFileGen->Release();

    Module::Destruct();

    delete (uint32_t*)m_pDynamicMetadata;
    m_pDynamicMetadata = (TADDR)NULL;

    m_CrstLeafLock.Destroy();
}

//
// Holder of changed value of MDUpdateMode via IMDInternalEmit::SetMDUpdateMode.
// Returns back the original value on release.
//
class MDUpdateModeHolder
{
public:
    MDUpdateModeHolder()
    {
        m_pInternalEmitter = NULL;
        m_OriginalMDUpdateMode = UINT32_MAX;
    }
    ~MDUpdateModeHolder()
    {
        WRAPPER_NO_CONTRACT;
        (void)Release();
    }
    HRESULT SetMDUpdateMode(IMetaDataEmit *pEmitter, ULONG updateMode)
    {
        LIMITED_METHOD_CONTRACT;
        HRESULT hr = S_OK;

        _ASSERTE(updateMode != UINT32_MAX);

        IfFailRet(pEmitter->QueryInterface(IID_IMDInternalEmit, (void **)&m_pInternalEmitter));
        _ASSERTE(m_pInternalEmitter != NULL);

        IfFailRet(m_pInternalEmitter->SetMDUpdateMode(updateMode, &m_OriginalMDUpdateMode));
        _ASSERTE(m_OriginalMDUpdateMode != UINT32_MAX);

        return hr;
    }
    HRESULT Release(ULONG expectedPreviousUpdateMode = UINT32_MAX)
    {
        HRESULT hr = S_OK;

        if (m_OriginalMDUpdateMode != UINT32_MAX)
        {
            _ASSERTE(m_pInternalEmitter != NULL);
            ULONG previousUpdateMode;
            // Ignore the error when releasing
            hr = m_pInternalEmitter->SetMDUpdateMode(m_OriginalMDUpdateMode, &previousUpdateMode);
            m_OriginalMDUpdateMode = UINT32_MAX;

            if (expectedPreviousUpdateMode != UINT32_MAX)
            {
                if ((hr == S_OK) && (expectedPreviousUpdateMode != previousUpdateMode))
                {
                    hr = S_FALSE;
                }
            }
        }
        if (m_pInternalEmitter != NULL)
        {
            (void)m_pInternalEmitter->Release();
            m_pInternalEmitter = NULL;
        }
        return hr;
    }
    ULONG GetOriginalMDUpdateMode()
    {
        WRAPPER_NO_CONTRACT;
        _ASSERTE(m_OriginalMDUpdateMode != UINT32_MAX);
        return m_OriginalMDUpdateMode;
    }
private:
    IMDInternalEmit *m_pInternalEmitter;
    ULONG            m_OriginalMDUpdateMode;
};

// Called in live paths to fetch metadata for dynamic modules. This makes the metadata available to the
// debugger from out-of-process.
//
// Notes:
//    This buffer can be retrieved by the debugger via code:ReflectionModule.GetDynamicMetadataBuffer
//
//    Threading:
//    - Callers must ensure nobody else is adding to the metadata.
//    - This function still takes its own locks to cooperate with the Debugger's out-of-process access.
//      The debugger can slip this thread outside the locks to ensure the data is consistent.
//
//    This does not raise a debug notification to invalidate the metadata. Reasoning is that this only
//    happens in one case: on each class load. In this case, we already send a class-load notification
//    debug event, so sending a separate "metadata-refresh" would make the eventing twice as chatty.
//    Class-load events are high-volume and events are slow. We can avoid the chattiness by ensuring
//    the debugger knows that Class-load also means "refresh metadata".
//
void ReflectionModule::CaptureModuleMetaDataToMemory()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
    }
    CONTRACTL_END;

    // Do not release the emitter. This is a weak reference.
    IMetaDataEmit *pEmitter = this->GetEmitter();
    _ASSERTE(pEmitter != NULL);

    HRESULT hr;

    MDUpdateModeHolder hMDUpdateMode;
    IfFailThrow(hMDUpdateMode.SetMDUpdateMode(pEmitter, MDUpdateExtension));
    _ASSERTE(hMDUpdateMode.GetOriginalMDUpdateMode() == MDUpdateFull);

    DWORD numBytes;
    hr = pEmitter->GetSaveSize(cssQuick, &numBytes);
    IfFailThrow(hr);

    // Operate on local data, and then persist it into the module once we know it's valid.
    NewArrayHolder<uint8_t> pBuffer(new uint8_t[numBytes + sizeof(DynamicMetadata)]);
    _ASSERTE(pBuffer != NULL); // allocation would throw first

    DynamicMetadata *pDynamicMetadata = (DynamicMetadata*)(uint8_t*)pBuffer;

    // ReflectionModule is still in a consistent state, and now we're just operating on local data to
    // assemble the new metadata buffer. If this fails, then worst case is that metadata does not include
    // recently generated classes.

    // Caller ensures serialization that guarantees that the metadata doesn't grow underneath us.
    BYTE * pRawData = &pDynamicMetadata->Data[0];
    hr = pEmitter->SaveToMemory(pRawData, numBytes);
    pDynamicMetadata->Size = numBytes;

    IfFailThrow(hr);

    // Now that we're successful, transfer ownership back into the module.
    {
        CrstHolder ch(&m_CrstLeafLock);

        delete (uint32_t*)m_pDynamicMetadata;

        m_pDynamicMetadata = (TADDR)pBuffer.Extract();
    }

    //

    hr = hMDUpdateMode.Release(MDUpdateExtension);
    // Will be S_FALSE if someone changed the MDUpdateMode (from MDUpdateExtension) meanwhile
    _ASSERTE(hr == S_OK);
}


#endif // !DACCESS_COMPILE

#ifdef DACCESS_COMPILE
// Accessor to expose m_pDynamicMetadata to debugger.
//
// Returns:
//    Pointer to SBuffer  containing metadata buffer. May be null.
//
// Notes:
//    Only used by the debugger, so only accessible via DAC.
//    The buffer is updated via code:ReflectionModule.CaptureModuleMetaDataToMemory
TADDR ReflectionModule::GetDynamicMetadataBuffer() const
{
    SUPPORTS_DAC;

    // If we ask for metadata, but have been suppressing capture, then we're out of date.
    // However, the debugger may be debugging already baked types in the module and so may need the metadata
    // for that. So we return what we do have.
    //
    // Debugger will get the next metadata update:
    // 1) with the next load class
    // 2) or if this is right after the last class, see code:ReflectionModule.CaptureModuleMetaDataToMemory

    return m_pDynamicMetadata;
}
#endif

TADDR ReflectionModule::GetIL(RVA il) // virtual
{
#ifndef DACCESS_COMPILE
    WRAPPER_NO_CONTRACT;
    BYTE* pByte = NULL;
    if (il != 0)
        m_pCeeFileGen->GetMethodBuffer(il, &pByte);
    return TADDR(pByte);
#else // DACCESS_COMPILE
    SUPPORTS_DAC;
    DacNotImpl();
    return (TADDR)NULL;
#endif // DACCESS_COMPILE
}

PTR_VOID ReflectionModule::GetRvaField(RVA field) // virtual
{
#ifndef DACCESS_COMPILE
    WRAPPER_NO_CONTRACT;
    // This function should be call only if the target is a field or a field with RVA.
    PTR_BYTE pByte = NULL;
    m_pCeeFileGen->ComputePointer(m_sdataSection, field, &pByte);
    return dac_cast<PTR_VOID>(pByte);
#else // DACCESS_COMPILE
    SUPPORTS_DAC;
    DacNotImpl();
    return NULL;
#endif // DACCESS_COMPILE
}

#ifndef DACCESS_COMPILE

// ===========================================================================
// VASigCookies
// ===========================================================================

static bool TypeSignatureContainsGenericVariables(SigParser& sp);
static bool MethodSignatureContainsGenericVariables(SigParser& sp);

static bool TypeSignatureContainsGenericVariables(SigParser& sp)
{
    STANDARD_VM_CONTRACT;

    CorElementType et = ELEMENT_TYPE_END;
    IfFailThrow(sp.GetElemType(&et));

    if (CorIsPrimitiveType(et))
        return false;

    switch (et)
    {
        case ELEMENT_TYPE_OBJECT:
        case ELEMENT_TYPE_STRING:
        case ELEMENT_TYPE_TYPEDBYREF:
            return false;

        case ELEMENT_TYPE_BYREF:
        case ELEMENT_TYPE_PTR:
        case ELEMENT_TYPE_SZARRAY:
            return TypeSignatureContainsGenericVariables(sp);

        case ELEMENT_TYPE_VALUETYPE:
        case ELEMENT_TYPE_CLASS:
            IfFailThrow(sp.GetToken(NULL)); // Skip RID
            return false;

        case ELEMENT_TYPE_FNPTR:
            return MethodSignatureContainsGenericVariables(sp);

        case ELEMENT_TYPE_ARRAY:
            {
                if (TypeSignatureContainsGenericVariables(sp))
                    return true;

                uint32_t rank;
                IfFailThrow(sp.GetData(&rank)); // Get rank
                if (rank)
                {
                    uint32_t nsizes;
                    IfFailThrow(sp.GetData(&nsizes)); // Get # of sizes
                    while (nsizes--)
                    {
                        IfFailThrow(sp.GetData(NULL)); // Skip size
                    }

                    uint32_t nlbounds;
                    IfFailThrow(sp.GetData(&nlbounds)); // Get # of lower bounds
                    while (nlbounds--)
                    {
                        IfFailThrow(sp.GetData(NULL)); // Skip lower bounds
                    }
                }
            }
            return false;

        case ELEMENT_TYPE_GENERICINST:
            {
                if (TypeSignatureContainsGenericVariables(sp))
                    return true;

                uint32_t argCnt;
                IfFailThrow(sp.GetData(&argCnt)); // Get number of parameters
                while (argCnt--)
                {
                    if (TypeSignatureContainsGenericVariables(sp))
                        return true;
                }
            }
            return false;

        case ELEMENT_TYPE_INTERNAL:
            IfFailThrow(sp.GetPointer(NULL));
            return false;

        case ELEMENT_TYPE_VAR:
        case ELEMENT_TYPE_MVAR:
            return true;

        default:
            // Return conservative answer for unhandled elements
            _ASSERTE(!"Unexpected element type.");
            return true;
    }
}

static bool MethodSignatureContainsGenericVariables(SigParser& sp)
{
    STANDARD_VM_CONTRACT;

    uint32_t callConv = 0;
    IfFailThrow(sp.GetCallingConvInfo(&callConv));

    if (callConv & IMAGE_CEE_CS_CALLCONV_GENERIC)
    {
        // Generic signatures should never show up here, return conservative answer.
        _ASSERTE(!"Unexpected generic signature.");
        return true;
    }

    uint32_t numArgs = 0;
    IfFailThrow(sp.GetData(&numArgs));

    // iterate over the return type and parameters
    for (uint32_t i = 0; i <= numArgs; i++)
    {
        if (TypeSignatureContainsGenericVariables(sp))
            return true;
    }

    return false;
}

//==========================================================================
// Enregisters a VASig.
//==========================================================================
VASigCookie *Module::GetVASigCookie(Signature vaSignature, const SigTypeContext* typeContext)
{
    CONTRACT(VASigCookie*)
    {
        INSTANCE_CHECK;
        STANDARD_VM_CHECK;
        POSTCONDITION(CheckPointer(RETVAL));
        INJECT_FAULT(COMPlusThrowOM());
    }
    CONTRACT_END;

    SigTypeContext emptyContext;

    Module* pLoaderModule = this;
    if (!typeContext->IsEmpty())
    {
        // Strip the generic context if it is not actually used by the signature. It is nececessary for both:
        // - Performance: allow more sharing of vasig cookies
        // - Functionality: built-in runtime marshalling is disallowed for generic signatures
        SigParser sigParser = vaSignature.CreateSigParser();
        if (MethodSignatureContainsGenericVariables(sigParser))
        {
            pLoaderModule = ClassLoader::ComputeLoaderModuleWorker(this, mdTokenNil, typeContext->m_classInst, typeContext->m_methodInst);
        }
        else
        {
            typeContext = &emptyContext;
        }
    }
    else
    {
#ifdef _DEBUG
        // The method signature should not contain any generic variables if the generic context is not provided.
        SigParser sigParser = vaSignature.CreateSigParser();
        _ASSERTE(!MethodSignatureContainsGenericVariables(sigParser));
#endif
    }

    VASigCookie *pCookie = GetVASigCookieWorker(this, pLoaderModule, vaSignature, typeContext);

    RETURN pCookie;
}

VASigCookie *Module::GetVASigCookieWorker(Module* pDefiningModule, Module* pLoaderModule, Signature vaSignature, const SigTypeContext* typeContext)
{
    CONTRACT(VASigCookie*)
    {
        STANDARD_VM_CHECK;
        POSTCONDITION(CheckPointer(RETVAL));
        INJECT_FAULT(COMPlusThrowOM());
    }
    CONTRACT_END;

    VASigCookieBlock *pBlock;
    VASigCookie      *pCookie;

    pCookie = NULL;

    // First, see if we already enregistered this sig.
    // Note that we're outside the lock here, so be a bit careful with our logic
    for (pBlock = pLoaderModule->m_pVASigCookieBlock; pBlock != NULL; pBlock = pBlock->m_Next)
    {
        for (UINT i = 0; i < pBlock->m_numcookies; i++)
        {
            if (pBlock->m_cookies[i].signature.GetRawSig() == vaSignature.GetRawSig())
            {
                _ASSERTE(pBlock->m_cookies[i].classInst.GetNumArgs() == typeContext->m_classInst.GetNumArgs());
                _ASSERTE(pBlock->m_cookies[i].methodInst.GetNumArgs() == typeContext->m_methodInst.GetNumArgs());

                bool instMatch = true;

                for (DWORD j = 0; j < pBlock->m_cookies[i].classInst.GetNumArgs(); j++)
                {
                    if (pBlock->m_cookies[i].classInst[j] != typeContext->m_classInst[j])
                    {
                        instMatch = false;
                        break;
                    }
                }

                if (instMatch)
                {
                    for (DWORD j = 0; j < pBlock->m_cookies[i].methodInst.GetNumArgs(); j++)
                    {
                        if (pBlock->m_cookies[i].methodInst[j] != typeContext->m_methodInst[j])
                        {
                            instMatch = false;
                            break;
                        }
                    }
                }

                if (instMatch)
                {
                    pCookie = &(pBlock->m_cookies[i]);
                    break;
                }
            }
        }
    }

    if (!pCookie)
    {
        // If not, time to make a new one.

        // Compute the size of args first, outside of the lock.

        MetaSig metasig(vaSignature, pDefiningModule, typeContext);
        ArgIterator argit(&metasig);

        // Upper estimate of the vararg size
        DWORD sizeOfArgs = argit.SizeOfArgStack();

        // Prepare instantiation
        LoaderAllocator  *pLoaderAllocator = pLoaderModule->GetLoaderAllocator();

        DWORD classInstCount = typeContext->m_classInst.GetNumArgs();
        DWORD methodInstCount = typeContext->m_methodInst.GetNumArgs();
        pLoaderAllocator->EnsureInstantiation(pDefiningModule, typeContext->m_classInst);
        pLoaderAllocator->EnsureInstantiation(pDefiningModule, typeContext->m_methodInst);

        // enable gc before taking lock
        {
            CrstHolder ch(&pLoaderModule->m_Crst);

            // Note that we were possibly racing to create the cookie, and another thread
            // may have already created it.  We could put another check
            // here, but it's probably not worth the effort, so we'll just take an
            // occasional duplicate cookie instead.

            // Is the first block in the list full?
            if (pLoaderModule->m_pVASigCookieBlock && pLoaderModule->m_pVASigCookieBlock->m_numcookies
                < VASigCookieBlock::kVASigCookieBlockSize)
            {
                // Nope, reserve a new slot in the existing block.
                pCookie = &(pLoaderModule->m_pVASigCookieBlock->m_cookies[pLoaderModule->m_pVASigCookieBlock->m_numcookies]);
            }
            else
            {
                // Yes, create a new block.
                VASigCookieBlock *pNewBlock = new VASigCookieBlock();

                pNewBlock->m_Next = pLoaderModule->m_pVASigCookieBlock;
                pNewBlock->m_numcookies = 0;
                pLoaderModule->m_pVASigCookieBlock = pNewBlock;
                pCookie = &(pNewBlock->m_cookies[0]);
            }

            // Now, fill in the new cookie (assuming we had enough memory to create one.)
            pCookie->pModule = pDefiningModule;
            pCookie->pPInvokeILStub = 0;
            pCookie->sizeOfArgs = sizeOfArgs;
            pCookie->signature = vaSignature;
            pCookie->pLoaderModule = pLoaderModule;

            AllocMemTracker amt;

            if (classInstCount != 0)
            {
                TypeHandle* pClassInst = (TypeHandle*)(void*)amt.Track(pLoaderAllocator->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(classInstCount) * S_SIZE_T(sizeof(TypeHandle))));
                for (DWORD i = 0; i < classInstCount; i++)
                {
                    pClassInst[i] = typeContext->m_classInst[i];
                }
                pCookie->classInst = Instantiation(pClassInst, classInstCount);
            }

            if (methodInstCount != 0)
            {
                TypeHandle* pMethodInst = (TypeHandle*)(void*)amt.Track(pLoaderAllocator->GetHighFrequencyHeap()->AllocMem(S_SIZE_T(methodInstCount) * S_SIZE_T(sizeof(TypeHandle))));
                for (DWORD i = 0; i < methodInstCount; i++)
                {
                    pMethodInst[i] = typeContext->m_methodInst[i];
                }
                pCookie->methodInst = Instantiation(pMethodInst, methodInstCount);
            }

            amt.SuppressRelease();

            // Finally, now that it's safe for asynchronous readers to see it,
            // update the count.
            pLoaderModule->m_pVASigCookieBlock->m_numcookies++;
        }
    }

    RETURN pCookie;
}

#endif // !DACCESS_COMPILE

#ifdef DACCESS_COMPILE

void
LookupMapBase::EnumMemoryRegions(CLRDataEnumMemoryFlags flags,
                             bool enumThis)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        FORBID_FAULT;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    if (enumThis)
    {
        DacEnumHostDPtrMem(this);
    }
    if (pTable.IsValid())
    {
        DacEnumMemoryRegion(dac_cast<TADDR>(pTable),
                            dwCount * sizeof(TADDR));
    }
}


/* static */
void
LookupMapBase::ListEnumMemoryRegions(CLRDataEnumMemoryFlags flags)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        FORBID_FAULT;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    LookupMapBase * headMap = this;
    bool enumHead = false;
    while (headMap)
    {
        headMap->EnumMemoryRegions(flags, enumHead);

        if (!headMap->pNext.IsValid())
        {
            break;
        }

        headMap = headMap->pNext;
        enumHead = true;
    }
}

#endif // DACCESS_COMPILE


// Optimization intended for Module::EnsureActive only
#include <optsmallperfcritical.h>

#ifndef DACCESS_COMPILE
VOID Module::EnsureActive()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;
    GetAssembly()->EnsureActive();
}
#endif // DACCESS_COMPILE

#include <optdefault.h>

CHECK Module::CheckActivated()
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
    }
    CONTRACTL_END;

#ifndef DACCESS_COMPILE
    Assembly *pAssembly = GetAssembly();
    CHECK(pAssembly != NULL);
    _ASSERTE(pAssembly != NULL);
    CHECK(pAssembly->CheckActivated());
#endif
    CHECK_OK;
}

#ifdef DACCESS_COMPILE

void Module::EnumMemoryRegions(CLRDataEnumMemoryFlags flags,
                               bool enumThis)
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        NOTHROW;
        GC_NOTRIGGER;
        MODE_ANY;
        FORBID_FAULT;
        SUPPORTS_DAC;
    }
    CONTRACTL_END;

    if (enumThis)
    {
        DAC_ENUM_VTHIS();
        EMEM_OUT(("MEM: %p Module\n", dac_cast<TADDR>(this)));
    }

    if (m_pPEAssembly.IsValid())
    {
        m_pPEAssembly->EnumMemoryRegions(flags);
    }
    if (m_pAssembly.IsValid())
    {
        m_pAssembly->EnumMemoryRegions(flags);
    }

    m_TypeRefToMethodTableMap.ListEnumMemoryRegions(flags);
    m_TypeDefToMethodTableMap.ListEnumMemoryRegions(flags);

    if (flags == CLRDATA_ENUM_MEM_HEAP2)
    {
        GetLoaderAllocator()->EnumMemoryRegions(flags);
    }
    else if (flags != CLRDATA_ENUM_MEM_MINI && flags != CLRDATA_ENUM_MEM_TRIAGE)
    {
        if (m_pAvailableClasses.IsValid())
        {
            m_pAvailableClasses->EnumMemoryRegions(flags);
        }
        if (m_pAvailableParamTypes.IsValid())
        {
            m_pAvailableParamTypes->EnumMemoryRegions(flags);
        }
        if (m_pInstMethodHashTable.IsValid())
        {
            m_pInstMethodHashTable->EnumMemoryRegions(flags);
        }
        if (m_pAvailableClassesCaseIns.IsValid())
        {
            m_pAvailableClassesCaseIns->EnumMemoryRegions(flags);
        }

        // Save the LookupMap structures.
        m_MethodDefToDescMap.ListEnumMemoryRegions(flags);
        m_FieldDefToDescMap.ListEnumMemoryRegions(flags);
        m_MemberRefMap.ListEnumMemoryRegions(flags);
        m_GenericParamToDescMap.ListEnumMemoryRegions(flags);
        m_ManifestModuleReferencesMap.ListEnumMemoryRegions(flags);

        LookupMap<PTR_MethodTable>::Iterator typeDefIter(&m_TypeDefToMethodTableMap);
        while (typeDefIter.Next())
        {
            if (typeDefIter.GetElement())
            {
                typeDefIter.GetElement()->EnumMemoryRegions(flags);
            }
        }

        LookupMap<PTR_TypeRef>::Iterator typeRefIter(&m_TypeRefToMethodTableMap);
        while (typeRefIter.Next())
        {
            if (typeRefIter.GetElement())
            {
                TypeHandle th = TypeHandle::FromTAddr(dac_cast<TADDR>(typeRefIter.GetElement()));
                th.EnumMemoryRegions(flags);
            }
        }

        LookupMap<PTR_MethodDesc>::Iterator methodDefIter(&m_MethodDefToDescMap);
        while (methodDefIter.Next())
        {
            if (methodDefIter.GetElement())
            {
                methodDefIter.GetElement()->EnumMemoryRegions(flags);
            }
        }

        LookupMap<PTR_FieldDesc>::Iterator fieldDefIter(&m_FieldDefToDescMap);
        while (fieldDefIter.Next())
        {
            if (fieldDefIter.GetElement())
            {
                fieldDefIter.GetElement()->EnumMemoryRegions(flags);
            }
        }

        LookupMap<PTR_TypeVarTypeDesc>::Iterator genericParamIter(&m_GenericParamToDescMap);
        while (genericParamIter.Next())
        {
            if (genericParamIter.GetElement())
            {
                genericParamIter.GetElement()->EnumMemoryRegions(flags);
            }
        }

    }   // !CLRDATA_ENUM_MEM_MINI && !CLRDATA_ENUM_MEM_TRIAGE && !CLRDATA_ENUM_MEM_HEAP2

    LookupMap<PTR_Module>::Iterator asmRefIter(&m_ManifestModuleReferencesMap);
    while (asmRefIter.Next())
    {
        if (asmRefIter.GetElement())
        {
            asmRefIter.GetElement()->GetAssembly()->EnumMemoryRegions(flags);
        }
    }

#ifdef FEATURE_METADATA_UPDATER
    m_ClassList.EnumMemoryRegions();

    DPTR(PTR_EnCEEClassData) classData = m_ClassList.Table();
    DPTR(PTR_EnCEEClassData) classLast = classData + m_ClassList.Count();

    while (classData.IsValid() && classData < classLast)
    {
        if ((*classData).IsValid())
        {
            (*classData)->EnumMemoryRegions(flags);
        }

        classData++;
    }
#endif // FEATURE_METADATA_UPDATER
}

FieldDesc *Module::LookupFieldDef(mdFieldDef token)
{
    WRAPPER_NO_CONTRACT;
    _ASSERTE(TypeFromToken(token) == mdtFieldDef);
    return m_FieldDefToDescMap.GetElement(RidFromToken(token));
}

#endif // DACCESS_COMPILE





//-------------------------------------------------------------------------------
// Make best-case effort to obtain an image name for use in an error message.
//
// This routine must expect to be called before the this object is fully loaded.
// It can return an empty if the name isn't available or the object isn't initialized
// enough to get a name, but it mustn't crash.
//-------------------------------------------------------------------------------
LPCWSTR Module::GetPathForErrorMessages()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        if (FORBIDGC_LOADER_USE_ENABLED()) FORBID_FAULT; else { INJECT_FAULT(COMPlusThrowOM()); }
    }
    CONTRACTL_END

    PEAssembly *pPEAssembly = GetPEAssembly();

    if (pPEAssembly)
    {
        return pPEAssembly->GetPathForErrorMessages();
    }
    else
    {
        return W("");
    }
}

LPCWSTR ModuleBase::GetPathForErrorMessages()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        FORBID_FAULT;
    }
    CONTRACTL_END;
    return W("");
}

#if defined(_DEBUG) && !defined(DACCESS_COMPILE) && !defined(CROSS_COMPILE)
void Module::ExpandAll()
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    //If the EE isn't started yet, it's not safe to jit.  We fail in COM jitting a p/invoke.
    if (!g_fEEStarted)
        return;
    struct Local
    {
        static void CompileMethodDesc(MethodDesc * pMD)
        {
            //Must have a method body
            if (pMD->HasILHeader()
                //Can't jit open instantiations
                && !pMD->IsGenericMethodDefinition()
                //These are the only methods we can jit
                && (pMD->IsStatic() || pMD->GetNumGenericMethodArgs() == 0
                    || pMD->HasClassInstantiation())
                && (pMD->MayHaveNativeCode() && !pMD->IsFCall()))
            {
                pMD->PrepareInitialCode();
            }
        }
        static void CompileMethodsForMethodTable(MethodTable * pMT)
        {
            MethodTable::MethodIterator it(pMT);
            for (; it.IsValid(); it.Next())
            {
                MethodDesc * pMD = it.GetMethodDesc();
                CompileMethodDesc(pMD);
            }
        }
#if 0
        static void CompileMethodsForTypeDef(Module * pModule, mdTypeDef td)
        {
            TypeHandle th = ClassLoader::LoadTypeDefThrowing(pModule, td, ClassLoader::ThrowIfNotFound,
                                                             ClassLoader::PermitUninstDefOrRef);

            MethodTable * pMT = th.GetMethodTable();
            CompileMethodsForMethodTable(pMT);
        }
#endif
        static void CompileMethodsForTypeDefRefSpec(Module * pModule, mdToken tok)
        {
            TypeHandle th;
            HRESULT hr = S_OK;

            EX_TRY
            {
                th = ClassLoader::LoadTypeDefOrRefOrSpecThrowing(
                    pModule,
                    tok,
                    NULL /*SigTypeContext*/);
            }
            EX_CATCH
            {
                hr = GET_EXCEPTION()->GetHR();
            }
            EX_END_CATCH

            //Only do this for non-generic types and unshared generic types
            //(canonical generics and value type generic instantiations).
            if (SUCCEEDED(hr) && !th.IsTypeDesc()
                            && th.AsMethodTable()->IsCanonicalMethodTable())
            {
                CompileMethodsForMethodTable(th.AsMethodTable());
            }
        }
        static void CompileMethodsForMethodDefRefSpec(Module * pModule, mdToken tok)
        {
            HRESULT hr = S_OK;
            EX_TRY
            {
                MethodDesc * pMD =
                    MemberLoader::GetMethodDescFromMemberDefOrRefOrSpec(pModule, tok,
                                                                        /*SigTypeContext*/NULL,
                                                                        TRUE, TRUE);
                CompileMethodDesc(pMD);
            }
            EX_CATCH
            {
                hr = GET_EXCEPTION()->GetHR();
            }
            EX_END_CATCH
        }
    };
    //Jit all methods eagerly

    IMDInternalImport * pMDI = GetMDImport();
    HENUMTypeDefInternalHolder hEnum(pMDI);
    mdTypeDef td;
    hEnum.EnumTypeDefInit();

    //verify global methods
    if (GetGlobalMethodTable())
    {
        //jit everything in the MT.
        Local::CompileMethodsForTypeDefRefSpec(this, COR_GLOBAL_PARENT_TOKEN);
    }
    while (pMDI->EnumNext(&hEnum, &td))
    {
        //jit everything
        Local::CompileMethodsForTypeDefRefSpec(this, td);
    }

    //Get the type refs.  They're always awesome.
    HENUMInternalHolder hEnumTypeRefs(pMDI);
    mdToken tr;

    hEnumTypeRefs.EnumAllInit(mdtTypeRef);
    while (hEnumTypeRefs.EnumNext(&tr))
    {
        Local::CompileMethodsForTypeDefRefSpec(this, tr);
    }

    //make sure to get the type specs
    HENUMInternalHolder hEnumTypeSpecs(pMDI);
    mdToken ts;

    hEnumTypeSpecs.EnumAllInit(mdtTypeSpec);
    while (hEnumTypeSpecs.EnumNext(&ts))
    {
        Local::CompileMethodsForTypeDefRefSpec(this, ts);
    }


    //And now for the interesting generic methods
    HENUMInternalHolder hEnumMethodSpecs(pMDI);
    mdToken ms;

    hEnumMethodSpecs.EnumAllInit(mdtMethodSpec);
    while (hEnumMethodSpecs.EnumNext(&ms))
    {
        Local::CompileMethodsForMethodDefRefSpec(this, ms);
    }
}
#endif //_DEBUG && !DACCESS_COMPILE && !CROSS_COMPILE

//-------------------------------------------------------------------------------

// Verify consistency of asmconstants.h

// Wrap all C_ASSERT's in asmconstants.h with a class definition.  Many of the
// fields referenced below are private, and this class is a friend of the
// enclosing type.  (A C_ASSERT isn't a compiler intrinsic, just a magic
// typedef that produces a compiler error when the condition is false.)
#include "clrvarargs.h" /* for VARARG C_ASSERTs in asmconstants.h */
class CheckAsmOffsets
{
#ifndef CROSSBITNESS_COMPILE
#define ASMCONSTANTS_C_ASSERT(cond) static_assert(cond, #cond);
#include "asmconstants.h"
#endif // CROSSBITNESS_COMPILE
};

//-------------------------------------------------------------------------------

#ifdef DACCESS_COMPILE
void DECLSPEC_NORETURN ModuleBase::ThrowTypeLoadExceptionImpl(IMDInternalImport *pInternalImport,
                                                      mdToken token,
                                                      UINT resIDWhy)
{
    WRAPPER_NO_CONTRACT;
    ThrowHR(E_FAIL);
}
#else
void DECLSPEC_NORETURN Module::ThrowTypeLoadExceptionImpl(IMDInternalImport *pInternalImport,
                                                      mdToken token,
                                                      UINT resIDWhy)
{
    WRAPPER_NO_CONTRACT;
    GetAssembly()->ThrowTypeLoadException(pInternalImport, token, NULL, resIDWhy);
}
#endif
