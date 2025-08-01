; Licensed to the .NET Foundation under one or more agreements.
; The .NET Foundation licenses this file to you under the MIT license.

#include "ksarm64.h"
#include "asmconstants.h"
#include "asmmacros.h"

    IMPORT ExternalMethodFixupWorker
    IMPORT PreStubWorker
    IMPORT PInvokeImportWorker
#ifdef FEATURE_VIRTUAL_STUB_DISPATCH
    IMPORT VSD_ResolveWorker
#endif
    IMPORT ComPreStubWorker
    IMPORT COMToCLRWorker
    IMPORT CallDescrWorkerUnwindFrameChainHandler
    IMPORT UMEntryPrestubUnwindFrameChainHandler
    IMPORT TheUMEntryPrestubWorker
    IMPORT GetCurrentSavedRedirectContext
    IMPORT OnHijackWorker
#ifdef FEATURE_READYTORUN
    IMPORT DynamicHelperWorker
#endif
    IMPORT HijackHandler
    IMPORT ThrowControlForThread
#ifdef FEATURE_INTERPRETER
    SETALIAS Thread_GetInterpThreadContext, ?GetInterpThreadContext@Thread@@QEAAPEAUInterpThreadContext@@XZ
    IMPORT $Thread_GetInterpThreadContext
    IMPORT ExecuteInterpretedMethod
#endif

#ifdef FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP
    IMPORT  g_write_watch_table
#endif

#ifdef FEATURE_MANUALLY_MANAGED_CARD_BUNDLES
    IMPORT g_card_bundle_table
#endif

    IMPORT  g_ephemeral_low
    IMPORT  g_ephemeral_high
    IMPORT  g_lowest_address
    IMPORT  g_highest_address
    IMPORT  g_card_table
#ifdef FEATURE_VIRTUAL_STUB_DISPATCH
    IMPORT  g_dispatch_cache_chain_success_counter
#endif
    IMPORT  g_pGetGCStaticBase
    IMPORT  g_pGetNonGCStaticBase

    IMPORT g_pPollGC
    IMPORT g_TrapReturningThreads

#ifdef WRITE_BARRIER_CHECK
    SETALIAS g_GCShadow, ?g_GCShadow@@3PEAEEA
    SETALIAS g_GCShadowEnd, ?g_GCShadowEnd@@3PEAEEA

    IMPORT g_lowest_address
    IMPORT $g_GCShadow
    IMPORT $g_GCShadowEnd
#endif // WRITE_BARRIER_CHECK

#ifdef FEATURE_COMINTEROP
    IMPORT CLRToCOMWorker
#endif // FEATURE_COMINTEROP

    IMPORT JIT_WriteBarrier_Table_Loc
    IMPORT JIT_WriteBarrier_Loc

    ;;like TEXTAREA, but with 64 byte alignment so that we can align the patchable pool below to 64 without warning
    AREA    |.text|,ALIGN=6,CODE,READONLY

;; LPVOID __stdcall GetCurrentIP(void);
    LEAF_ENTRY GetCurrentIP
        mov     x0, lr
        ret     lr
    LEAF_END

;; LPVOID __stdcall GetCurrentSP(void);
    LEAF_ENTRY GetCurrentSP
        mov     x0, sp
        ret     lr
    LEAF_END

;; DWORD64 __stdcall GetDataCacheZeroIDReg(void);
    LEAF_ENTRY GetDataCacheZeroIDReg
        mrs     x0, dczid_el0
        and     x0, x0, 31
        ret     lr
    LEAF_END

;; uint64_t GetSveLengthFromOS(void);
    LEAF_ENTRY GetSveLengthFromOS
        rdvl    x0, 1
        ret     lr
    LEAF_END

; ------------------------------------------------------------------
; The call in PInvokeImportPrecode points to this function.
        NESTED_ENTRY PInvokeImportThunk

        PROLOG_SAVE_REG_PAIR           fp, lr, #-224!
        SAVE_ARGUMENT_REGISTERS        sp, 16
        SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 96

        mov     x0, x12
        bl      PInvokeImportWorker
        mov     x12, x0

        ; pop the stack and restore original register state
        RESTORE_FLOAT_ARGUMENT_REGISTERS  sp, 96
        RESTORE_ARGUMENT_REGISTERS        sp, 16
        EPILOG_RESTORE_REG_PAIR           fp, lr, #224!

        ; If we got back from PInvokeImportWorker, the MD has been successfully
        ; linked. Proceed to execute the original DLL call.
        EPILOG_BRANCH_REG x12

        NESTED_END

; ------------------------------------------------------------------

        NESTED_ENTRY ThePreStub

        PROLOG_WITH_TRANSITION_BLOCK

        add         x0, sp, #__PWTB_TransitionBlock ; pTransitionBlock
        mov         x1, METHODDESC_REGISTER         ; pMethodDesc

        bl          PreStubWorker

        mov         x9, x0

        EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
        EPILOG_BRANCH_REG  x9

        NESTED_END

;; ------------------------------------------------------------------
;; ThePreStubPatch()

        LEAF_ENTRY ThePreStubPatch
        nop
ThePreStubPatchLabel
        EXPORT          ThePreStubPatchLabel
        ret             lr
        LEAF_END

#ifdef FEATURE_COMINTEROP

; ------------------------------------------------------------------
; setStubReturnValue
; w0 - size of floating point return value (MetaSig::GetFPReturnSize())
; x1 - pointer to the return buffer in the stub frame
    LEAF_ENTRY setStubReturnValue

        cbz     w0, NoFloatingPointRetVal

        ;; Float return case
        cmp     x0, #4
        bne     LNoFloatRetVal
        ldr     s0, [x1]
        ret
LNoFloatRetVal

        ;; Double return case
        cmp     w0, #8
        bne     LNoDoubleRetVal
        ldr     d0, [x1]
        ret
LNoDoubleRetVal

        ;; Float HFA return case
        cmp     w0, #16
        bne     LNoFloatHFARetVal
        ldp     s0, s1, [x1]
        ldp     s2, s3, [x1, #8]
        ret
LNoFloatHFARetVal

        ;;Double HFA return case
        cmp     w0, #32
        bne     LNoDoubleHFARetVal
        ldp     d0, d1, [x1]
        ldp     d2, d3, [x1, #16]
        ret
LNoDoubleHFARetVal

        ;;Vector HVA return case
        cmp     w3, #64
        bne     LNoVectorHVARetVal
        ldp     q0, q1, [x1]
        ldp     q2, q3, [x1, #32]
        ret
LNoVectorHVARetVal

        EMIT_BREAKPOINT ; Unreachable

NoFloatingPointRetVal

        ;; Restore the return value from retbuf
        ldr     x0, [x1]
        ldr     x1, [x1, #8]
        ret

    LEAF_END

; ------------------------------------------------------------------
; GenericCLRToCOMCallStub that erects a CLRToCOMMethodFrame and calls into the runtime
; (CLRToCOMWorker) to dispatch rare cases of the interface call.
;
; On entry:
;   x0          : 'this' object
;   x12         : Interface MethodDesc*
;   plus user arguments in registers and on the stack
;
; On exit:
;   x0/x1/s0-s3/d0-d3 set to return value of the call as appropriate
;
    NESTED_ENTRY GenericCLRToCOMCallStub

        PROLOG_WITH_TRANSITION_BLOCK ASM_ENREGISTERED_RETURNTYPE_MAXSIZE

        add         x0, sp, #__PWTB_TransitionBlock ; pTransitionBlock
        mov         x1, x12                         ; pMethodDesc

        ; Call CLRToCOMWorker(TransitionBlock *, CLRToCOMCallMethodDesc *).
        ; This call will set up the rest of the frame (including the vfptr, the GS cookie and
        ; linking to the thread), make the client call and return with correct registers set
        ; (x0/x1/s0-s3/d0-d3 as appropriate).

        bl          CLRToCOMWorker

        ; x0 = fpRetSize

        ; The return value is stored before float argument registers
        add         x1, sp, #(__PWTB_FloatArgumentRegisters - ASM_ENREGISTERED_RETURNTYPE_MAXSIZE)
        bl          setStubReturnValue

        EPILOG_WITH_TRANSITION_BLOCK_RETURN

    NESTED_END

; ------------------------------------------------------------------
; COM to CLR stub called the first time a particular method is invoked.
;
; On entry:
;   x12         : ComCallMethodDesc* provided by prepad thunk
;   plus user arguments in registers and on the stack
;
; On exit:
;   tail calls to real method
;
    NESTED_ENTRY ComCallPreStub

    GBLA ComCallPreStub_FrameSize
    GBLA ComCallPreStub_StackAlloc
    GBLA ComCallPreStub_FrameOffset
    GBLA ComCallPreStub_ErrorReturnOffset
    GBLA ComCallPreStub_FirstStackAdjust

ComCallPreStub_FrameSize         SETA (SIZEOF__ComMethodFrame)
ComCallPreStub_FirstStackAdjust  SETA (8 + SIZEOF__ArgumentRegisters + 2 * 8) ; x8, reg args , fp & lr already pushed
ComCallPreStub_StackAlloc        SETA ComCallPreStub_FrameSize - ComCallPreStub_FirstStackAdjust
ComCallPreStub_StackAlloc        SETA ComCallPreStub_StackAlloc + SIZEOF__FloatArgumentRegisters + 8; 8 for ErrorReturn
    IF ComCallPreStub_StackAlloc:MOD:16 != 0
ComCallPreStub_StackAlloc     SETA ComCallPreStub_StackAlloc + 8
    ENDIF

ComCallPreStub_FrameOffset       SETA (ComCallPreStub_StackAlloc - (SIZEOF__ComMethodFrame - ComCallPreStub_FirstStackAdjust))
ComCallPreStub_ErrorReturnOffset SETA SIZEOF__FloatArgumentRegisters

    IF (ComCallPreStub_FirstStackAdjust):MOD:16 != 0
ComCallPreStub_FirstStackAdjust     SETA ComCallPreStub_FirstStackAdjust + 8
    ENDIF

    ; Save arguments and return address
    PROLOG_SAVE_REG_PAIR           fp, lr, #-ComCallPreStub_FirstStackAdjust!
    PROLOG_STACK_ALLOC  ComCallPreStub_StackAlloc

    SAVE_ARGUMENT_REGISTERS        sp, (16+ComCallPreStub_StackAlloc)

    SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 0

    str x12, [sp, #(ComCallPreStub_FrameOffset + UnmanagedToManagedFrame__m_pvDatum)]
    add x0, sp, #(ComCallPreStub_FrameOffset)
    add x1, sp, #(ComCallPreStub_ErrorReturnOffset)
    bl ComPreStubWorker

    cbz x0, ComCallPreStub_ErrorExit

    mov x12, x0

    ; pop the stack and restore original register state
    RESTORE_FLOAT_ARGUMENT_REGISTERS  sp, 0
    RESTORE_ARGUMENT_REGISTERS        sp, (16+ComCallPreStub_StackAlloc)

    EPILOG_STACK_FREE ComCallPreStub_StackAlloc
    EPILOG_RESTORE_REG_PAIR           fp, lr, #ComCallPreStub_FirstStackAdjust!

    ; and tailcall to the actual method
    EPILOG_BRANCH_REG x12

ComCallPreStub_ErrorExit
    ldr x0, [sp, #(ComCallPreStub_ErrorReturnOffset)] ; ErrorReturn

    ; pop the stack
    EPILOG_STACK_FREE ComCallPreStub_StackAlloc
    EPILOG_RESTORE_REG_PAIR           fp, lr, #ComCallPreStub_FirstStackAdjust!

    EPILOG_RETURN

    NESTED_END

; ------------------------------------------------------------------
; COM to CLR stub which sets up a ComMethodFrame and calls COMToCLRWorker.
;
; On entry:
;   x12         : ComCallMethodDesc*  provided by prepad thunk
;   plus user arguments in registers and on the stack
;
; On exit:
;   Result in x0/d0 as per the real method being called
;
    NESTED_ENTRY GenericComCallStub

    GBLA GenericComCallStub_FrameSize
    GBLA GenericComCallStub_StackAlloc
    GBLA GenericComCallStub_FrameOffset
    GBLA GenericComCallStub_FirstStackAdjust

GenericComCallStub_FrameSize         SETA (SIZEOF__ComMethodFrame)
GenericComCallStub_FirstStackAdjust  SETA (8 + SIZEOF__ArgumentRegisters + 2 * 8)
GenericComCallStub_StackAlloc        SETA GenericComCallStub_FrameSize - GenericComCallStub_FirstStackAdjust
GenericComCallStub_StackAlloc        SETA GenericComCallStub_StackAlloc + SIZEOF__FloatArgumentRegisters

    IF (GenericComCallStub_StackAlloc):MOD:16 != 0
GenericComCallStub_StackAlloc     SETA GenericComCallStub_StackAlloc + 8
    ENDIF

GenericComCallStub_FrameOffset       SETA (GenericComCallStub_StackAlloc - (SIZEOF__ComMethodFrame - GenericComCallStub_FirstStackAdjust))

    IF (GenericComCallStub_FirstStackAdjust):MOD:16 != 0
GenericComCallStub_FirstStackAdjust     SETA GenericComCallStub_FirstStackAdjust + 8
    ENDIF


    ; Save arguments and return address
    PROLOG_SAVE_REG_PAIR           fp, lr, #-GenericComCallStub_FirstStackAdjust!
    PROLOG_STACK_ALLOC  GenericComCallStub_StackAlloc

    SAVE_ARGUMENT_REGISTERS        sp, (16+GenericComCallStub_StackAlloc)
    SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 0

    str x12, [sp, #(GenericComCallStub_FrameOffset + UnmanagedToManagedFrame__m_pvDatum)]
    add x0, sp, #GenericComCallStub_FrameOffset
    bl COMToCLRWorker

    ; pop the stack
    EPILOG_STACK_FREE GenericComCallStub_StackAlloc
    EPILOG_RESTORE_REG_PAIR           fp, lr, #GenericComCallStub_FirstStackAdjust!

    EPILOG_RETURN

    NESTED_END

; ------------------------------------------------------------------
; COM to CLR stub called from COMToCLRWorker that actually dispatches to the real managed method.
;
; On entry:
;   x0          : dwStackSlots, count of argument stack slots to copy
;   x1          : pFrame, ComMethodFrame pushed by GenericComCallStub above
;   x2          : pTarget, address of code to call
;   x3          : pSecretArg, hidden argument passed to target above in x12
;   x4          : pDangerousThis, managed 'this' reference
;
; On exit:
;   Result in x0/d0 as per the real method being called
;
    NESTED_ENTRY COMToCLRDispatchHelper,,CallDescrWorkerUnwindFrameChainHandler

    PROLOG_SAVE_REG_PAIR           fp, lr, #-16!

    cbz x0, COMToCLRDispatchHelper_RegSetup

    add x9, x1, #SIZEOF__ComMethodFrame

    ; Compute number of 8 bytes slots to copy. This is done by rounding up the
    ; dwStackSlots value to the nearest even value
    add x0, x0, #1
    bic x0, x0, #1

    ; Compute how many slots to adjust the address to copy from. Since we
    ; are copying 16 bytes at a time, adjust by -1 from the rounded value
    sub x6, x0, #1
    add x9, x9, x6, LSL #3

COMToCLRDispatchHelper_StackLoop
    ldp     x7, x8, [x9], #-16  ; post-index
    stp     x7, x8, [sp, #-16]! ; pre-index
    subs    x0, x0, #2
    bne     COMToCLRDispatchHelper_StackLoop

COMToCLRDispatchHelper_RegSetup

    ; We need an aligned offset for restoring float args, so do the subtraction into
    ; a scratch register
    sub     x5, x1, GenericComCallStub_FrameOffset
    RESTORE_FLOAT_ARGUMENT_REGISTERS x5, 0

    mov lr, x2
    mov x12, x3

    mov x0, x4

    ldp x2, x3, [x1, #(SIZEOF__ComMethodFrame - SIZEOF__ArgumentRegisters + 16)]
    ldp x4, x5, [x1, #(SIZEOF__ComMethodFrame - SIZEOF__ArgumentRegisters + 32)]
    ldp x6, x7, [x1, #(SIZEOF__ComMethodFrame - SIZEOF__ArgumentRegisters + 48)]
    ldr x8, [x1, #(SIZEOF__ComMethodFrame - SIZEOF__ArgumentRegisters - 8)]

    ldr x1, [x1, #(SIZEOF__ComMethodFrame - SIZEOF__ArgumentRegisters + 8)]

    blr lr

    EPILOG_STACK_RESTORE
    EPILOG_RESTORE_REG_PAIR           fp, lr, #16!
    EPILOG_RETURN

    NESTED_END

#endif ; FEATURE_COMINTEROP

;
; x12 = UMEntryThunkData*
;
    NESTED_ENTRY TheUMEntryPrestub,,UMEntryPrestubUnwindFrameChainHandler

    ; Save arguments and return address
    PROLOG_SAVE_REG_PAIR           fp, lr, #-224!
    SAVE_ARGUMENT_REGISTERS        sp, 16
    SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 96

    mov x0, x12
    bl  TheUMEntryPrestubWorker

    ; save real target address in x12.
    mov x12, x0

    ; pop the stack and restore original register state
    RESTORE_ARGUMENT_REGISTERS        sp, 16
    RESTORE_FLOAT_ARGUMENT_REGISTERS  sp, 96
    EPILOG_RESTORE_REG_PAIR           fp, lr, #224!

    ; and tailcall to the actual method
    EPILOG_BRANCH_REG x12

    NESTED_END

#ifdef FEATURE_HIJACK
; ------------------------------------------------------------------
; Hijack function for functions which return a scalar type or a struct (value type)
    NESTED_ENTRY OnHijackTripThread
    PROLOG_SAVE_REG_PAIR   fp, lr, #-192!
    ; Spill callee saved registers
    PROLOG_SAVE_REG_PAIR   x19, x20, #16
    PROLOG_SAVE_REG_PAIR   x21, x22, #32
    PROLOG_SAVE_REG_PAIR   x23, x24, #48
    PROLOG_SAVE_REG_PAIR   x25, x26, #64
    PROLOG_SAVE_REG_PAIR   x27, x28, #80

    ; save any integral return value(s)
    stp x0, x1, [sp, #96]

    ; save async continuation return value
    str x2, [sp, #112]

    ; save any FP/HFA/HVA return value(s)
    stp q0, q1, [sp, #128]
    stp q2, q3, [sp, #160]

    mov x0, sp
    bl OnHijackWorker

    ; restore any integral return value(s)
    ldp x0, x1, [sp, #96]

    ; restore async continuation return value
    ldr x2, [sp, #112]

    ; restore any FP/HFA/HVA return value(s)
    ldp q0, q1, [sp, #128]
    ldp q2, q3, [sp, #160]

    EPILOG_RESTORE_REG_PAIR   x19, x20, #16
    EPILOG_RESTORE_REG_PAIR   x21, x22, #32
    EPILOG_RESTORE_REG_PAIR   x23, x24, #48
    EPILOG_RESTORE_REG_PAIR   x25, x26, #64
    EPILOG_RESTORE_REG_PAIR   x27, x28, #80
    EPILOG_RESTORE_REG_PAIR   fp, lr,   #192!
    EPILOG_RETURN
    NESTED_END

#endif ; FEATURE_HIJACK

;; ------------------------------------------------------------------
;; Redirection Stub for GC in fully interruptible method
        GenerateRedirectedHandledJITCaseStub GCThreadControl
;; ------------------------------------------------------------------
        GenerateRedirectedHandledJITCaseStub DbgThreadControl
;; ------------------------------------------------------------------
        GenerateRedirectedHandledJITCaseStub UserSuspend

#ifdef _DEBUG
; ------------------------------------------------------------------
; Redirection Stub for GC Stress
        GenerateRedirectedHandledJITCaseStub GCStress
#endif


; ------------------------------------------------------------------

        ; This helper enables us to call into a funclet after restoring Fp register
        NESTED_ENTRY CallEHFunclet
        ; On entry:
        ;
        ; X0 = throwable
        ; X1 = PC to invoke
        ; X2 = address of CONTEXT record; used to restore the non-volatile registers of CrawlFrame
        ; X3 = address of the location where the SP of funclet's caller (i.e. this helper) should be saved.
        ;

        ; Using below prolog instead of PROLOG_SAVE_REG_PAIR fp,lr, #-96!
        ; is intentional. Above statement would also emit instruction to save
        ; sp in fp. If sp is saved in fp in prolog then it is not expected that fp can change in the body
        ; of method. However, this method needs to be able to change fp before calling funclet.
        ; This is required to access locals in funclet.
        PROLOG_SAVE_REG_PAIR_NO_FP fp,lr, #-96!

        ; Spill callee saved registers
        PROLOG_SAVE_REG_PAIR   x19, x20, 16
        PROLOG_SAVE_REG_PAIR   x21, x22, 32
        PROLOG_SAVE_REG_PAIR   x23, x24, 48
        PROLOG_SAVE_REG_PAIR   x25, x26, 64
        PROLOG_SAVE_REG_PAIR   x27, x28, 80

        ; Save the SP of this function. We cannot store SP directly.
        mov fp, sp
        str fp, [x3]

        ldp x19, x20, [x2, #OFFSETOF__CONTEXT__X19]
        ldp x21, x22, [x2, #(OFFSETOF__CONTEXT__X19 + 16)]
        ldp x23, x24, [x2, #(OFFSETOF__CONTEXT__X19 + 32)]
        ldp x25, x26, [x2, #(OFFSETOF__CONTEXT__X19 + 48)]
        ldp x27, x28, [x2, #(OFFSETOF__CONTEXT__X19 + 64)]
        ldr fp, [x2, #OFFSETOF__CONTEXT__Fp]

        ; Invoke the funclet
        blr x1
        nop

        EPILOG_RESTORE_REG_PAIR   x19, x20, 16
        EPILOG_RESTORE_REG_PAIR   x21, x22, 32
        EPILOG_RESTORE_REG_PAIR   x23, x24, 48
        EPILOG_RESTORE_REG_PAIR   x25, x26, 64
        EPILOG_RESTORE_REG_PAIR   x27, x28, 80
        EPILOG_RESTORE_REG_PAIR   fp, lr, #96!
        EPILOG_RETURN

        NESTED_END CallEHFunclet

        ; This helper enables us to call into a filter funclet after restoring Fp register
        NESTED_ENTRY CallEHFilterFunclet

        PROLOG_SAVE_REG_PAIR_NO_FP   fp, lr, #-16!

        ; On entry:
        ;
        ; X0 = throwable
        ; X1 = FP of the main function
        ; X2 = PC to invoke
        ; X3 = address of the location where the SP of funclet's caller (i.e. this helper) should be saved.
        ;
        ; Save the SP of this function
        mov fp, sp
        str fp, [x3]
        ; Restore frame pointer
        mov fp, x1
        ; Invoke the filter funclet
        blr x2

        EPILOG_RESTORE_REG_PAIR   fp, lr,   #16!
        EPILOG_RETURN

        NESTED_END CallEHFilterFunclet


        GBLA FaultingExceptionFrame_StackAlloc
        GBLA FaultingExceptionFrame_FrameOffset

FaultingExceptionFrame_StackAlloc         SETA (SIZEOF__FaultingExceptionFrame)
FaultingExceptionFrame_FrameOffset        SETA  0

        MACRO
        GenerateRedirectedStubWithFrame $STUB, $TARGET

        ;
        ; This is the primary function to which execution will be redirected to.
        ;
        NESTED_ENTRY $STUB

        ;
        ; IN: lr: original IP before redirect
        ;

        PROLOG_SAVE_REG_PAIR    fp, lr, #-16!
        PROLOG_STACK_ALLOC  FaultingExceptionFrame_StackAlloc

        ; At this point, the stack maybe misaligned if the thread abort was asynchronously
        ; triggered in the prolog or epilog of the managed method. For such a case, we must
        ; align the stack before calling into the VM.
        ;
        ; Runtime check for 16-byte alignment.
        mov x0, sp
        and x0, x0, #15
        sub sp, sp, x0

        ; Save pointer to FEF for GetFrameFromRedirectedStubStackFrame
        add x19, sp, #FaultingExceptionFrame_FrameOffset

        ; Prepare to initialize to NULL
        mov x1,#0
        str x1, [x19]                                                        ; Initialize vtbl (it is not strictly necessary)
        str x1, [x19, #FaultingExceptionFrame__m_fFilterExecuted]            ; Initialize BOOL for personality routine

        mov x0, x19       ; move the ptr to FEF in X0

        bl            $TARGET

        ; Target should not return.
        EMIT_BREAKPOINT

        NESTED_END $STUB

        MEND


; ------------------------------------------------------------------
;
; Helpers for ThreadAbort exceptions
;

        NESTED_ENTRY RedirectForThreadAbort2,,HijackHandler
        PROLOG_SAVE_REG_PAIR fp,lr, #-16!

        ; stack must be 16 byte aligned
        CHECK_STACK_ALIGNMENT

        ; On entry:
        ;
        ; x0 = address of FaultingExceptionFrame
        ;
        ; Invoke the helper to setup the FaultingExceptionFrame and raise the exception
        bl              ThrowControlForThread

        ; ThrowControlForThread doesn't return.
        EMIT_BREAKPOINT

        NESTED_END RedirectForThreadAbort2

        GenerateRedirectedStubWithFrame RedirectForThreadAbort, RedirectForThreadAbort2

#ifdef FEATURE_VIRTUAL_STUB_DISPATCH
; ------------------------------------------------------------------
; ResolveWorkerChainLookupAsmStub
;
; This method will perform a quick chained lookup of the entry if the
;  initial cache lookup fails.
;
; On Entry:
;   x9        contains the pointer to the current ResolveCacheElem
;   x11       contains the address of the indirection (and the flags in the low two bits)
;   x12       contains our contract the DispatchToken
; Must be preserved:
;   x0        contains the instance object ref that we are making an interface call on
;   x9        Must point to a ResolveCacheElem [For Sanity]
;  [x1-x7]    contains any additional register arguments for the interface method
;
; Loaded from x0
;   x13       contains our type     the MethodTable  (from object ref in x0)
;
; On Exit:
;   x0, [x1-x7] arguments for the interface implementation target
;
; On Exit (to ResolveWorkerAsmStub):
;   x11       contains the address of the indirection and the flags in the low two bits.
;   x12       contains our contract (DispatchToken)
;   x16,x17   will be trashed
;
    GBLA BACKPATCH_FLAG      ; two low bit flags used by ResolveWorkerAsmStub
    GBLA PROMOTE_CHAIN_FLAG  ; two low bit flags used by ResolveWorkerAsmStub
BACKPATCH_FLAG      SETA  1
PROMOTE_CHAIN_FLAG  SETA  2

    NESTED_ENTRY ResolveWorkerChainLookupAsmStub

        tst     x11, #BACKPATCH_FLAG    ; First we check if x11 has the BACKPATCH_FLAG set
        bne     Fail                    ; If the BACKPATCH_FLAGS is set we will go directly to the ResolveWorkerAsmStub

        ldr     x13, [x0]         ; retrieve the MethodTable from the object ref in x0
MainLoop
        ldr     x9, [x9, #ResolveCacheElem__pNext]     ; x9 <= the next entry in the chain
        cmp     x9, #0
        beq     Fail

        ldp     x16, x17, [x9]
        cmp     x16, x13          ; compare our MT with the one in the ResolveCacheElem
        bne     MainLoop

        cmp     x17, x12          ; compare our DispatchToken with one in the ResolveCacheElem
        bne     MainLoop

Success
        ldr     x13, =g_dispatch_cache_chain_success_counter
        ldr     x16, [x13]
        subs    x16, x16, #1
        str     x16, [x13]
        blt     Promote

        ldr     x16, [x9, #ResolveCacheElem__target]    ; get the ImplTarget
        br      x16               ; branch to interface implementation target

Promote
                                  ; Move this entry to head position of the chain
        mov     x16, #256
        str     x16, [x13]        ; be quick to reset the counter so we don't get a bunch of contending threads
        orr     x11, x11, #PROMOTE_CHAIN_FLAG   ; set PROMOTE_CHAIN_FLAG
        mov     x12, x9           ; We pass the ResolveCacheElem to ResolveWorkerAsmStub instead of the DispatchToken

Fail
        b       ResolveWorkerAsmStub ; call the ResolveWorkerAsmStub method to transition into the VM

    NESTED_END ResolveWorkerChainLookupAsmStub

;; ------------------------------------------------------------------
;; void ResolveWorkerAsmStub(args in regs x0-x7 & stack and possibly retbuf arg in x8, x11:IndirectionCellAndFlags, x12:DispatchToken)
;;
;; The stub dispatch thunk which transfers control to VSD_ResolveWorker.
        NESTED_ENTRY ResolveWorkerAsmStub

        PROLOG_WITH_TRANSITION_BLOCK

        add x0, sp, #__PWTB_TransitionBlock ; pTransitionBlock
        and x1, x11, #-4 ; Indirection cell
        mov x2, x12 ; DispatchToken
        and x3, x11, #3 ; flag
        bl VSD_ResolveWorker
        mov x9, x0

        EPILOG_WITH_TRANSITION_BLOCK_TAILCALL

        EPILOG_BRANCH_REG  x9

        NESTED_END
#endif // FEATURE_VIRTUAL_STUB_DISPATCH

#ifdef FEATURE_READYTORUN

    NESTED_ENTRY DelayLoad_MethodCall
    PROLOG_WITH_TRANSITION_BLOCK

    add x0, sp, #__PWTB_TransitionBlock ; pTransitionBlock
    mov x1, x11 ; Indirection cell
    mov x2, x9 ; sectionIndex
    mov x3, x10 ; Module*
    bl ExternalMethodFixupWorker
    mov x12, x0

    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
    EPILOG_BRANCH_REG   x12

    NESTED_END

    MACRO
        DynamicHelper $frameFlags, $suffix

        NESTED_ENTRY DelayLoad_Helper$suffix

        PROLOG_WITH_TRANSITION_BLOCK

        add x0, sp, #__PWTB_TransitionBlock ; pTransitionBlock
        mov x1, x11 ; Indirection cell
        mov x2, x9 ; sectionIndex
        mov x3, x10 ; Module*
        mov x4, $frameFlags
        bl DynamicHelperWorker
        cbnz x0, %FT0
        ldr x0, [sp, #__PWTB_ArgumentRegister_FirstArg]
        EPILOG_WITH_TRANSITION_BLOCK_RETURN
0
        mov x12, x0
        EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
        EPILOG_BRANCH_REG  x12
        NESTED_END
    MEND

    DynamicHelper DynamicHelperFrameFlags_Default
    DynamicHelper DynamicHelperFrameFlags_ObjectArg, _Obj
    DynamicHelper DynamicHelperFrameFlags_ObjectArg | DynamicHelperFrameFlags_ObjectArg2, _ObjObj
#endif // FEATURE_READYTORUN

#ifdef FEATURE_COMINTEROP
; ------------------------------------------------------------------
; Function used by COM interop to get floating point return value (since it's not in the same
; register(s) as non-floating point values).
;
; On entry;
;   x0          : size of the FP result (4 or 8 bytes)
;   x1          : pointer to 64-bit buffer to receive result
;
; On exit:
;   buffer pointed to by x1 on entry contains the float or double argument as appropriate
;
    LEAF_ENTRY getFPReturn
    str d0, [x1]
    LEAF_END

; ------------------------------------------------------------------
; Function used by COM interop to set floating point return value (since it's not in the same
; register(s) as non-floating point values).
;
; On entry:
;   x0          : size of the FP result (4 or 8 bytes)
;   x1          : 32-bit or 64-bit FP result
;
; On exit:
;   s0          : float result if x0 == 4
;   d0          : double result if x0 == 8
;
    LEAF_ENTRY setFPReturn
    fmov d0, x1
    LEAF_END
#endif

;
; JIT Static access helpers when coreclr host specifies single appdomain flag
;

; ------------------------------------------------------------------

; void* JIT_GetDynamicNonGCStaticBase(DynamicStaticsInfo *dynamicInfo)

    LEAF_ENTRY JIT_GetDynamicNonGCStaticBase_SingleAppDomain
    ; If class is not initialized, bail to C++ helper
    add x1, x0, #OFFSETOF__DynamicStaticsInfo__m_pNonGCStatics
    ldar x1, [x1]
    tbnz x1, #0, CallHelper1
    mov x0, x1
    ret lr

CallHelper1
    ; Tail call GetNonGCStaticBase
    ldr x0, [x0, #OFFSETOF__DynamicStaticsInfo__m_pMethodTable]
    adrp     x1, g_pGetNonGCStaticBase
    ldr      x1, [x1, g_pGetNonGCStaticBase]
    br       x1
    LEAF_END

; void* JIT_GetDynamicGCStaticBase(DynamicStaticsInfo *dynamicInfo)

    LEAF_ENTRY JIT_GetDynamicGCStaticBase_SingleAppDomain
    ; If class is not initialized, bail to C++ helper
    add x1, x0, #OFFSETOF__DynamicStaticsInfo__m_pGCStatics
    ldar x1, [x1]
    tbnz x1, #0, CallHelper2
    mov x0, x1
    ret lr

CallHelper2
    ; Tail call GetGCStaticBase
    ldr x0, [x0, #OFFSETOF__DynamicStaticsInfo__m_pMethodTable]
    adrp     x1, g_pGetGCStaticBase
    ldr      x1, [x1, g_pGetGCStaticBase]
    br       x1
    LEAF_END

; ------------------------------------------------------------------
; __declspec(naked) void F_CALL_CONV JIT_WriteBarrier_Callable(Object **dst, Object* val)
    LEAF_ENTRY  JIT_WriteBarrier_Callable

    ; Setup args for JIT_WriteBarrier. x14 = dst ; x15 = val
    mov     x14, x0                     ; x14 = dst
    mov     x15, x1                     ; x15 = val

    ; Branch to the write barrier
    adrp    x17, JIT_WriteBarrier_Loc
    ldr     x17, [x17, JIT_WriteBarrier_Loc]
    br      x17

    LEAF_END

#ifdef PROFILING_SUPPORTED

; ------------------------------------------------------------------
; void JIT_ProfilerEnterLeaveTailcallStub(UINT_PTR ProfilerHandle)
   LEAF_ENTRY  JIT_ProfilerEnterLeaveTailcallStub
   ret      lr
   LEAF_END

 #define PROFILE_ENTER    1
 #define PROFILE_LEAVE    2
 #define PROFILE_TAILCALL 4
 #define SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA 320

; ------------------------------------------------------------------
    MACRO
    GenerateProfileHelper $helper, $flags

    LCLS __HelperNakedFuncName
__HelperNakedFuncName SETS "$helper":CC:"Naked"
    IMPORT $helper

    NESTED_ENTRY $__HelperNakedFuncName
        ; On entry:
        ;   x10 = functionIDOrClientID
        ;   x11 = profiledSp
        ;   x12 = throwable
        ;
        ; On exit:
        ;   Values of x0-x8, q0-q7, fp are preserved.
        ;   Values of other volatile registers are not preserved.

        PROLOG_SAVE_REG_PAIR fp, lr, -SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA! ; Allocate space and save Fp, Pc.
        SAVE_ARGUMENT_REGISTERS sp, 16          ; Save x8 and argument registers (x0-x7).
        str     xzr, [sp, #88]                  ; Clear functionId.
        SAVE_FLOAT_ARGUMENT_REGISTERS sp, 96    ; Save floating-point/SIMD registers (q0-q7).
        add     x12, fp, SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA ; Compute probeSp - initial value of Sp on entry to the helper.
        stp     x12, x11, [sp, #224]            ; Save probeSp, profiledSp.
        str     xzr, [sp, #240]                 ; Clear hiddenArg.
        mov     w12, $flags
        stp     w12, wzr, [sp, #248]            ; Save flags and clear unused field.

        mov     x0, x10
        mov     x1, sp
        bl $helper

        RESTORE_ARGUMENT_REGISTERS sp, 16       ; Restore x8 and argument registers.
        RESTORE_FLOAT_ARGUMENT_REGISTERS sp, 96 ; Restore floating-point/SIMD registers.

        EPILOG_RESTORE_REG_PAIR fp, lr, SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA!
        EPILOG_RETURN

    NESTED_END
0

    MEND

    GenerateProfileHelper ProfileEnter, PROFILE_ENTER
    GenerateProfileHelper ProfileLeave, PROFILE_LEAVE
    GenerateProfileHelper ProfileTailcall, PROFILE_TAILCALL

#endif

#ifdef FEATURE_TIERED_COMPILATION

    IMPORT OnCallCountThresholdReached

    NESTED_ENTRY OnCallCountThresholdReachedStub
        PROLOG_WITH_TRANSITION_BLOCK

        add     x0, sp, #__PWTB_TransitionBlock ; TransitionBlock *
        mov     x1, x9 ; stub-identifying token
        bl      OnCallCountThresholdReached
        mov     x9, x0

        EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
        EPILOG_BRANCH_REG x9
    NESTED_END

    IMPORT JIT_PatchpointWorkerWorkerWithPolicy

    NESTED_ENTRY JIT_Patchpoint
        PROLOG_WITH_TRANSITION_BLOCK

        add     x0, sp, #__PWTB_TransitionBlock ; TransitionBlock *
        bl      JIT_PatchpointWorkerWorkerWithPolicy

        EPILOG_WITH_TRANSITION_BLOCK_RETURN
    NESTED_END

    // first arg register holds iloffset, which needs to be moved to the second register, and the first register filled with NULL
    LEAF_ENTRY JIT_PatchpointForced
        mov x1, x0
        mov x0, #0
        b JIT_Patchpoint
    LEAF_END

#endif ; FEATURE_TIERED_COMPILATION

    LEAF_ENTRY  JIT_ValidateIndirectCall
        ret lr
    LEAF_END

    LEAF_ENTRY  JIT_DispatchIndirectCall
        br x9
    LEAF_END

#ifdef FEATURE_SPECIAL_USER_MODE_APC

    IMPORT |?ApcActivationCallback@Thread@@CAX_K@Z|

    ; extern "C" void NTAPI ApcActivationCallbackStub(ULONG_PTR Parameter);
    NESTED_ENTRY ApcActivationCallbackStub

        PROLOG_SAVE_REG_PAIR    fp, lr, #-16!
        PROLOG_STACK_ALLOC      16                ; stack slot for CONTEXT* and padding

        ;REDIRECTSTUB_SP_OFFSET_CONTEXT is defined in asmconstants.h and is used in GetCONTEXTFromRedirectedStubStackFrame
        ;If CONTEXT is not saved at 0 offset from SP it must be changed as well.
        ASSERT REDIRECTSTUB_SP_OFFSET_CONTEXT == 0

        ; Save a copy of the redirect CONTEXT*.
        ; This is needed for the debugger to unwind the stack.
        ldr x17, [x0, OFFSETOF__APC_CALLBACK_DATA__ContextRecord]
        str x17, [sp]

        bl |?ApcActivationCallback@Thread@@CAX_K@Z|

        EPILOG_STACK_FREE       16                ; undo stack slot for CONTEXT* and padding
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN

; Put a label here to tell the debugger where the end of this function is.
    PATCH_LABEL ApcActivationCallbackStubEnd
    EXPORT ApcActivationCallbackStubEnd

    NESTED_END

#endif ; FEATURE_SPECIAL_USER_MODE_APC

    LEAF_ENTRY  JIT_PollGC
        ldr     x9, =g_TrapReturningThreads
        ldr     w9, [x9]
        cbnz    w9, JIT_PollGCRarePath
        ret
JIT_PollGCRarePath
        ldr     x9, =g_pPollGC
        ldr     x9, [x9]
        br x9
    LEAF_END

;x0 -This pointer
;x1 -ReturnBuffer
    LEAF_ENTRY ThisPtrRetBufPrecodeWorker
        ldr  x12, [METHODDESC_REGISTER, #ThisPtrRetBufPrecodeData__Target]
        mov  x11, x0     ; Move first arg pointer to temp register
        mov  x0,  x1     ; Move ret buf arg pointer from location in ABI for return buffer for instance method to location in ABI for return buffer for static method
        mov  x1, x11     ; Move temp register to first arg register for static method with return buffer
        EPILOG_BRANCH_REG x12
    LEAF_END

#ifdef FEATURE_INTERPRETER

    NESTED_ENTRY InterpreterStub

        PROLOG_WITH_TRANSITION_BLOCK

        INLINE_GETTHREAD x20, x19

        ldr x11, [x20, #OFFSETOF__Thread__m_pInterpThreadContext]
        cbnz x11, HaveInterpThreadContext

        mov x0, x20
        bl $Thread_GetInterpThreadContext
        mov x11, x0
        RESTORE_ARGUMENT_REGISTERS sp, __PWTB_ArgumentRegisters
        RESTORE_FLOAT_ARGUMENT_REGISTERS sp, __PWTB_FloatArgumentRegisters

HaveInterpThreadContext
        ; IR bytecode address
        mov x19, METHODDESC_REGISTER
        ldr x9, [METHODDESC_REGISTER]
        ldr x9, [x9, #OFFSETOF__InterpMethod__pCallStub]
        add x10, x9, #OFFSETOF__CallStubHeader__Routines
        ldr x9, [x11, #OFFSETOF__InterpThreadContext__pStackPointer]
        ; x19 contains IR bytecode address
        ; Copy the arguments to the interpreter stack, invoke the InterpExecMethod and load the return value
        ldr x11, [x10], #8
        blr x11

        EPILOG_WITH_TRANSITION_BLOCK_RETURN

    NESTED_END InterpreterStub

    NESTED_ENTRY InterpreterStubRetVoid
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetVoid

    NESTED_ENTRY InterpreterStubRetI8
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr x0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetI8

    NESTED_ENTRY InterpreterStubRetDouble
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr d0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetDouble

    NESTED_ENTRY InterpreterStubRetBuff
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        ; Load the return buffer address
        ; 16 is the size of the pushed registers above
        ldr x2, [sp, #__PWTB_ArgumentRegisters + 16]
        bl ExecuteInterpretedMethod
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetBuff

    NESTED_ENTRY InterpreterStubRet2I8
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr x1, [x0, #8]
        ldr x0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet2I8

    NESTED_ENTRY InterpreterStubRet2Double
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp d0, d1, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet2Double

    NESTED_ENTRY InterpreterStubRet3Double
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp d0, d1, [x0]
        ldr d2, [x0, #16]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet3Double

    NESTED_ENTRY InterpreterStubRet4Double
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp d0, d1, [x0]
        ldp d2, d3, [x0, #16]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet4Double

    NESTED_ENTRY InterpreterStubRetFloat
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr s0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetFloat

    NESTED_ENTRY InterpreterStubRet2Float
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp s0, s1, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet2Float

    NESTED_ENTRY InterpreterStubRet3Float
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp s0, s1, [x0]
        ldr s2, [x0, #8]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet3Float

    NESTED_ENTRY InterpreterStubRet4Float
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldp s0, s1, [x0]
        ldp s2, s3, [x0, #8]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRet4Float

     NESTED_ENTRY InterpreterStubRetVector64
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr d0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetVector64

    NESTED_ENTRY InterpreterStubRetVector128
        PROLOG_SAVE_REG_PAIR   fp, lr, #-16!
        ; The +16 is for the fp, lr above
        add x0, sp, #__PWTB_TransitionBlock + 16
        mov x1, x19 ; the IR bytecode pointer
        mov x2, xzr
        bl ExecuteInterpretedMethod
        ldr q0, [x0]
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END InterpreterStubRetVector128

    ; Routines for passing value type arguments by reference in general purpose registers X0..X7
    ; from native code to the interpreter

    ; Copy arguments from the processor stack to the interpreter stack
    ; The CPU stack slots are aligned to pointer size.

    LEAF_ENTRY Store_Stack
        ldr w11, [x10], #4 ; SP offset
        ldr w12, [x10], #4 ; number of stack slots
        add x11, sp, x11
        add x11, x11, #__PWTB_TransitionBlock + SIZEOF__TransitionBlock
StoreCopyLoop
        ldr x13, [x11], #8
        str x13, [x9], #8
        subs x12, x12, #8
        bne StoreCopyLoop
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_Stack

    LEAF_ENTRY Load_Stack_Ref
        ldr w11, [x10], #4 ; SP offset
        ldr w12, [x10], #4 ; size of the value type
        add x11, sp, x11
        str x9, [x11]
        add x9, x9, x12
        ; Align x9 to the stack slot size
        add x9, x9, 7
        and x9, x9, 0xfffffffffffffff8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_Stack_Ref

    MACRO
        Copy_Ref $argReg
        cmp x11, #16
        blt CopyBy8$argReg
RefCopyLoop16$argReg
        ldp x13, x14, [$argReg], #16
        stp x13, x14, [x9], #16
        subs x11, x11, #16
        bgt RefCopyLoop16$argReg
        beq RefCopyDone$argReg
        add x11, x11, #16
CopyBy8$argReg
        cmp x11, #8
        blt RefCopyLoop1$argReg
RefCopyLoop8$argReg
        ldr x13, [$argReg], #8
        str x13, [x9], #8
        subs x11, x11, #8
        bgt RefCopyLoop8$argReg
        beq RefCopyDone$argReg
        add x11, x11, #8
RefCopyLoop1$argReg
        ldrb w13, [$argReg], #1
        strb w13, [x9], #1
        subs x11, x11, #1
        bne  RefCopyLoop1$argReg
RefCopyDone$argReg
        ; Align x9 to the stack slot size
        add x9, x9, 7
        and x9, x9, 0xfffffffffffffff8
    MEND

    LEAF_ENTRY Store_Stack_Ref
        ldr w12, [x10], #4 ; SP offset
        ldr w11, [x10], #4 ; size of the value type
        add x12, sp, x12
        ldr x12, [x12, #__PWTB_TransitionBlock + SIZEOF__TransitionBlock]
        Copy_Ref x12
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_Stack_Ref

    MACRO
        Store_Ref $argReg

    LEAF_ENTRY Store_Ref_$argReg
        ldr x11, [x10], #8 ; size of the value type
        Copy_Ref $argReg
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_Ref_$argReg

    MEND

    Store_Ref X0
    Store_Ref X1
    Store_Ref X2
    Store_Ref X3
    Store_Ref X4
    Store_Ref X5
    Store_Ref X6
    Store_Ref X7

    LEAF_ENTRY Store_X0
        str x0, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0

    LEAF_ENTRY Store_X0_X1
        stp x0, x1, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1

    LEAF_ENTRY Store_X0_X1_X2
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2
        str x2, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2

    LEAF_ENTRY Store_X0_X1_X2_X3
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2_X3
        stp x2, x3, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2_X3

    LEAF_ENTRY Store_X0_X1_X2_X3_X4
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2_X3_X4
        stp x2, x3, [x9], #16
    ALTERNATE_ENTRY Store_X4
        str x4, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2_X3_X4

    LEAF_ENTRY Store_X0_X1_X2_X3_X4_X5
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2_X3_X4_X5
        stp x2, x3, [x9], #16
    ALTERNATE_ENTRY Store_X4_X5
        stp x4, x5, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2_X3_X4_X5

    LEAF_ENTRY Store_X0_X1_X2_X3_X4_X5_X6
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2_X3_X4_X5_X6
        stp x2, x3, [x9], #16
    ALTERNATE_ENTRY Store_X4_X5_X6
        stp x4, x5, [x9], #16
    ALTERNATE_ENTRY Store_X6
        str x6, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2_X3_X4_X5_X6

    LEAF_ENTRY Store_X0_X1_X2_X3_X4_X5_X6_X7
        stp x0, x1, [x9], #16
    ALTERNATE_ENTRY Store_X2_X3_X4_X5_X6_X7
        stp x2, x3, [x9], #16
    ALTERNATE_ENTRY Store_X4_X5_X6_X7
        stp x4, x5, [x9], #16
    ALTERNATE_ENTRY Store_X6_X7
        stp x6, x7, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X0_X1_X2_X3_X4_X5_X6_X7

    LEAF_ENTRY Store_X1
        str x1, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1

    LEAF_ENTRY Store_X1_X2
        stp x1, x2, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2

    LEAF_ENTRY Store_X1_X2_X3
        stp x1, x2, [x9], #16
    ALTERNATE_ENTRY Store_X3
        str x3, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2_X3

    LEAF_ENTRY Store_X1_X2_X3_X4
        stp x1, x2, [x9], #16
    ALTERNATE_ENTRY Store_X3_X4
        stp x3, x4, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2_X3_X4

    LEAF_ENTRY Store_X1_X2_X3_X4_X5
        stp x1, x2, [x9], #16
    ALTERNATE_ENTRY Store_X3_X4_X5
        stp x3, x4, [x9], #16
    ALTERNATE_ENTRY Store_X5
        str x5, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2_X3_X4_X5

    LEAF_ENTRY Store_X1_X2_X3_X4_X5_X6
        stp x1, x2, [x9], #16
    ALTERNATE_ENTRY Store_X3_X4_X5_X6
        stp x3, x4, [x9], #16
    ALTERNATE_ENTRY Store_X5_X6
        stp x5, x6, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2_X3_X4_X5_X6

    LEAF_ENTRY Store_X1_X2_X3_X4_X5_X6_X7
        stp x1, x2, [x9], #16
    ALTERNATE_ENTRY Store_X3_X4_X5_X6_X7
        stp x3, x4, [x9], #16
    ALTERNATE_ENTRY Store_X5_X6_X7
        stp x5, x6, [x9], #16
    ALTERNATE_ENTRY Store_X7
        str x7, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_X1_X2_X3_X4_X5_X6_X7

    ; Floating point stores using stp wherever possible

    LEAF_ENTRY Store_D0
        str d0, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0

    LEAF_ENTRY Store_D1
        str d1, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1

    LEAF_ENTRY Store_D0_D1
        stp d0, d1, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1

    LEAF_ENTRY Store_D0_D1_D2
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2
        str d2, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2

    LEAF_ENTRY Store_D0_D1_D2_D3
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2_D3
        stp d2, d3, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2_D3

    LEAF_ENTRY Store_D0_D1_D2_D3_D4
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2_D3_D4
        stp d2, d3, [x9], #16
    ALTERNATE_ENTRY Store_D4
        str d4, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2_D3_D4

    LEAF_ENTRY Store_D0_D1_D2_D3_D4_D5
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2_D3_D4_D5
        stp d2, d3, [x9], #16
    ALTERNATE_ENTRY Store_D4_D5
        stp d4, d5, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2_D3_D4_D5

    LEAF_ENTRY Store_D0_D1_D2_D3_D4_D5_D6
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2_D3_D4_D5_D6
        stp d2, d3, [x9], #16
    ALTERNATE_ENTRY Store_D4_D5_D6
        stp d4, d5, [x9], #16
    ALTERNATE_ENTRY Store_D6
        str d6, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2_D3_D4_D5_D6

    LEAF_ENTRY Store_D0_D1_D2_D3_D4_D5_D6_D7
        stp d0, d1, [x9], #16
    ALTERNATE_ENTRY Store_D2_D3_D4_D5_D6_D7
        stp d2, d3, [x9], #16
    ALTERNATE_ENTRY Store_D4_D5_D6_D7
        stp d4, d5, [x9], #16
    ALTERNATE_ENTRY Store_D6_D7
        stp d6, d7, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D0_D1_D2_D3_D4_D5_D6_D7

    LEAF_ENTRY Store_D1_D2
        stp d1, d2, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2

    LEAF_ENTRY Store_D1_D2_D3
        stp d1, d2, [x9], #16
    ALTERNATE_ENTRY Store_D3
        str d3, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2_D3

    LEAF_ENTRY Store_D1_D2_D3_D4
        stp d1, d2, [x9], #16
    ALTERNATE_ENTRY Store_D3_D4
        stp d3, d4, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2_D3_D4

    LEAF_ENTRY Store_D1_D2_D3_D4_D5
        stp d1, d2, [x9], #16
    ALTERNATE_ENTRY Store_D3_D4_D5
        stp d3, d4, [x9], #16
    ALTERNATE_ENTRY Store_D5
        str d5, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2_D3_D4_D5

    LEAF_ENTRY Store_D1_D2_D3_D4_D5_D6
        stp d1, d2, [x9], #16
    ALTERNATE_ENTRY Store_D3_D4_D5_D6
        stp d3, d4, [x9], #16
    ALTERNATE_ENTRY Store_D5_D6
        stp d5, d6, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2_D3_D4_D5_D6

    LEAF_ENTRY Store_D1_D2_D3_D4_D5_D6_D7
        stp d1, d2, [x9], #16
    ALTERNATE_ENTRY Store_D3_D4_D5_D6_D7
        stp d3, d4, [x9], #16
    ALTERNATE_ENTRY Store_D5_D6_D7
        stp d5, d6, [x9], #16
    ALTERNATE_ENTRY Store_D7
        str d7, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Store_D1_D2_D3_D4_D5_D6_D7

    ; Routines for passing value type arguments by reference in general purpose registers X0..X7
    ; from the interpreter to native code
    ; Copy arguments from the interpreter stack to the processor stack
    ; The CPU stack slots are aligned to pointer size.
    LEAF_ENTRY Load_Stack
        ldr w14, [x10], #4 ; SP offset
        ldr w12, [x10], #4 ; number of stack slots
        add x14, sp, x14
CopyLoop
        ldr x13, [x9], #8
        str x13, [x14], #8
        subs x12, x12, #8
        bne CopyLoop
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_Stack

    ; Routines for passing value type arguments by reference in general purpose registers X0..X7

    MACRO
        Load_Ref $argReg

    LEAF_ENTRY Load_Ref_$argReg
        mov $argReg, x9
        ldr x12, [x10], #8
        add x9, x9, x12
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_Ref_$argReg

    MEND

    Load_Ref X0
    Load_Ref X1
    Load_Ref X2
    Load_Ref X3
    Load_Ref X4
    Load_Ref X5
    Load_Ref X6
    Load_Ref X7

    ; Routines for passing arguments by value in general purpose registers X0..X7

    LEAF_ENTRY Load_X0
        ldr x0, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0

    LEAF_ENTRY Load_X0_X1
        ldp x0, x1, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1

    LEAF_ENTRY Load_X0_X1_X2
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2
        ldr x2, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2

    LEAF_ENTRY Load_X0_X1_X2_X3
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2_X3
        ldp x2, x3, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2_X3

    LEAF_ENTRY Load_X0_X1_X2_X3_X4
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2_X3_X4
        ldp x2, x3, [x9], #16
    ALTERNATE_ENTRY Load_X4
        ldr x4, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2_X3_X4

    LEAF_ENTRY Load_X0_X1_X2_X3_X4_X5
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2_X3_X4_X5
        ldp x2, x3, [x9], #16
    ALTERNATE_ENTRY Load_X4_X5
        ldp x4, x5, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2_X3_X4_X5

    LEAF_ENTRY Load_X0_X1_X2_X3_X4_X5_X6
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2_X3_X4_X5_X6
        ldp x2, x3, [x9], #16
    ALTERNATE_ENTRY Load_X4_X5_X6
        ldp x4, x5, [x9], #16
    ALTERNATE_ENTRY Load_X6
        ldr x6, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2_X3_X4_X5_X6

    LEAF_ENTRY Load_X0_X1_X2_X3_X4_X5_X6_X7
        ldp x0, x1, [x9], #16
    ALTERNATE_ENTRY Load_X2_X3_X4_X5_X6_X7
        ldp x2, x3, [x9], #16
    ALTERNATE_ENTRY Load_X4_X5_X6_X7
        ldp x4, x5, [x9], #16
    ALTERNATE_ENTRY Load_X6_X7
        ldp x6, x7, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X0_X1_X2_X3_X4_X5_X6_X7

    LEAF_ENTRY Load_X1
        ldr x1, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1

    LEAF_ENTRY Load_X1_X2
        ldp x1, x2, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2

    LEAF_ENTRY Load_X1_X2_X3
        ldp x1, x2, [x9], #16
    ALTERNATE_ENTRY Load_X3
        ldr x3, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2_X3

    LEAF_ENTRY Load_X1_X2_X3_X4
        ldp x1, x2, [x9], #16
    ALTERNATE_ENTRY Load_X3_X4
        ldp x3, x4, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2_X3_X4

    LEAF_ENTRY Load_X1_X2_X3_X4_X5
        ldp x1, x2, [x9], #16
    ALTERNATE_ENTRY Load_X3_X4_X5
        ldp x3, x4, [x9], #16
    ALTERNATE_ENTRY Load_X5
        ldr x5, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2_X3_X4_X5

    LEAF_ENTRY Load_X1_X2_X3_X4_X5_X6
        ldp x1, x2, [x9], #16
    ALTERNATE_ENTRY Load_X3_X4_X5_X6
        ldp x3, x4, [x9], #16
    ALTERNATE_ENTRY Load_X5_X6
        ldp x5, x6, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2_X3_X4_X5_X6

    LEAF_ENTRY Load_X1_X2_X3_X4_X5_X6_X7
        ldp x1, x2, [x9], #16
    ALTERNATE_ENTRY Load_X3_X4_X5_X6_X7
        ldp x3, x4, [x9], #16
    ALTERNATE_ENTRY Load_X5_X6_X7
        ldp x5, x6, [x9], #16
    ALTERNATE_ENTRY Load_X7
        ldr x7, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_X1_X2_X3_X4_X5_X6_X7

    ; Routines for passing arguments in floating point registers D0..D7

    LEAF_ENTRY Load_D0
        ldr d0, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0

    LEAF_ENTRY Load_D1
        ldr d1, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D1

    LEAF_ENTRY Load_D0_D1
        ldp d0, d1, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1

    LEAF_ENTRY Load_D0_D1_D2
        ldr d0, [x9], #8
    ALTERNATE_ENTRY Load_D1_D2
        ldr d1, [x9], #8
    ALTERNATE_ENTRY Load_D2
        ldr d2, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2

    LEAF_ENTRY Load_D0_D1_D2_D3
        ldr d0, [x9], #8
    ALTERNATE_ENTRY Load_D1_D2_D3
        ldr d1, [x9], #8
    ALTERNATE_ENTRY Load_D2_D3
        ldr d2, [x9], #8
    ALTERNATE_ENTRY Load_D3
        ldr d3, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3

    LEAF_ENTRY Load_D0_D1_D2_D3_D4
        ldr d0, [x9], #8
    ALTERNATE_ENTRY Load_D1_D2_D3_D4
        ldr d1, [x9], #8
    ALTERNATE_ENTRY Load_D2_D3_D4
        ldr d2, [x9], #8
    ALTERNATE_ENTRY Load_D3_D4
        ldr d3, [x9], #8
    ALTERNATE_ENTRY Load_D4
        ldr d4, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3_D4

    LEAF_ENTRY Load_D0_D1_D2_D3_D4_D5
        ldr d0, [x9], #8
    ALTERNATE_ENTRY Load_D1_D2_D3_D4_D5
        ldr d1, [x9], #8
    ALTERNATE_ENTRY Load_D2_D3_D4_D5
        ldr d2, [x9], #8
    ALTERNATE_ENTRY Load_D3_D4_D5
        ldr d3, [x9], #8
    ALTERNATE_ENTRY Load_D4_D5
        ldr d4, [x9], #8
    ALTERNATE_ENTRY Load_D5
        ldr d5, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3_D4_D5

    LEAF_ENTRY Load_D0_D1_D2_D3_D4_D5_D6
        ldr d0, [x9], #8
    ALTERNATE_ENTRY Load_D1_D2_D3_D4_D5_D6
        ldr d1, [x9], #8
    ALTERNATE_ENTRY Load_D2_D3_D4_D5_D6
        ldr d2, [x9], #8
    ALTERNATE_ENTRY Load_D3_D4_D5_D6
        ldr d3, [x9], #8
    ALTERNATE_ENTRY Load_D4_D5_D6
        ldr d4, [x9], #8
    ALTERNATE_ENTRY Load_D5_D6
        ldr d5, [x9], #8
    ALTERNATE_ENTRY Load_D6
        ldr d6, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3_D4_D5_D6

    LEAF_ENTRY Load_D0_D1_D2_D3_D4_D5_D6_D7
        ldp d0, d1, [x9], #16
    ALTERNATE_ENTRY Load_D2_D3_D4_D5_D6_D7
        ldp d2, d3, [x9], #16
    ALTERNATE_ENTRY Load_D4_D5_D6_D7
        ldp d4, d5, [x9], #16
    ALTERNATE_ENTRY Load_D6_D7
        ldp d6, d7, [x9], #16
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3_D4_D5_D6_D7

    LEAF_ENTRY Load_D1_D2_D3_D4_D5_D6_D7
        ldp d1, d2, [x9], #16
    ALTERNATE_ENTRY Load_D3_D4_D5_D6_D7
        ldp d3, d4, [x9], #16
    ALTERNATE_ENTRY Load_D5_D6_D7
        ldp d5, d6, [x9], #16
    ALTERNATE_ENTRY Load_D7
        ldr d7, [x9], #8
        ldr x11, [x10], #8
        EPILOG_BRANCH_REG x11
    LEAF_END Load_D0_D1_D2_D3_D4_D5_D6_D7

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetVoid
        PROLOG_SAVE_REG_PAIR fp, lr, #-16!
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        ret lr
    NESTED_END CallJittedMethodRetVoid

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetBuff
        PROLOG_SAVE_REG_PAIR fp, lr, #-16!
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        mov x8, x2
        ldr x11, [x10], #8
        blr x11
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #16!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetBuff

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetI8
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        str x0, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetI8

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet2I8
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp x0, x1, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet2I8

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetDouble
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        str d0, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetDouble

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet2Double
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp d0, d1, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet2Double

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet3Double
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp d0, d1, [x2], #16
        str d2, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet3Double

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet4Double
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp d0, d1, [x2], #16
        stp d2, d3, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet4Double

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetFloat
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        str s0, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetFloat

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet2Float
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp s0, s1, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet2Float

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet3Float
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp s0, s1, [x2], #8
        str s2, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet3Float

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRet4Float
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        stp s0, s1, [x2], #8
        stp s2, s3, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRet4Float

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetVector64
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        str d0, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetVector64

    ; X0 - routines array
    ; X1 - interpreter stack args location
    ; X2 - interpreter stack return value location
    ; X3 - stack arguments size (properly aligned)
    NESTED_ENTRY CallJittedMethodRetVector128
        PROLOG_SAVE_REG_PAIR fp, lr, #-32!
        str x2, [sp, #16]
        sub sp, sp, x3
        mov x10, x0
        mov x9, x1
        ldr x11, [x10], #8
        blr x11
        ldr x2, [sp, #16]
        str q0, [x2]
        EPILOG_STACK_RESTORE
        EPILOG_RESTORE_REG_PAIR fp, lr, #32!
        EPILOG_RETURN
    NESTED_END CallJittedMethodRetVector128

#endif // FEATURE_INTERPRETER

; Must be at very end of file
    END
