// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.intel_syntax noprefix
#include "unixasmmacros.inc"
#include "asmconstants.h"

//////////////////////////////////////////////////////////////////////////
//
// PInvokeImportThunk
//
// The call in PInvokeImportPrecode points to this function
//
// EXTERN_C VOID __stdcall PInvokeImportThunk()//
NESTED_ENTRY PInvokeImportThunk, _TEXT, NoHandler

        //
        // Save integer parameter registers.
        // Make sure to preserve r11 as well as it is used to pass the stack argument size from JIT
        // Make sure to preserve rax as well as it is used for the return buffer for Swift calls
        //
        PUSH_ARGUMENT_REGISTERS
        push_register r11
        push_register rax

        //
        // Allocate space for XMM parameter registers and alignment
        //
        alloc_stack     0x88

        SAVE_FLOAT_ARGUMENT_REGISTERS 0

    END_PROLOGUE

        //
        // Call PInvokeImportWorker w/ the PInvokeMethodDesc*
        //
        mov             rdi, METHODDESC_REGISTER
        call            C_FUNC(PInvokeImportWorker)
        mov             r10, rax

        RESTORE_FLOAT_ARGUMENT_REGISTERS 0

        //
        // epilogue, r10 contains the native target address
        //
        free_stack      0x88

        //
        // Restore integer parameter registers, r11 and rax
        //
        pop_register rax
        pop_register r11
        POP_ARGUMENT_REGISTERS

        jmp r10

NESTED_END PInvokeImportThunk, _TEXT

//------------------------------------------------
// JIT_RareDisableHelper
//
// The JIT expects this helper to preserve registers used for return values
//
NESTED_ENTRY JIT_RareDisableHelper, _TEXT, NoHandler

    // First integer return register
    push_register rax
    // Second integer return register
    push_register rdx
    alloc_stack         0x28
    END_PROLOGUE
    // First float return register
    movdqa              xmmword ptr [rsp], xmm0
    // Second float return register
    movdqa              xmmword ptr [rsp+0x10], xmm1

    call                C_FUNC(JIT_RareDisableHelperWorker)

    movdqa              xmm0, xmmword ptr [rsp]
    movdqa              xmm1, xmmword ptr [rsp+0x10]
    free_stack          0x28
    pop_register        rdx
    pop_register        rax
    ret

NESTED_END JIT_RareDisableHelper, _TEXT

#ifdef FEATURE_HIJACK

//------------------------------------------------
// OnHijackTripThread
//
NESTED_ENTRY OnHijackTripThread, _TEXT, NoHandler

    // Make room for the real return address (rip)
    push_register rax

    PUSH_CALLEE_SAVED_REGISTERS

    // Push rcx for the async continuation
    push_register rcx
    // Push rdx for the second half of the return value
    push_register rdx
    // Push rax again - this is where integer/pointer return values are returned
    push_register rax

    mov                 rdi, rsp

    alloc_stack         0x20

    // First float return register
    movdqa              [rsp], xmm0
    // Second float return register
    movdqa              [rsp+0x10], xmm1

    END_PROLOGUE

    call                C_FUNC(OnHijackWorker)

    movdqa              xmm0, [rsp]
    movdqa              xmm1, [rsp+0x10]
    free_stack          0x20

    pop_register        rax
    pop_register        rdx
    pop_register        rcx

    POP_CALLEE_SAVED_REGISTERS
    ret

NESTED_END OnHijackTripThread, _TEXT

#endif // FEATURE_HIJACK

#ifdef FEATURE_TIERED_COMPILATION

NESTED_ENTRY OnCallCountThresholdReachedStub, _TEXT, NoHandler
        PROLOG_WITH_TRANSITION_BLOCK

        lea     rdi, [rsp + __PWTB_TransitionBlock] // TransitionBlock *
        mov     rsi, rax // stub-identifying token, see OnCallCountThresholdReachedStub
        call    C_FUNC(OnCallCountThresholdReached)

        EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
        TAILJMP_RAX
NESTED_END OnCallCountThresholdReachedStub, _TEXT

NESTED_ENTRY JIT_Patchpoint, _TEXT, NoHandler
        PROLOG_WITH_TRANSITION_BLOCK

        lea     rdi, [rsp + __PWTB_TransitionBlock] // TransitionBlock *
        call    C_FUNC(JIT_PatchpointWorkerWorkerWithPolicy)

        EPILOG_WITH_TRANSITION_BLOCK_RETURN
NESTED_END JIT_Patchpoint, _TEXT

// first arg register holds iloffset, which needs to be moved to the second register, and the first register filled with NULL
LEAF_ENTRY JIT_PatchpointForced, _TEXT
        mov rsi, rdi
        xor rdi, rdi
        jmp C_FUNC(JIT_Patchpoint)
LEAF_END JIT_PatchpointForced, _TEXT

#endif // FEATURE_TIERED_COMPILATION
