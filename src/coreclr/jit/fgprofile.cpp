// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "jitpch.h"

#ifdef _MSC_VER
#pragma hdrstop
#endif

#include "fgprofilesynthesis.h"

// Flowgraph Profile Support

//------------------------------------------------------------------------
// fgHaveProfileData: check if profile data is available
//
// Returns:
//   true if so
//
// Note:
//   In most cases it is more appropriate to call fgHaveProfileWeights,
//   since that tells you if blocks have profile-based weights.
//
//   This method literally checks if the runtime had a profile schema,
//   from which we can derive weights.
//
//   Schema-based data comes from Tier0 methods, which currently do not do
//   any inlining; thus inlinee profile data should be available and
//   representative.
//
bool Compiler::fgHaveProfileData()
{
    return (fgPgoSchema != nullptr);
}

//------------------------------------------------------------------------
// fgHaveProfileWeights: Check if we have a profile that has weights.
//
// Notes:
//    These weights may come from instrumentation or from synthesis.
//
bool Compiler::fgHaveProfileWeights()
{
    return fgPgoHaveWeights;
}

//------------------------------------------------------------------------
// fgRemoveProfileData: Remove all traces of profile info
//
// Notes:
//   Needed if the jit initially thought it was going to optimize
//   the method, but then decided not to.
//
//   Does not modify any block fields, so should be called before
//   we start to incorporate profile data.
//
void Compiler::fgRemoveProfileData(const char* reason)
{
    fgPgoFailReason  = reason;
    fgPgoQueryResult = E_FAIL;
    fgPgoHaveWeights = false;
    fgPgoData        = nullptr;
    fgPgoSchema      = nullptr;
    fgPgoDisabled    = true;
    fgPgoDynamic     = false;
}

//------------------------------------------------------------------------
// fgHaveSufficientProfileWeights: check if profile data is available
//   and is sufficient enough to be trustful.
//
// Returns:
//   true if so
//
// Note:
//   See notes for fgHaveProfileData.
//
bool Compiler::fgHaveSufficientProfileWeights()
{
    if (!fgHaveProfileWeights())
    {
        return false;
    }

    switch (fgPgoSource)
    {
        case ICorJitInfo::PgoSource::Dynamic:
        case ICorJitInfo::PgoSource::Text:
        case ICorJitInfo::PgoSource::Blend:
            return true;

        case ICorJitInfo::PgoSource::Synthesis:
            // Single-edge methods always have sufficient profile data.
            // Assuming we don't synthesize value and class profile data (which we don't currently).
            return fgPgoSingleEdge;

        case ICorJitInfo::PgoSource::Static:
        {
            // We sometimes call this very early, eg evaluating the prejit root.
            //
            if (fgFirstBB != nullptr)
            {
                const weight_t sufficientSamples = 1000;
                return fgFirstBB->bbWeight > sufficientSamples;
            }

            return true;
        }

        default:
            return false;
    }
}

//------------------------------------------------------------------------
// fgHaveTrustedProfileWeights: check if profile data source is one
//   that can be trusted to faithfully represent the current program
//   behavior.
//
// Returns:
//   true if so
//
// Note:
//   See notes for fgHaveProfileData.
//
bool Compiler::fgHaveTrustedProfileWeights()
{
    if (!fgHaveProfileWeights())
    {
        return false;
    }

    // We allow Text to be trusted so we can use it to stand in
    // for Dynamic results.
    //
    switch (fgPgoSource)
    {
        case ICorJitInfo::PgoSource::Dynamic:
        case ICorJitInfo::PgoSource::Blend:
        case ICorJitInfo::PgoSource::Text:
            return true;

        case ICorJitInfo::PgoSource::Synthesis:
            // Single-edge methods with synthetic profile are trustful.
            // Assuming we don't synthesize value and class profile data (which we don't currently).
            return fgPgoSingleEdge;

        default:
            return false;
    }
}

//------------------------------------------------------------------------
// fgApplyProfileScale: scale inlinee counts by appropriate scale factor
//
void Compiler::fgApplyProfileScale()
{
    // Only applicable to inlinees
    //
    if (!compIsForInlining())
    {
        return;
    }

    JITDUMP("Computing inlinee profile scale:\n");

    // Callee has profile data?
    //
    if (!fgHaveProfileWeights())
    {
        // No; we will carry on nonetheless.
        //
        JITDUMP("   ... no callee profile data, will use non-pgo weight to scale\n");
    }

    // Determine the weight of the first block preds, if any.
    // (only happens if the first block is a loop head).
    //
    weight_t firstBlockPredWeight = 0;
    for (FlowEdge* const firstBlockPred : fgFirstBB->PredEdges())
    {
        firstBlockPredWeight += firstBlockPred->getLikelyWeight();
    }

    // Determine the "input" weight for the callee
    //
    weight_t calleeWeight = fgFirstBB->bbWeight;

    // Callee entry weight is zero or negative (taking backedges into account)?
    // If so, just choose the smallest plausible weight.
    //
    if (calleeWeight <= firstBlockPredWeight)
    {
        calleeWeight = fgHaveProfileWeights() ? 1.0 : BB_UNITY_WEIGHT;
        JITDUMP("   ... callee entry has zero or negative weight, will use weight of " FMT_WT " to scale\n",
                calleeWeight);
        JITDUMP("Profile data could not be scaled consistently. Data %s inconsistent.\n",
                fgPgoConsistent ? "is now" : "was already");

        if (fgPgoConsistent)
        {
            Metrics.ProfileInconsistentInlineeScale++;
            fgPgoConsistent = false;
        }
    }
    else
    {
        calleeWeight -= firstBlockPredWeight;
    }

    // Call site has profile weight?
    //
    const BasicBlock* callSiteBlock = impInlineInfo->iciBlock;
    if (!callSiteBlock->hasProfileWeight())
    {
        // No? We will carry on nonetheless.
        //
        JITDUMP("   ... call site not profiled, will use non-pgo weight to scale\n");
    }

    const weight_t callSiteWeight = callSiteBlock->bbWeight;

    // Call site has zero count?
    //
    // Todo: perhaps retain some semblance of callee profile data,
    // possibly scaled down severely.
    //
    // You might wonder why we bother to inline at cold sites.
    // Recall ALWAYS and FORCE inlines bypass all profitability checks.
    // And, there can be hot-path benefits to a cold-path inline.
    //
    if (callSiteWeight == BB_ZERO_WEIGHT)
    {
        JITDUMP("   ... zero call site count; scale will be 0.0\n");
    }

    // If profile data reflects a complete single run we can expect
    // calleeWeight >= callSiteWeight.
    //
    // However if our profile is just a subset of execution we may
    // not see this.
    //
    // So, we are willing to scale the callee counts down or up as
    // needed to match the call site.
    //
    // Hence, scale can be somewhat arbitrary...
    //
    const weight_t scale = callSiteWeight / calleeWeight;

    JITDUMP("   call site count " FMT_WT " callee entry count " FMT_WT " scale " FMT_WT "\n", callSiteWeight,
            calleeWeight, scale);
    JITDUMP("Scaling inlinee blocks\n");

    for (BasicBlock* const block : Blocks())
    {
        block->scaleBBWeight(scale);
    }
}

//------------------------------------------------------------------------
// fgGetProfileWeightForBasicBlock: obtain profile data for a block
//
// Arguments:
//   offset       - IL offset of the block
//   weightWB     - [OUT] weight obtained
//
// Returns:
//   true if data was found
//
bool Compiler::fgGetProfileWeightForBasicBlock(IL_OFFSET offset, weight_t* weightWB)
{
    noway_assert(weightWB != nullptr);
    weight_t weight = 0;

#ifdef DEBUG
    unsigned hashSeed = fgStressBBProf();
    if (hashSeed != 0)
    {
        unsigned hash = (info.compMethodHash() * hashSeed) ^ (offset * 1027);

        // We need to especially stress the procedure splitting codepath.  Therefore
        // one third the time we should return a weight of zero.
        // Otherwise we should return some random weight (usually between 0 and 288).
        // The below gives a weight of zero, 44% of the time

        if (hash % 3 == 0)
        {
            weight = BB_ZERO_WEIGHT;
        }
        else if (hash % 11 == 0)
        {
            weight = (weight_t)(hash % 23) * (hash % 29) * (hash % 31);
        }
        else
        {
            weight = (weight_t)(hash % 17) * (hash % 19);
        }

        // The first block is never given a weight of zero
        if ((offset == 0) && (weight == BB_ZERO_WEIGHT))
        {
            weight = (weight_t)1 + (hash % 5);
        }

        *weightWB = weight;
        return true;
    }
#endif // DEBUG

    if (!fgHaveProfileWeights())
    {
        return false;
    }

    for (UINT32 i = 0; i < fgPgoSchemaCount; i++)
    {
        if ((IL_OFFSET)fgPgoSchema[i].ILOffset != offset)
        {
            continue;
        }

        if (fgPgoSchema[i].InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::BasicBlockIntCount)
        {
            *weightWB = (weight_t) * (uint32_t*)(fgPgoData + fgPgoSchema[i].Offset);
            return true;
        }

        if (fgPgoSchema[i].InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::BasicBlockLongCount)
        {
            *weightWB = (weight_t) * (uint64_t*)(fgPgoData + fgPgoSchema[i].Offset);
            return true;
        }
    }

    *weightWB = 0;
    return true;
}

typedef jitstd::vector<ICorJitInfo::PgoInstrumentationSchema> Schema;

//------------------------------------------------------------------------
// Instrumentor: base class for count and class instrumentation
//
class Instrumentor
{
protected:
    Compiler* m_comp;
    unsigned  m_schemaCount;
    unsigned  m_instrCount;
    bool      m_modifiedFlow;

protected:
    Instrumentor(Compiler* comp)
        : m_comp(comp)
        , m_schemaCount(0)
        , m_instrCount(0)
        , m_modifiedFlow(false)
    {
    }

public:
    virtual bool ShouldProcess(BasicBlock* block)
    {
        return false;
    }
    virtual bool ShouldInstrument(BasicBlock* block)
    {
        return ShouldProcess(block);
    }
    virtual void Prepare(bool preImport)
    {
    }
    virtual void BuildSchemaElements(BasicBlock* block, Schema& schema)
    {
    }
    virtual void Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory)
    {
    }
    unsigned SchemaCount() const
    {
        return m_schemaCount;
    }
    unsigned InstrCount() const
    {
        return m_instrCount;
    }

    void SetModifiedFlow()
    {
        m_modifiedFlow = true;
    }

    bool ModifiedFlow() const
    {
        return m_modifiedFlow;
    }
};

//------------------------------------------------------------------------
// NonInstrumentor: instrumentor that does not instrument anything
//
class NonInstrumentor : public Instrumentor
{
public:
    NonInstrumentor(Compiler* comp)
        : Instrumentor(comp)
    {
    }
};

//------------------------------------------------------------------------
// BlockCountInstrumentor: instrumentor that adds a counter to each
//   non-internal imported basic block
//
class BlockCountInstrumentor : public Instrumentor
{
private:
    void        RelocateProbes();
    BasicBlock* m_entryBlock;

public:
    BlockCountInstrumentor(Compiler* comp)
        : Instrumentor(comp)
        , m_entryBlock(nullptr)
    {
    }
    bool ShouldProcess(BasicBlock* block) override
    {
        return block->HasFlag(BBF_IMPORTED) && !block->HasFlag(BBF_INTERNAL);
    }
    void Prepare(bool isPreImport) override;
    void BuildSchemaElements(BasicBlock* block, Schema& schema) override;
    void Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory) override;

    static GenTree* CreateCounterIncrement(Compiler* comp, uint8_t* counterAddr, var_types countType);
};

//------------------------------------------------------------------------
// BlockCountInstrumentor::Prepare: prepare for count instrumentation
//
// Arguments:
//   preImport - true if this is the prepare call that happens before
//      importation
//
void BlockCountInstrumentor::Prepare(bool preImport)
{
    if (preImport)
    {
        return;
    }

    RelocateProbes();

#ifdef DEBUG
    // Set schema index to invalid value
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        block->bbCountSchemaIndex = -1;
    }
#endif
}

//------------------------------------------------------------------------
// BlockCountInstrumentor::RelocateProbes: relocate any probes that
//   would appear in post-tail call blocks.
//
// Notes:
//   Conveys relocation information by updating the m_relocationMap.
//
//   Actual relocation happens during Instrument, keying off of the
//   BBF_TAILCALL_SUCCESSOR flag and m_relocationMap entries.
//
void BlockCountInstrumentor::RelocateProbes()
{
    // We only see such blocks when optimizing. They are flagged by the importer.
    //
    if (!m_comp->opts.IsInstrumentedAndOptimized() || ((m_comp->optMethodFlags & OMF_HAS_TAILCALL_SUCCESSOR) == 0))
    {
        // No problematic blocks to worry about.
        //
        return;
    }

    JITDUMP("Optimized + instrumented + potential tail calls --- preparing to relocate edge probes\n");

    // We should be in a root method compiler instance. We currently do not instrument inlinees.
    //
    // Relaxing this will require changes below because inlinee compilers
    // share the root compiler flow graph (and hence bb epoch), and flow
    // from inlinee tail calls to returns can be more complex.
    //
    assert(!m_comp->compIsForInlining());

    // Keep track of return blocks needing special treatment.
    //
    ArrayStack<BasicBlock*> criticalPreds(m_comp->getAllocator(CMK_Pgo));

    // Walk blocks looking for BBJ_RETURNs that are successors of potential tail calls.
    //
    // If any such block has a conditional pred, we will need to reroute flow from those preds
    // via an intermediary block. That block will subsequently hold the relocated block
    // probe for the returnBlock for those preds.
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        // Ignore blocks that we won't process.
        //
        if (!ShouldProcess(block))
        {
            continue;
        }

        if (!block->HasFlag(BBF_TAILCALL_SUCCESSOR))
        {
            continue;
        }

        JITDUMP("Return " FMT_BB " is successor of possible tail call\n", block->bbNum);
        assert(block->KindIs(BBJ_RETURN));

        // Scan for critical preds, and add relocated probes to non-critical preds.
        //
        criticalPreds.Reset();
        for (BasicBlock* const pred : block->PredBlocks())
        {
            if (!ShouldProcess(pred))
            {
                JITDUMP(FMT_BB " -> " FMT_BB " is dead edge\n", pred->bbNum, block->bbNum);
                continue;
            }

            BasicBlock* const succ = pred->GetUniqueSucc();

            if ((succ == nullptr) || pred->isBBCallFinallyPairTail())
            {
                // Route pred through the intermediary.
                //
                JITDUMP(FMT_BB " -> " FMT_BB " is critical edge\n", pred->bbNum, block->bbNum);
                criticalPreds.Push(pred);
            }
            else
            {
                assert(pred->KindIs(BBJ_ALWAYS));
            }
        }

        // If there are any critical preds, create and instrument the
        // intermediary and reroute flow. Mark the intermediary so we make
        // sure to instrument it later.
        //
        if (criticalPreds.Height() > 0)
        {
            BasicBlock* const intermediary = m_comp->fgNewBBbefore(BBJ_ALWAYS, block, /* extendRegion */ true);
            intermediary->SetFlags(BBF_IMPORTED | BBF_MARKED);
            intermediary->inheritWeight(block);
            FlowEdge* const newEdge = m_comp->fgAddRefPred(block, intermediary);
            intermediary->SetTargetEdge(newEdge);
            SetModifiedFlow();

            while (criticalPreds.Height() > 0)
            {
                BasicBlock* const pred = criticalPreds.Pop();

                // Redirect any jumps
                //
                m_comp->fgReplaceJumpTarget(pred, block, intermediary);
            }
        }
    }
}

//------------------------------------------------------------------------
// BlockCountInstrumentor::BuildSchemaElements: create schema elements for a block counter
//
// Arguments:
//   block -- block to instrument
//   schema -- schema that we're building
//
void BlockCountInstrumentor::BuildSchemaElements(BasicBlock* block, Schema& schema)
{
    unsigned numCountersPerProbe = 1;

    // When we have both interlocked and scalable profile modes enabled, we will
    // count both ways, so allocate two count slots per probe.
    //
    if ((JitConfig.JitScalableProfiling() > 0) && (JitConfig.JitInterlockedProfiling() > 0))
    {
        numCountersPerProbe = 2;
    }
    else if (JitConfig.JitCounterPadding() > 0)
    {
        numCountersPerProbe = (unsigned)JitConfig.JitCounterPadding();
    }

    // Remember the schema index for this block.
    //
    assert(block->bbCountSchemaIndex == -1);
    block->bbCountSchemaIndex = (int)schema.size();

    // Assign the current block's IL offset into the profile data
    // (make sure IL offset is sane)
    //
    IL_OFFSET offset = block->bbCodeOffs;
    assert((int)offset >= 0);

    ICorJitInfo::PgoInstrumentationSchema schemaElem;
    schemaElem.Count               = numCountersPerProbe;
    schemaElem.Other               = 0;
    schemaElem.InstrumentationKind = m_comp->opts.compCollect64BitCounts
                                         ? ICorJitInfo::PgoInstrumentationKind::BasicBlockLongCount
                                         : ICorJitInfo::PgoInstrumentationKind::BasicBlockIntCount;
    schemaElem.ILOffset            = offset;
    schemaElem.Offset              = 0;

    schema.push_back(schemaElem);

    m_schemaCount++;

    // If this is the entry block, remember it for later.
    // Note it might not be fgFirstBB, if we have a scratchBB.
    //
    if (offset == 0)
    {
        assert(m_entryBlock == nullptr);
        m_entryBlock = block;
    }
}

//------------------------------------------------------------------------
// BlockCountInstrumentor::Instrument: add counter probe to block
//
// Arguments:
//   block -- block of interest
//   schema -- instrumentation schema
//   profileMemory -- profile data slab
//
void BlockCountInstrumentor::Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory)
{
    const ICorJitInfo::PgoInstrumentationSchema& entry = schema[block->bbCountSchemaIndex];

    assert(block->bbCodeOffs == (IL_OFFSET)entry.ILOffset);
    assert((entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::BasicBlockIntCount) ||
           (entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::BasicBlockLongCount));
    uint8_t* addrOfCurrentExecutionCount = entry.Offset + profileMemory;

#ifdef DEBUG
    if (JitConfig.JitPropagateSynthesizedCountsToProfileData() > 0)
    {
        // Write the current synthesized count as the profile data
        //
        weight_t blockWeight = block->bbWeight;

        if (entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeIntCount)
        {
            *((uint32_t*)addrOfCurrentExecutionCount) = (uint32_t)blockWeight;
        }
        else
        {
            *((uint64_t*)addrOfCurrentExecutionCount) = (uint64_t)blockWeight;
        }

        return;
    }
#endif

    var_types typ =
        entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::BasicBlockIntCount ? TYP_INT : TYP_LONG;

    GenTree* incCount = CreateCounterIncrement(m_comp, addrOfCurrentExecutionCount, typ);

    if (block->HasFlag(BBF_TAILCALL_SUCCESSOR))
    {
        // This block probe needs to be relocated; instrument each predecessor.
        //
        bool first = true;
        for (BasicBlock* pred : block->PredBlocks())
        {
            const bool isLivePred = ShouldProcess(pred) || pred->HasFlag(BBF_MARKED);
            if (!isLivePred)
            {
                continue;
            }

            JITDUMP("Placing copy of block probe for " FMT_BB " in pred " FMT_BB "\n", block->bbNum, pred->bbNum);
            if (!first)
            {
                incCount = m_comp->gtCloneExpr(incCount);
            }
            m_comp->fgNewStmtAtBeg(pred, incCount);
            pred->RemoveFlags(BBF_MARKED);
            first = false;
        }
    }
    else
    {
        m_comp->fgNewStmtAtBeg(block, incCount);
    }

    m_instrCount++;
}

//------------------------------------------------------------------------
// BlockCountInstrumentor::CreateCounterIncrement: create a tree that increments a profile counter.
//
// Arguments:
//   comp        - compiler instance
//   counterAddr - address of counter to increment
//   countType   - type of counter
//
// Returns:
//   A node that increments the specified count.
//
GenTree* BlockCountInstrumentor::CreateCounterIncrement(Compiler* comp, uint8_t* counterAddr, var_types countType)
{
    const bool interlocked = JitConfig.JitInterlockedProfiling() > 0;
    const bool scalable    = JitConfig.JitScalableProfiling() > 0;

    if (interlocked || scalable)
    {
        GenTree* result = nullptr;

        if (interlocked)
        {
            // Form counter address
            GenTree* addressNode = comp->gtNewIconHandleNode(reinterpret_cast<size_t>(counterAddr), GTF_ICON_BBC_PTR);

            // Interlocked increment
            result = comp->gtNewAtomicNode(GT_XADD, countType, addressNode, comp->gtNewIconNode(1, countType));
        }

        if (scalable)
        {
            if (interlocked)
            {
                assert(result != nullptr);
                counterAddr += (countType == TYP_INT) ? 4 : 8;
            }

            // Form counter address
            GenTree* addressNode = comp->gtNewIconHandleNode(reinterpret_cast<size_t>(counterAddr), GTF_ICON_BBC_PTR);

            // Scalable increment
            GenTree* scalableNode = comp->gtNewHelperCallNode((countType == TYP_INT) ? CORINFO_HELP_COUNTPROFILE32
                                                                                     : CORINFO_HELP_COUNTPROFILE64,
                                                              countType, addressNode);

            if (interlocked)
            {
                result = comp->gtNewOperNode(GT_COMMA, countType, result, scalableNode);
            }
            else
            {
                result = scalableNode;
            }
        }

        return result;
    }

    // Else do an unsynchronized update
    //

    // Read Basic-Block count value
    GenTree* valueNode =
        comp->gtNewIndOfIconHandleNode(countType, reinterpret_cast<size_t>(counterAddr), GTF_ICON_BBC_PTR);

    // Increment value by 1
    GenTree* incValueNode = comp->gtNewOperNode(GT_ADD, countType, valueNode, comp->gtNewIconNode(1, countType));

    // Write new Basic-Block count value
    GenTree* counterAddrNode = comp->gtNewIconHandleNode(reinterpret_cast<size_t>(counterAddr), GTF_ICON_BBC_PTR);
    GenTree* updateNode      = comp->gtNewStoreIndNode(countType, counterAddrNode, incValueNode);

    return updateNode;
}

//------------------------------------------------------------------------
// SpanningTreeVisitor: abstract class for computations done while
//   evolving a spanning tree.
//
class SpanningTreeVisitor
{
public:
    // To save visitors a bit of work, we also note
    // for non-tree edges whether the edge postdominates
    // the source, dominates the target, or is a critical edge.
    //
    // Later we may need to relocate or duplicate probes. We
    // overload this enum to also represent those cases.
    //
    enum class EdgeKind
    {
        Unknown,
        PostdominatesSource,
        Pseudo,
        DominatesTarget,
        CriticalEdge,
        Deleted,
        Relocated,
        Leader,
        Duplicate
    };

    virtual void Badcode()                                                               = 0;
    virtual void VisitBlock(BasicBlock* block)                                           = 0;
    virtual void VisitTreeEdge(BasicBlock* source, BasicBlock* target)                   = 0;
    virtual void VisitNonTreeEdge(BasicBlock* source, BasicBlock* target, EdgeKind kind) = 0;
};

//------------------------------------------------------------------------
// WalkSpanningTree: evolve a "maximal cost" depth first spanning tree,
//   invoking the visitor as each edge is classified, or each node is first
//   discovered.
//
// Arguments:
//    visitor - visitor to notify
//
// Notes:
//   We only have rudimentary weights at this stage, and so in practice
//   we use a depth-first spanning tree (DFST) where we try to steer
//   the DFS to preferentially visit "higher" cost edges.
//
//   Since instrumentation happens after profile incorporation
//   we could in principle use profile weights to steer the DFS or to build
//   a true maximum weight tree. However we are relying on being able to
//   rebuild the exact same spanning tree "later on" when doing a subsequent
//   profile reconstruction. So, we restrict ourselves to just using
//   information apparent in the IL.
//
void Compiler::WalkSpanningTree(SpanningTreeVisitor* visitor)
{
    // We will track visited or queued nodes with a bit vector.
    //
    BitVecTraits traits(compBasicBlockID, this);
    BitVec       marked = BitVecOps::MakeEmpty(&traits);

    // And nodes to visit with a bit vector and stack.
    //
    ArrayStack<BasicBlock*> stack(getAllocator(CMK_Pgo));

    // Scratch vector for visiting successors of blocks with
    // multiple successors.
    //
    // Bit vector to track progress through those successors.
    //
    ArrayStack<BasicBlock*> scratch(getAllocator(CMK_Pgo));
    BitVec                  processed = BitVecOps::MakeEmpty(&traits);

    // Push the method entry and all EH handler region entries on the stack.
    // (push method entry last so it's visited first).
    //
    // Note inlinees are "contaminated" with root method EH structures.
    // We know the inlinee itself doesn't have EH, so we only look at
    // handlers for root methods.
    //
    // If we ever want to support inlining methods with EH, we'll
    // have to revisit this.
    //
    if (!compIsForInlining())
    {
        for (EHblkDsc* const HBtab : EHClauses(this))
        {
            BasicBlock* hndBegBB = HBtab->ebdHndBeg;
            stack.Push(hndBegBB);
            BitVecOps::AddElemD(&traits, marked, hndBegBB->bbID);
            if (HBtab->HasFilter())
            {
                BasicBlock* filterBB = HBtab->ebdFilter;
                stack.Push(filterBB);
                BitVecOps::AddElemD(&traits, marked, filterBB->bbID);
            }
        }
    }

    stack.Push(fgFirstBB);
    BitVecOps::AddElemD(&traits, marked, fgFirstBB->bbID);

    unsigned nBlocks = 0;

    while (!stack.Empty())
    {
        BasicBlock* const block = stack.Pop();

        // Visit the block.
        //
        assert(BitVecOps::IsMember(&traits, marked, block->bbID));
        visitor->VisitBlock(block);
        nBlocks++;

        switch (block->GetKind())
        {
            case BBJ_CALLFINALLY:
            {
                // Just queue up the continuation block,
                // unless the finally doesn't return, in which
                // case we really should treat this block as a throw,
                // and so this block would get instrumented.
                //
                // Since our keying scheme is IL based and this
                // block has no IL offset, we'd need to invent
                // some new keying scheme. For now we just
                // ignore this (rare) case.
                //
                if (block->isBBCallFinallyPair())
                {
                    // This block should be the only pred of the continuation.
                    //
                    BasicBlock* const target = block->Next();
                    assert(!BitVecOps::IsMember(&traits, marked, target->bbID));
                    visitor->VisitTreeEdge(block, target);
                    stack.Push(target);
                    BitVecOps::AddElemD(&traits, marked, target->bbID);
                }
            }
            break;

            case BBJ_THROW:

                // Ignore impact of throw blocks on flow,  if we're doing minimal
                // method profiling, and it appears the method can return without throwing.
                //
                // fgReturnCount is provisionally set in fgFindBasicBlocks based on
                // the raw IL stream prescan.
                //
                if (JitConfig.JitMinimalJitProfiling() && (fgReturnCount > 0))
                {
                    break;
                }

                __fallthrough;

            case BBJ_RETURN:
            {
                // Pseudo-edge back to method entry.
                //
                // Note if the throw is caught locally this will over-state the profile
                // count for method entry. But we likely don't care too much about
                // profiles for methods that throw lots of exceptions.
                //
                BasicBlock* const target = fgFirstBB;
                assert(BitVecOps::IsMember(&traits, marked, target->bbID));
                visitor->VisitNonTreeEdge(block, target, SpanningTreeVisitor::EdgeKind::Pseudo);
            }
            break;

            case BBJ_EHFINALLYRET:
            case BBJ_EHFAULTRET:
            case BBJ_EHCATCHRET:
            case BBJ_EHFILTERRET:
            case BBJ_LEAVE:
            {
                // See if we're leaving an EH handler region.
                //
                bool            isInTry     = false;
                unsigned const  regionIndex = ehGetMostNestedRegionIndex(block, &isInTry);
                EHblkDsc* const dsc         = ehGetBlockHndDsc(block);

                if (isInTry || (dsc->ebdHandlerType == EH_HANDLER_CATCH))
                {
                    // We're leaving a try or catch, not a handler.
                    // Treat this as a normal edge.
                    //
                    BasicBlock* const target = block->GetTarget();

                    // In some bad IL cases we may not have a target.
                    // In others we may see something other than LEAVE be most-nested in a try.
                    //
                    if (target == nullptr)
                    {
                        JITDUMP("No jump dest for " FMT_BB ", suspect bad code\n", block->bbNum);
                        visitor->Badcode();
                    }
                    else if (!block->KindIs(BBJ_LEAVE))
                    {
                        JITDUMP("EH RET in " FMT_BB " most-nested in try, suspect bad code\n", block->bbNum);
                        visitor->Badcode();
                    }
                    else
                    {
                        if (BitVecOps::IsMember(&traits, marked, target->bbID))
                        {
                            visitor->VisitNonTreeEdge(block, target,
                                                      SpanningTreeVisitor::EdgeKind::PostdominatesSource);
                        }
                        else
                        {
                            visitor->VisitTreeEdge(block, target);
                            stack.Push(target);
                            BitVecOps::AddElemD(&traits, marked, target->bbID);
                        }
                    }
                }
                else
                {
                    // Pseudo-edge back to handler entry.
                    //
                    BasicBlock* const target = dsc->ebdHndBeg;
                    assert(BitVecOps::IsMember(&traits, marked, target->bbID));
                    visitor->VisitNonTreeEdge(block, target, SpanningTreeVisitor::EdgeKind::Pseudo);
                }
            }
            break;

            default:
            {
                // If this block is a control flow fork, we want to
                // preferentially visit critical edges first; if these
                // edges end up in the DFST then instrumentation will
                // require edge splitting.
                //
                // We also want to preferentially visit edges to rare
                // successors last, if this block is non-rare.
                //
                // It's not immediately clear if we should pass comp or this
                // to NumSucc here (for inlinees).
                //
                // It matters for FINALLYRET and for SWITCHES. Currently
                // we handle the first one specially, and it seems possible
                // things will just work for switches either way, but it
                // might work a bit better using the root compiler.
                //
                const unsigned numSucc = block->NumSucc();

                if (numSucc == 1)
                {
                    // Not a fork. Just visit the sole successor.
                    //
                    BasicBlock* const target = block->GetSucc(0);
                    if (BitVecOps::IsMember(&traits, marked, target->bbID))
                    {
                        // We can't instrument in the call finally pair tail block
                        // so treat this as a critical edge.
                        //
                        visitor->VisitNonTreeEdge(block, target,
                                                  block->isBBCallFinallyPairTail()
                                                      ? SpanningTreeVisitor::EdgeKind::CriticalEdge
                                                      : SpanningTreeVisitor::EdgeKind::PostdominatesSource);
                    }
                    else
                    {
                        visitor->VisitTreeEdge(block, target);
                        stack.Push(target);
                        BitVecOps::AddElemD(&traits, marked, target->bbID);
                    }
                }
                else
                {
                    // A block with multiple successors.
                    //
                    // Because we're using a stack up above, we work in reverse
                    // order of "cost" here --  so we first consider rare,
                    // then normal, then critical.
                    //
                    // That is, all things being equal we'd prefer to
                    // have critical edges be tree edges, and
                    // edges from non-rare to rare be non-tree edges.
                    //
                    scratch.Reset();
                    BitVecOps::ClearD(&traits, processed);

                    for (unsigned i = 0; i < numSucc; i++)
                    {
                        BasicBlock* const succ = block->GetSucc(i);
                        scratch.Push(succ);
                    }

                    // Rare successors of non-rare blocks
                    //
                    for (unsigned i = 0; i < numSucc; i++)
                    {
                        BasicBlock* const target = scratch.Top(i);

                        if (BitVecOps::IsMember(&traits, processed, i))
                        {
                            continue;
                        }

                        if (block->isRunRarely() || !target->isRunRarely())
                        {
                            continue;
                        }

                        BitVecOps::AddElemD(&traits, processed, i);

                        if (BitVecOps::IsMember(&traits, marked, target->bbID))
                        {
                            visitor->VisitNonTreeEdge(block, target,
                                                      target->bbRefs > 1
                                                          ? SpanningTreeVisitor::EdgeKind::CriticalEdge
                                                          : SpanningTreeVisitor::EdgeKind::DominatesTarget);
                        }
                        else
                        {
                            visitor->VisitTreeEdge(block, target);
                            stack.Push(target);
                            BitVecOps::AddElemD(&traits, marked, target->bbID);
                        }
                    }

                    // Non-critical edges
                    //
                    for (unsigned i = 0; i < numSucc; i++)
                    {
                        BasicBlock* const target = scratch.Top(i);

                        if (BitVecOps::IsMember(&traits, processed, i))
                        {
                            continue;
                        }

                        if (target->bbRefs != 1)
                        {
                            continue;
                        }

                        BitVecOps::AddElemD(&traits, processed, i);

                        if (BitVecOps::IsMember(&traits, marked, target->bbID))
                        {
                            visitor->VisitNonTreeEdge(block, target, SpanningTreeVisitor::EdgeKind::DominatesTarget);
                        }
                        else
                        {
                            visitor->VisitTreeEdge(block, target);
                            stack.Push(target);
                            BitVecOps::AddElemD(&traits, marked, target->bbID);
                        }
                    }

                    // Critical edges
                    //
                    for (unsigned i = 0; i < numSucc; i++)
                    {
                        BasicBlock* const target = scratch.Top(i);

                        if (BitVecOps::IsMember(&traits, processed, i))
                        {
                            continue;
                        }

                        BitVecOps::AddElemD(&traits, processed, i);

                        if (BitVecOps::IsMember(&traits, marked, target->bbID))
                        {
                            visitor->VisitNonTreeEdge(block, target, SpanningTreeVisitor::EdgeKind::CriticalEdge);
                        }
                        else
                        {
                            visitor->VisitTreeEdge(block, target);
                            stack.Push(target);
                            BitVecOps::AddElemD(&traits, marked, target->bbID);
                        }
                    }

                    // Verify we processed each successor.
                    //
                    assert(numSucc == BitVecOps::Count(&traits, processed));
                }
            }
            break;
        }
    }

    // Notify visitor of remaining blocks
    //
    for (BasicBlock* const block : Blocks())
    {
        if (!BitVecOps::IsMember(&traits, marked, block->bbID))
        {
            visitor->VisitBlock(block);
        }
    }
}

// Map a block into its schema key we will use for storing basic blocks.
//
static int32_t EfficientEdgeCountBlockToKey(BasicBlock* block)
{
    static const int IS_INTERNAL_BLOCK = (int32_t)0x80000000;
    int32_t          key               = (int32_t)block->bbCodeOffs;
    // We may see empty BBJ_ALWAYS BBF_INTERNAL blocks that were added
    // by fgNormalizeEH.
    //
    // We'll use their bbNum in place of IL offset, and set
    // a high bit as a "flag"
    //
    if (block->HasFlag(BBF_INTERNAL))
    {
        key = block->bbNum | IS_INTERNAL_BLOCK;
    }

    return key;
}

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor: instrumentor that adds a counter to
//   selective edges.
//
// Based on "Optimally Profiling and Tracing Programs,"
// Ball and Larus PLDI '92.
//
class EfficientEdgeCountInstrumentor
    : public Instrumentor
    , public SpanningTreeVisitor
{
private:
    // A particular edge probe. These are linked
    // on the source block via bbSparseProbeList.
    //
    struct Probe
    {
        BasicBlock* source;
        BasicBlock* target;
        Probe*      next;
        int         schemaIndex;
        EdgeKind    kind;
        Probe*      leader;
    };

    // Add probe to block, representing edge from source to target.
    //
    Probe* NewProbe(BasicBlock* block, BasicBlock* source, BasicBlock* target)
    {
        Probe* p       = new (m_comp, CMK_Pgo) Probe();
        p->source      = source;
        p->target      = target;
        p->kind        = EdgeKind::Unknown;
        p->schemaIndex = -1;
        p->next        = (Probe*)block->bbSparseProbeList;
        p->leader      = nullptr;

        block->bbSparseProbeList = p;
        m_probeCount++;

        return p;
    }

    void NewSourceProbe(BasicBlock* source, BasicBlock* target)
    {
        JITDUMP("[%u] New probe for " FMT_BB " -> " FMT_BB " [source]\n", m_probeCount, source->bbNum, target->bbNum);
        Probe* p = NewProbe(source, source, target);
        p->kind  = EdgeKind::PostdominatesSource;
    }

    void NewTargetProbe(BasicBlock* source, BasicBlock* target)
    {
        JITDUMP("[%u] New probe for " FMT_BB " -> " FMT_BB " [target]\n", m_probeCount, source->bbNum, target->bbNum);

        Probe* p = NewProbe(source, source, target);
        p->kind  = EdgeKind::DominatesTarget;
    }

    void NewEdgeProbe(BasicBlock* source, BasicBlock* target)
    {
        JITDUMP("[%u] New probe for " FMT_BB " -> " FMT_BB " [edge]\n", m_probeCount, source->bbNum, target->bbNum);

        Probe* p = NewProbe(source, source, target);
        p->kind  = EdgeKind::CriticalEdge;

        m_edgeProbeCount++;
    }

    void NewRelocatedProbe(BasicBlock* block, BasicBlock* source, BasicBlock* target, Probe** pLeader = nullptr)
    {
        Probe*      p   = NewProbe(block, source, target);
        const char* msg = "unknown";

        // Are we starting or adding to a duplicate group?
        //
        if (pLeader != nullptr)
        {
            Probe* l = *pLeader;
            if (l == nullptr)
            {
                // This probe will be the leader of the group
                //
                *pLeader = p;
                p->kind  = EdgeKind::Leader;
                msg      = "leader";
            }
            else
            {
                // This probe is a duplicate
                //
                p->leader = l;
                p->kind   = EdgeKind::Duplicate;
                msg       = "duplicate";
            }
        }
        else
        {
            p->kind = EdgeKind::Relocated;
            msg     = "relocated";
        }

        JITDUMP("New %s probe for " FMT_BB " -> " FMT_BB " [reloc to " FMT_BB " ]\n", msg, source->bbNum, target->bbNum,
                block->bbNum);
    }

    void SplitCriticalEdges();
    void RelocateProbes();

    unsigned m_blockCount;
    unsigned m_probeCount;
    unsigned m_edgeProbeCount;
    bool     m_badcode;
    bool     m_minimal;

public:
    EfficientEdgeCountInstrumentor(Compiler* comp, bool minimal)
        : Instrumentor(comp)
        , SpanningTreeVisitor()
        , m_blockCount(0)
        , m_probeCount(0)
        , m_edgeProbeCount(0)
        , m_badcode(false)
        , m_minimal(minimal)
    {
    }
    void Prepare(bool isPreImport) override;
    bool ShouldProcess(BasicBlock* block) override
    {
        return block->HasFlag(BBF_IMPORTED);
    }
    bool ShouldInstrument(BasicBlock* block) override
    {
        return ShouldProcess(block) && ((!m_minimal) || (m_schemaCount > 1));
    }
    void BuildSchemaElements(BasicBlock* block, Schema& schema) override;
    void Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory) override;

    void Badcode() override
    {
        m_badcode = true;
    }

    void VisitBlock(BasicBlock* block) override
    {
        m_blockCount++;
        block->bbSparseProbeList = nullptr;
    }

    void VisitTreeEdge(BasicBlock* source, BasicBlock* target) override
    {
    }

    void VisitNonTreeEdge(BasicBlock* source, BasicBlock* target, SpanningTreeVisitor::EdgeKind kind) override
    {
        switch (kind)
        {
            case EdgeKind::PostdominatesSource:
            case EdgeKind::Pseudo:
                NewSourceProbe(source, target);
                break;
            case EdgeKind::DominatesTarget:
                NewTargetProbe(source, target);
                break;
            case EdgeKind::CriticalEdge:
                NewEdgeProbe(source, target);
                break;
            default:
                assert(!"unexpected edge kind");
                break;
        }
    }
};

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor::Prepare: analyze the flow graph to
//   determine which edges should be instrumented.
//
// Arguments:
//   preImport - true if this is the prepare call that happens before
//      importation
//
// Notes:
//   Build a (maximum weight) spanning tree and designate the non-tree
//   edges as the ones needing instrumentation.
//
//   For non-critical edges, instrumentation happens in either the
//   predecessor or successor blocks.
//
//   Note we may only schematize and instrument a subset of the full
//   set of instrumentation envisioned here, if the method is partially
//   imported, as subsequent "passes" will bypass un-imported blocks.
//
//   It might be preferable to export the full schema but only
//   selectively instrument; this would make merging and importing
//   of data simpler, as all schemas for a method would agree, no
//   matter what importer-level opts were applied.
//
void EfficientEdgeCountInstrumentor::Prepare(bool preImport)
{
    if (preImport)
    {
        JITDUMP("\nEfficientEdgeCountInstrumentor: preparing for instrumentation\n");
        m_comp->WalkSpanningTree(this);
        JITDUMP("%u blocks, %u probes (%u on critical edges)\n", m_blockCount, m_probeCount, m_edgeProbeCount);
        return;
    }

    // If we saw badcode in the preimport prepare, we would expect
    // compilation to blow up in the importer. So if we end up back
    // here postimport with badcode set, something is wrong.
    //
    assert(!m_badcode);

    // Walk the probe list splitting critical edges as required.
    //
    SplitCriticalEdges();

    // If this is an optimized method, look for potential tail calls in
    // probe blocks that are not BBJ_RETURN.
    //
    // If we see any, we need to adjust our instrumentation pattern.
    //
    RelocateProbes();
}

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor::SplitCriticalEdges: add blocks for
//   probes along critical edges and adjust affeted probes and probe lists.
//
//
// Notes:
//   Transforms CriticalEdge probes to Deleted and/or Relocated probes.
//
void EfficientEdgeCountInstrumentor::SplitCriticalEdges()
{
    if (m_edgeProbeCount == 0)
    {
        return;
    }

    JITDUMP("\nEfficientEdgeCountInstrumentor: splitting up to %u critical edges\n", m_edgeProbeCount);
    unsigned edgesSplit   = 0;
    unsigned edgesIgnored = 0;

    for (BasicBlock* const block : m_comp->Blocks())
    {
        if (!ShouldProcess(block))
        {

#ifdef DEBUG
            // Account for probes originating from un-imported blocks.
            //
            for (Probe* probe = (Probe*)block->bbSparseProbeList; probe != nullptr; probe = probe->next)
            {
                if (probe->kind == EdgeKind::CriticalEdge)
                {
                    edgesIgnored++;
                }
            }
#endif

            continue;
        }

        for (Probe* probe = (Probe*)block->bbSparseProbeList; probe != nullptr; probe = probe->next)
        {
            // Figure out what block the probe will appear in.
            //
            BasicBlock* const source            = probe->source;
            BasicBlock* const target            = probe->target;
            BasicBlock*       instrumentedBlock = nullptr;

            switch (probe->kind)
            {
                case EdgeKind::PostdominatesSource:
                    instrumentedBlock = source;
                    break;
                case EdgeKind::DominatesTarget:
                    instrumentedBlock = target;
                    break;
                case EdgeKind::Relocated:
                    instrumentedBlock = block;
                    break;
                case EdgeKind::CriticalEdge:
                {
                    assert(block == source);

                    // See if the edge still exists.
                    //
                    bool found = false;
                    for (BasicBlock* const succ : block->Succs())
                    {
                        if (target == succ)
                        {
                            found = true;
                            break;
                        }
                    }

                    if (found)
                    {
                        instrumentedBlock = m_comp->fgSplitEdge(block, target);
                        instrumentedBlock->SetFlags(BBF_IMPORTED);
                        edgesSplit++;

                        // Add in the relocated probe
                        //
                        NewRelocatedProbe(instrumentedBlock, source, target);
                    }
                    else
                    {
                        JITDUMP("Could not find " FMT_BB " -> " FMT_BB " edge to instrument\n", block->bbNum,
                                target->bbNum);

                        JITDUMP(" -- assuming this edge was folded away by the importer\n");

                        // Placate the asserts below
                        //
                        instrumentedBlock = source;
                        edgesIgnored++;
                    }

                    // Delete the critical edge probe
                    //
                    probe->kind = EdgeKind::Deleted;
                }
                break;

                default:
                    assert(!"unexpected edge kind");
            }

            assert(instrumentedBlock != nullptr);
        }
    }

    // We should have found all edges needing splitting.
    //
    assert((edgesSplit + edgesIgnored) == m_edgeProbeCount);

    if (edgesSplit > 0)
    {
        SetModifiedFlow();
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor::RelocateProbes: relocate any probes that
//   would appear in post-tail call blocks.
//
// Notes:
//   May create Leader and Duplicate probes.
//
void EfficientEdgeCountInstrumentor::RelocateProbes()
{
    // We only see such blocks when optimizing. They are flagged by the importer.
    //
    if (!m_comp->opts.IsInstrumentedAndOptimized() || ((m_comp->optMethodFlags & OMF_HAS_TAILCALL_SUCCESSOR) == 0))
    {
        // No problematic blocks to worry about.
        //
        return;
    }

    JITDUMP("Optimized + instrumented + potential tail calls --- preparing to relocate edge probes\n");

    // We should be in a root method compiler instance. We currently do not instrument inlinees.
    //
    // Relaxing this will require changes below because inlinee compilers
    // share the root compiler flow graph (and hence bb epoch), and flow
    // from inlinee tail calls to returns can be more complex.
    //
    assert(!m_comp->compIsForInlining());

    // We may need to track the critical predecessors of some blocks.
    //
    ArrayStack<BasicBlock*> criticalPreds(m_comp->getAllocator(CMK_Pgo));

    // Walk probe list looking for probes that would appear in BBJ_RETURNs
    // that are successors of potential tail calls, and relocate them.
    //
    // If any such block has a conditional pred, we will need to reroute flow from those preds
    // via an intermediary block. That block will subsequently hold the relocated edge
    // probe for the return for those preds.
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        if (!ShouldProcess(block))
        {
            continue;
        }

        // Nothing to do unless the block is a tail call successor.
        //
        if (!block->HasFlag(BBF_TAILCALL_SUCCESSOR))
        {
            continue;
        }

        JITDUMP("Return " FMT_BB " is successor of possible tail call\n", block->bbNum);
        assert(block->KindIs(BBJ_RETURN));

        // This block should have just one probe, which we no longer need.
        //
        Probe* const probe = (Probe*)block->bbSparseProbeList;
        assert(probe->next == nullptr);
        assert(probe->kind == EdgeKind::PostdominatesSource);
        probe->kind = EdgeKind::Deleted;

        // The first probe we add will be the leader of a duplicate probe group.
        //
        Probe* leader = nullptr;

        // Scan for critical preds, and add relocated probes to non-critical preds.
        //
        criticalPreds.Reset();
        for (BasicBlock* const pred : block->PredBlocks())
        {
            // Does this pred reach along a critical edge,
            // or is the pred the tail of a callfinally pair?
            //
            BasicBlock* const succ = pred->GetUniqueSucc();

            if ((succ == nullptr) || pred->isBBCallFinallyPairTail())
            {
                // Route pred through the intermediary.
                //
                JITDUMP(FMT_BB " -> " FMT_BB " is critical edge\n", pred->bbNum, block->bbNum);
                criticalPreds.Push(pred);
            }
            else
            {
                // Put a copy of probe into the pred.
                //
                NewRelocatedProbe(pred, probe->source, probe->target, &leader);

                // Ensure this pred always jumps to block
                //
                assert(pred->KindIs(BBJ_ALWAYS));
                assert(pred->TargetIs(block));
            }
        }

        // If there are any critical preds, create and instrument the
        // intermediary and reroute flow.
        //
        if (criticalPreds.Height() > 0)
        {
            BasicBlock* intermediary = m_comp->fgNewBBbefore(BBJ_ALWAYS, block, /* extendRegion */ true);
            intermediary->SetFlags(BBF_IMPORTED);
            FlowEdge* const newEdge = m_comp->fgAddRefPred(block, intermediary);
            intermediary->SetTargetEdge(newEdge);
            NewRelocatedProbe(intermediary, probe->source, probe->target, &leader);
            SetModifiedFlow();

            // Redirect flow and figure out profile impact.
            //
            // We don't expect to see mixtures of profiled and unprofiled preds,
            // but if we do, fall back to our old default behavior.
            //
            weight_t weight              = 0;
            bool     allPredsHaveProfile = true;

            while (criticalPreds.Height() > 0)
            {
                BasicBlock* const pred = criticalPreds.Pop();
                m_comp->fgReplaceJumpTarget(pred, block, intermediary);

                if (pred->hasProfileWeight())
                {
                    FlowEdge* const predIntermediaryEdge = m_comp->fgGetPredForBlock(intermediary, pred);
                    weight += predIntermediaryEdge->getLikelyWeight();
                }
                else
                {
                    allPredsHaveProfile = false;
                }
            }

            if (allPredsHaveProfile)
            {
                intermediary->setBBProfileWeight(weight);
            }
            else
            {
                intermediary->inheritWeight(block);
            }
        }
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor::BuildSchemaElements: create schema
//   elements for the probes
//
// Arguments:
//   block -- block to instrument
//   schema -- schema that we're building
//
// Todo: if required to have special entry probe, we must also
//  instrument method entry with a block count.
//
void EfficientEdgeCountInstrumentor::BuildSchemaElements(BasicBlock* block, Schema& schema)
{
    unsigned numCountersPerProbe = 1;

    // When we have both interlocked and scalable profile modes enabled, we will
    // count both ways, so allocate two count slots per probe.
    //
    if ((JitConfig.JitScalableProfiling() > 0) && (JitConfig.JitInterlockedProfiling() > 0))
    {
        numCountersPerProbe = 2;
    }
    else if (JitConfig.JitCounterPadding() > 0)
    {
        numCountersPerProbe = (unsigned)JitConfig.JitCounterPadding();
    }

    // Walk the bbSparseProbeList, emitting one schema element per...
    //
    for (Probe* probe = (Probe*)block->bbSparseProbeList; probe != nullptr; probe = probe->next)
    {
        // Deleted and Duplicate probes don't create new schema elements.
        //
        if ((probe->kind == EdgeKind::Duplicate) || (probe->kind == EdgeKind::Deleted))
        {
            continue;
        }

        // Probe is for the edge from source to target.
        //
        BasicBlock* const source = probe->source;
        BasicBlock* const target = probe->target;

        assert(probe->schemaIndex == -1);
        probe->schemaIndex = (int)schema.size();

        // Normally we use the offset of the block in the schema, but for certain
        // blocks we do not have any information we can use and need to use internal BB numbers.
        //
        int32_t sourceKey = EfficientEdgeCountBlockToKey(source);
        int32_t targetKey = EfficientEdgeCountBlockToKey(target);

        ICorJitInfo::PgoInstrumentationSchema schemaElem;
        schemaElem.Count               = numCountersPerProbe;
        schemaElem.Other               = targetKey;
        schemaElem.InstrumentationKind = m_comp->opts.compCollect64BitCounts
                                             ? ICorJitInfo::PgoInstrumentationKind::EdgeLongCount
                                             : ICorJitInfo::PgoInstrumentationKind::EdgeIntCount;
        schemaElem.ILOffset            = sourceKey;
        schemaElem.Offset              = 0;

        schema.push_back(schemaElem);

        m_schemaCount++;
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountInstrumentor::Instrument: add counter probes for edges
//   originating from block
//
// Arguments:
//   block -- block of interest
//   schema -- instrumentation schema
//   profileMemory -- profile data slab
//
void EfficientEdgeCountInstrumentor::Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory)
{
    // What type of probe(s) will we emit?
    //
    const bool interlocked    = JitConfig.JitInterlockedProfiling() > 0;
    const bool scalable       = JitConfig.JitScalableProfiling() > 0;
    const bool unsynchronized = !interlocked && !scalable;
    const bool dual           = interlocked && scalable;

    JITDUMP("Using %s probes\n",
            unsynchronized ? "unsychronized"
                           : (dual ? "both interlocked and scalable" : (interlocked ? "interlocked" : "scalable")));

    // Walk the bbSparseProbeList, adding instrumentation.
    //
    for (Probe* probe = (Probe*)block->bbSparseProbeList; probe != nullptr; probe = probe->next)
    {
        if (probe->kind == EdgeKind::Deleted)
        {
            continue;
        }

        // Probe is for the edge from source to target.
        //
        BasicBlock* const source = probe->source;
        BasicBlock* const target = probe->target;

        // Retrieve the schema index for this probe.
        // For duplicate probes, get the index from the group leader.
        //
        int schemaIndex = probe->schemaIndex;

        if (probe->kind == EdgeKind::Duplicate)
        {
            schemaIndex = probe->leader->schemaIndex;
        }

        // Sanity checks.
        //
        assert((schemaIndex >= 0) && (schemaIndex < (int)schema.size()));

        const ICorJitInfo::PgoInstrumentationSchema& entry = schema[schemaIndex];
        assert((entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeIntCount) ||
               (entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeLongCount));

        uint8_t* addrOfCurrentExecutionCount = profileMemory + entry.Offset;

#ifdef DEBUG
        if (JitConfig.JitPropagateSynthesizedCountsToProfileData() > 0)
        {
            // Write the current synthesized count as the profile data
            //
            // Todo: handle pseudo edges!
            FlowEdge* const edge = m_comp->fgGetPredForBlock(source, target);

            if (edge != nullptr)
            {
                weight_t edgeWeight = edge->getLikelyWeight();

                if (entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeIntCount)
                {
                    *((uint32_t*)addrOfCurrentExecutionCount) = (uint32_t)edgeWeight;
                }
                else
                {
                    *((uint64_t*)addrOfCurrentExecutionCount) = (uint64_t)edgeWeight;
                }
            }

            return;
        }
#endif

        // Determine where to place the probe.
        //
        BasicBlock* instrumentedBlock = nullptr;

        switch (probe->kind)
        {
            case EdgeKind::PostdominatesSource:
                instrumentedBlock = source;
                break;
            case EdgeKind::DominatesTarget:
                instrumentedBlock = target;
                break;
            case EdgeKind::Relocated:
            case EdgeKind::Leader:
            case EdgeKind::Duplicate:
                instrumentedBlock = block;
                break;
            case EdgeKind::CriticalEdge:
                // Should have been handled in SplitCriticalEdges()
                assert(!"unexpected probe kind");
                break;
            default:
                unreached();
        }

        assert(instrumentedBlock != nullptr);

        // Place the probe

        var_types typ =
            entry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeIntCount ? TYP_INT : TYP_LONG;

        GenTree* incCount = BlockCountInstrumentor::CreateCounterIncrement(m_comp, addrOfCurrentExecutionCount, typ);
        m_comp->fgNewStmtAtBeg(instrumentedBlock, incCount);

        if (probe->kind != EdgeKind::Duplicate)
        {
            m_instrCount++;
        }
    }
}

//------------------------------------------------------------------------
// HandleHistogramProbeVisitor: invoke functor on each virtual call or cast-related
//     helper calls in a tree
//
template <class TFunctor>
class HandleHistogramProbeVisitor final : public GenTreeVisitor<HandleHistogramProbeVisitor<TFunctor>>
{
public:
    enum
    {
        DoPreOrder = true
    };

    TFunctor& m_functor;
    Compiler* m_compiler;

    HandleHistogramProbeVisitor(Compiler* compiler, TFunctor& functor)
        : GenTreeVisitor<HandleHistogramProbeVisitor>(compiler)
        , m_functor(functor)
        , m_compiler(compiler)
    {
    }
    Compiler::fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
    {
        GenTree* const node = *use;
        if (node->IsCall() && (m_compiler->compClassifyGDVProbeType(node->AsCall()) != Compiler::GDVProbeType::None))
        {
            assert(node->AsCall()->gtHandleHistogramProfileCandidateInfo != nullptr);
            m_functor(m_compiler, node->AsCall());
        }

        return Compiler::WALK_CONTINUE;
    }
};

//------------------------------------------------------------------------
// ValueHistogramProbeVisitor: invoke functor on each node requiring a generic value probe
//
template <class TFunctor>
class ValueHistogramProbeVisitor final : public GenTreeVisitor<ValueHistogramProbeVisitor<TFunctor>>
{
public:
    enum
    {
        DoPreOrder = true
    };

    TFunctor& m_functor;
    Compiler* m_compiler;

    ValueHistogramProbeVisitor(Compiler* compiler, TFunctor& functor)
        : GenTreeVisitor<ValueHistogramProbeVisitor>(compiler)
        , m_functor(functor)
        , m_compiler(compiler)
    {
    }

    Compiler::fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
    {
        GenTree* const node = *use;
        if (node->IsCall() && node->AsCall()->IsSpecialIntrinsic())
        {
            const NamedIntrinsic ni = m_compiler->lookupNamedIntrinsic(node->AsCall()->gtCallMethHnd);
            if ((ni == NI_System_SpanHelpers_Memmove) || (ni == NI_System_SpanHelpers_SequenceEqual))
            {
                m_functor(m_compiler, node);
            }
        }
        return Compiler::WALK_CONTINUE;
    }
};

//------------------------------------------------------------------------
// BuildHandleHistogramProbeSchemaGen: functor that creates class probe schema elements
//
class BuildHandleHistogramProbeSchemaGen
{
private:
    Schema&   m_schema;
    unsigned& m_schemaCount;

public:
    BuildHandleHistogramProbeSchemaGen(Schema& schema, unsigned& schemaCount)
        : m_schema(schema)
        , m_schemaCount(schemaCount)
    {
    }

    void operator()(Compiler* compiler, GenTreeCall* call)
    {
        Compiler::GDVProbeType probeType = compiler->compClassifyGDVProbeType(call);

        if ((probeType == Compiler::GDVProbeType::ClassProfile) ||
            (probeType == Compiler::GDVProbeType::MethodAndClassProfile))
        {
            CreateHistogramSchemaEntries(compiler, call, true /* isTypeHistogram */);
        }

        if ((probeType == Compiler::GDVProbeType::MethodProfile) ||
            (probeType == Compiler::GDVProbeType::MethodAndClassProfile))
        {
            CreateHistogramSchemaEntries(compiler, call, false /* isTypeHistogram */);
        }
    }

    void CreateHistogramSchemaEntries(Compiler* compiler, GenTreeCall* call, bool isTypeHistogram)
    {
        ICorJitInfo::PgoInstrumentationSchema schemaElem = {};
        schemaElem.Count                                 = 1;
        schemaElem.Other = isTypeHistogram ? ICorJitInfo::HandleHistogram32::CLASS_FLAG : 0;
        if (call->IsVirtualStub())
        {
            schemaElem.Other |= ICorJitInfo::HandleHistogram32::INTERFACE_FLAG;
        }
        else if (call->IsDelegateInvoke())
        {
            schemaElem.Other |= ICorJitInfo::HandleHistogram32::DELEGATE_FLAG;
        }

        schemaElem.InstrumentationKind = compiler->opts.compCollect64BitCounts
                                             ? ICorJitInfo::PgoInstrumentationKind::HandleHistogramLongCount
                                             : ICorJitInfo::PgoInstrumentationKind::HandleHistogramIntCount;
        schemaElem.ILOffset            = (int32_t)call->gtHandleHistogramProfileCandidateInfo->ilOffset;
        schemaElem.Offset              = 0;

        m_schema.push_back(schemaElem);

        m_schemaCount++;

        // Re-using ILOffset and Other fields from schema item for TypeHandleHistogramCount
        schemaElem.InstrumentationKind = isTypeHistogram ? ICorJitInfo::PgoInstrumentationKind::HandleHistogramTypes
                                                         : ICorJitInfo::PgoInstrumentationKind::HandleHistogramMethods;
        schemaElem.Count               = ICorJitInfo::HandleHistogram32::SIZE;
        m_schema.push_back(schemaElem);

        m_schemaCount++;
    }
};

class BuildValueHistogramProbeSchemaGen
{
    Schema&   m_schema;
    unsigned& m_schemaCount;

public:
    BuildValueHistogramProbeSchemaGen(Schema& schema, unsigned& schemaCount)
        : m_schema(schema)
        , m_schemaCount(schemaCount)
    {
    }

    void operator()(Compiler* compiler, GenTree* call)
    {
        ICorJitInfo::PgoInstrumentationSchema schemaElem = {};
        schemaElem.Count                                 = 1;
        schemaElem.InstrumentationKind                   = compiler->opts.compCollect64BitCounts
                                                               ? ICorJitInfo::PgoInstrumentationKind::ValueHistogramLongCount
                                                               : ICorJitInfo::PgoInstrumentationKind::ValueHistogramIntCount;
        schemaElem.ILOffset = (int32_t)call->AsCall()->gtHandleHistogramProfileCandidateInfo->ilOffset;
        m_schema.push_back(schemaElem);
        m_schemaCount++;

        schemaElem.InstrumentationKind = ICorJitInfo::PgoInstrumentationKind::ValueHistogram;
        schemaElem.Count               = ICorJitInfo::HandleHistogram32::SIZE;
        m_schema.push_back(schemaElem);
        m_schemaCount++;
    }
};

//------------------------------------------------------------------------
// HandleHistogramProbeInserter: functor that adds class/method probe instrumentation
//
class HandleHistogramProbeInserter
{
    Schema&   m_schema;
    uint8_t*  m_profileMemory;
    int*      m_currentSchemaIndex;
    unsigned& m_instrCount;

public:
    HandleHistogramProbeInserter(Schema& schema, uint8_t* profileMemory, int* pCurrentSchemaIndex, unsigned& instrCount)
        : m_schema(schema)
        , m_profileMemory(profileMemory)
        , m_currentSchemaIndex(pCurrentSchemaIndex)
        , m_instrCount(instrCount)
    {
    }

    void operator()(Compiler* compiler, GenTreeCall* call)
    {
        JITDUMP("Found call [%06u] with probe index %d and ilOffset 0x%X\n", compiler->dspTreeID(call),
                call->gtHandleHistogramProfileCandidateInfo->probeIndex,
                call->gtHandleHistogramProfileCandidateInfo->ilOffset);

        // We transform the call from (CALLVIRT obj, ... args ...) to
        //
        //      (CALLVIRT
        //        (COMMA
        //          (tmp = obj)
        //          (COMMA
        //            (CALL probe_fn tmp, &probeEntry)
        //            tmp)))
        //         ... args ...)
        //

        // Read histograms
        void* typeHistogram   = nullptr;
        void* methodHistogram = nullptr;

        bool is32;
        ReadHistogramAndAdvance(call->gtHandleHistogramProfileCandidateInfo->ilOffset, &typeHistogram, &methodHistogram,
                                &is32);
        bool secondIs32;
        ReadHistogramAndAdvance(call->gtHandleHistogramProfileCandidateInfo->ilOffset, &typeHistogram, &methodHistogram,
                                &secondIs32);

        assert(((typeHistogram != nullptr) || (methodHistogram != nullptr)) &&
               "Expected at least one handle histogram when inserting probes");

        if ((typeHistogram != nullptr) && (methodHistogram != nullptr))
        {
            // We expect both histograms to be 32-bit or 64-bit, not a mix.
            assert(is32 == secondIs32);
        }

        assert(!call->gtArgs.AreArgsComplete());
        CallArg* objUse = nullptr;
        if (compiler->impIsCastHelperEligibleForClassProbe(call))
        {
            // Second arg of cast/isinst helper call is the object instance
            objUse = call->gtArgs.GetArgByIndex(1);
        }
        else
        {
            objUse = call->gtArgs.GetThisArg();
        }

        assert(objUse->GetEarlyNode()->TypeIs(TYP_REF));

        // Grab a temp to hold the 'this' object as it will be used three times
        //
        unsigned const tmpNum             = compiler->lvaGrabTemp(true DEBUGARG("handle histogram profile tmp"));
        compiler->lvaTable[tmpNum].lvType = TYP_REF;

        GenTree* helperCallNode = nullptr;

        if (typeHistogram != nullptr)
        {
            GenTree* const tmpNode          = compiler->gtNewLclvNode(tmpNum, TYP_REF);
            GenTree* const classProfileNode = compiler->gtNewIconNode((ssize_t)typeHistogram, TYP_I_IMPL);
            helperCallNode =
                compiler->gtNewHelperCallNode(is32 ? CORINFO_HELP_CLASSPROFILE32 : CORINFO_HELP_CLASSPROFILE64,
                                              TYP_VOID, tmpNode, classProfileNode);
        }

        if (methodHistogram != nullptr)
        {
            GenTree* const tmpNode           = compiler->gtNewLclvNode(tmpNum, TYP_REF);
            GenTree* const methodProfileNode = compiler->gtNewIconNode((ssize_t)methodHistogram, TYP_I_IMPL);

            GenTree* methodProfileCallNode;
            if (call->IsDelegateInvoke())
            {
                methodProfileCallNode = compiler->gtNewHelperCallNode(is32 ? CORINFO_HELP_DELEGATEPROFILE32
                                                                           : CORINFO_HELP_DELEGATEPROFILE64,
                                                                      TYP_VOID, tmpNode, methodProfileNode);
            }
            else
            {
                assert(call->IsVirtualVtable());
                GenTree* const baseMethodNode = compiler->gtNewIconEmbMethHndNode(call->gtCallMethHnd);
                methodProfileCallNode =
                    compiler->gtNewHelperCallNode(is32 ? CORINFO_HELP_VTABLEPROFILE32 : CORINFO_HELP_VTABLEPROFILE64,
                                                  TYP_VOID, tmpNode, baseMethodNode, methodProfileNode);
            }

            if (helperCallNode == nullptr)
            {
                helperCallNode = methodProfileCallNode;
            }
            else
            {
                helperCallNode = compiler->gtNewOperNode(GT_COMMA, TYP_REF, helperCallNode, methodProfileCallNode);
            }
        }

        // Generate the IR...
        //
        GenTree* const tmpNode2       = compiler->gtNewLclvNode(tmpNum, TYP_REF);
        GenTree* const callCommaNode  = compiler->gtNewOperNode(GT_COMMA, TYP_REF, helperCallNode, tmpNode2);
        GenTree* const storeNode      = compiler->gtNewStoreLclVarNode(tmpNum, objUse->GetNode());
        GenTree* const storeCommaNode = compiler->gtNewOperNode(GT_COMMA, TYP_REF, storeNode, callCommaNode);

        // Update the call
        //
        objUse->SetEarlyNode(storeCommaNode);

        JITDUMP("Modified call is now\n");
        DISPTREE(call);

        m_instrCount++;
    }

private:
    void ReadHistogramAndAdvance(IL_OFFSET ilOffset, void** typeHistogram, void** methodHistogram, bool* histogramIs32)
    {
        if (*m_currentSchemaIndex >= (int)m_schema.size())
        {
            return;
        }

        ICorJitInfo::PgoInstrumentationSchema& countEntry = m_schema[*m_currentSchemaIndex];

        bool is32 = countEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::HandleHistogramIntCount;
        bool is64 = countEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::HandleHistogramLongCount;
        if (!is32 && !is64)
        {
            return;
        }

        if (countEntry.ILOffset != static_cast<int32_t>(ilOffset))
        {
            return;
        }

        assert(*m_currentSchemaIndex + 2 <= (int)m_schema.size());
        ICorJitInfo::PgoInstrumentationSchema& tableEntry = m_schema[*m_currentSchemaIndex + 1];
        assert((tableEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::HandleHistogramTypes) ||
               (tableEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::HandleHistogramMethods));

        void** outHistogram;
        if (tableEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::HandleHistogramTypes)
        {
            assert(*typeHistogram == nullptr);
            outHistogram = typeHistogram;
        }
        else
        {
            assert(*methodHistogram == nullptr);
            outHistogram = methodHistogram;
        }

        *outHistogram  = &m_profileMemory[countEntry.Offset];
        *histogramIs32 = is32;

#ifdef DEBUG
        if (is32)
        {
            ICorJitInfo::HandleHistogram32* h32 =
                reinterpret_cast<ICorJitInfo::HandleHistogram32*>(&m_profileMemory[countEntry.Offset]);
            assert(reinterpret_cast<uint8_t*>(&h32->Count) == &m_profileMemory[countEntry.Offset]);
            assert(reinterpret_cast<uint8_t*>(h32->HandleTable) == &m_profileMemory[tableEntry.Offset]);
        }
        else
        {
            ICorJitInfo::HandleHistogram64* h64 =
                reinterpret_cast<ICorJitInfo::HandleHistogram64*>(&m_profileMemory[countEntry.Offset]);
            assert(reinterpret_cast<uint8_t*>(&h64->Count) == &m_profileMemory[countEntry.Offset]);
            assert(reinterpret_cast<uint8_t*>(h64->HandleTable) == &m_profileMemory[tableEntry.Offset]);
        }
#endif

        *m_currentSchemaIndex += 2;
    }
};

//------------------------------------------------------------------------
// ValueHistogramProbeInserter: functor that adds generic probes
//
class ValueHistogramProbeInserter
{
    Schema&   m_schema;
    uint8_t*  m_profileMemory;
    int*      m_currentSchemaIndex;
    unsigned& m_instrCount;

public:
    ValueHistogramProbeInserter(Schema& schema, uint8_t* profileMemory, int* pCurrentSchemaIndex, unsigned& instrCount)
        : m_schema(schema)
        , m_profileMemory(profileMemory)
        , m_currentSchemaIndex(pCurrentSchemaIndex)
        , m_instrCount(instrCount)
    {
    }

    void operator()(Compiler* compiler, GenTree* node)
    {
        if (*m_currentSchemaIndex >= (int)m_schema.size())
        {
            return;
        }

        assert(node->AsCall()->IsSpecialIntrinsic(compiler, NI_System_SpanHelpers_Memmove) ||
               node->AsCall()->IsSpecialIntrinsic(compiler, NI_System_SpanHelpers_SequenceEqual));

        const ICorJitInfo::PgoInstrumentationSchema& countEntry = m_schema[*m_currentSchemaIndex];
        if (countEntry.ILOffset !=
            static_cast<int32_t>(node->AsCall()->gtHandleHistogramProfileCandidateInfo->ilOffset))
        {
            return;
        }

        bool is32 = countEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::ValueHistogramIntCount;
        bool is64 = countEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::ValueHistogramLongCount;
        if (!is32 && !is64)
        {
            return;
        }

        assert(*m_currentSchemaIndex + 2 <= (int)m_schema.size());
        const ICorJitInfo::PgoInstrumentationSchema& tableEntry = m_schema[*m_currentSchemaIndex + 1];
        assert((tableEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::ValueHistogram));
        uint8_t* hist = &m_profileMemory[countEntry.Offset];
        assert(hist != nullptr);

        *m_currentSchemaIndex += 2;

        GenTree** lenArgRef = &node->AsCall()->gtArgs.GetUserArgByIndex(2)->EarlyNodeRef();

        // We have Memmove(dst, src, len) and we want to insert a call to CORINFO_HELP_VALUEPROFILE for the len:
        //
        //  \--*  COMMA     long
        //     +--*  CALL help void   CORINFO_HELP_VALUEPROFILE
        //     |  +--*  COMMA     long
        //     |  |  +--*  STORE_LCL_VAR long  tmp
        //     |  |  |  \--*  (node to poll)
        //     |  |  \--*  LCL_VAR   long   tmp
        //     |  \--*  CNS_INT   long   <hist>
        //     \--*  LCL_VAR   long   tmp
        //

        const unsigned lenTmpNum      = compiler->lvaGrabTemp(true DEBUGARG("length histogram profile tmp"));
        GenTree*       storeLenToTemp = compiler->gtNewTempStore(lenTmpNum, *lenArgRef);
        GenTree*       lengthLocal    = compiler->gtNewLclvNode(lenTmpNum, genActualType(*lenArgRef));
        GenTreeOp* lengthNode = compiler->gtNewOperNode(GT_COMMA, lengthLocal->TypeGet(), storeLenToTemp, lengthLocal);
        GenTree*   histNode   = compiler->gtNewIconNode(reinterpret_cast<ssize_t>(hist), TYP_I_IMPL);
        unsigned   helper     = is32 ? CORINFO_HELP_VALUEPROFILE32 : CORINFO_HELP_VALUEPROFILE64;
        GenTreeCall* helperCallNode = compiler->gtNewHelperCallNode(helper, TYP_VOID, lengthNode, histNode);

        *lenArgRef = compiler->gtNewOperNode(GT_COMMA, lengthLocal->TypeGet(), helperCallNode,
                                             compiler->gtCloneExpr(lengthLocal));
        m_instrCount++;
    }
};

//------------------------------------------------------------------------
// HandleHistogramProbeInstrumentor: instrumentor that adds a class probe to each
//   virtual call in the basic block
//
class HandleHistogramProbeInstrumentor : public Instrumentor
{
public:
    HandleHistogramProbeInstrumentor(Compiler* comp)
        : Instrumentor(comp)
    {
    }
    bool ShouldProcess(BasicBlock* block) override
    {
        return block->HasFlag(BBF_IMPORTED) && !block->HasFlag(BBF_INTERNAL);
    }
    void Prepare(bool isPreImport) override;
    void BuildSchemaElements(BasicBlock* block, Schema& schema) override;
    void Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory) override;
};

//------------------------------------------------------------------------
// ValueInstrumentor: instrumentor that adds a generic probe for integer values
//
class ValueInstrumentor : public Instrumentor
{
public:
    ValueInstrumentor(Compiler* comp)
        : Instrumentor(comp)
    {
    }
    bool ShouldProcess(BasicBlock* block) override
    {
        return block->HasFlag(BBF_IMPORTED) && !block->HasFlag(BBF_INTERNAL);
    }
    void Prepare(bool isPreImport) override;
    void BuildSchemaElements(BasicBlock* block, Schema& schema) override;
    void Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory) override;
};

//------------------------------------------------------------------------
// HandleHistogramProbeInstrumentor::Prepare: prepare for class instrumentation
//
// Arguments:
//   preImport - true if this is the prepare call that happens before
//      importation
//
void HandleHistogramProbeInstrumentor::Prepare(bool isPreImport)
{
    if (isPreImport)
    {
        return;
    }

#ifdef DEBUG
    // Set schema index to invalid value
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        block->bbHistogramSchemaIndex = -1;
    }
#endif
}

//------------------------------------------------------------------------
// HandleHistogramProbeInstrumentor::BuildSchemaElements: create schema elements for a class probe
//
// Arguments:
//   block -- block to instrument
//   schema -- schema that we're building
//
void HandleHistogramProbeInstrumentor::BuildSchemaElements(BasicBlock* block, Schema& schema)
{
    if (!block->HasFlag(BBF_HAS_HISTOGRAM_PROFILE))
    {
        return;
    }

    // Remember the schema index for this block.
    //
    block->bbHistogramSchemaIndex = (int)schema.size();

    // Scan the statements and identify the class probes
    //
    BuildHandleHistogramProbeSchemaGen                              schemaGen(schema, m_schemaCount);
    HandleHistogramProbeVisitor<BuildHandleHistogramProbeSchemaGen> visitor(m_comp, schemaGen);
    for (Statement* const stmt : block->Statements())
    {
        visitor.WalkTree(stmt->GetRootNodePointer(), nullptr);
    }
}

//------------------------------------------------------------------------
// HandleHistogramProbeInstrumentor::Instrument: add class probes to block
//
// Arguments:
//   block -- block of interest
//   schema -- instrumentation schema
//   profileMemory -- profile data slab
//
void HandleHistogramProbeInstrumentor::Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory)
{
    if (!block->HasFlag(BBF_HAS_HISTOGRAM_PROFILE))
    {
        return;
    }

    // Would be nice to avoid having to search here by tracking
    // candidates more directly.
    //
    JITDUMP("Scanning for calls to profile in " FMT_BB "\n", block->bbNum);

    // Scan the statements and add class probes
    //
    int histogramSchemaIndex = block->bbHistogramSchemaIndex;
    assert((histogramSchemaIndex >= 0) && (histogramSchemaIndex < (int)schema.size()));

    HandleHistogramProbeInserter insertProbes(schema, profileMemory, &histogramSchemaIndex, m_instrCount);
    HandleHistogramProbeVisitor<HandleHistogramProbeInserter> visitor(m_comp, insertProbes);
    for (Statement* const stmt : block->Statements())
    {
        visitor.WalkTree(stmt->GetRootNodePointer(), nullptr);
    }
}

void ValueInstrumentor::Prepare(bool isPreImport)
{
    if (isPreImport)
    {
        return;
    }

#ifdef DEBUG
    // Set schema index to invalid value
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        block->bbCountSchemaIndex = -1;
    }
#endif
}

void ValueInstrumentor::BuildSchemaElements(BasicBlock* block, Schema& schema)
{
    if (!block->HasFlag(BBF_HAS_VALUE_PROFILE))
    {
        return;
    }

    block->bbHistogramSchemaIndex = (int)schema.size();

    BuildValueHistogramProbeSchemaGen                             schemaGen(schema, m_schemaCount);
    ValueHistogramProbeVisitor<BuildValueHistogramProbeSchemaGen> visitor(m_comp, schemaGen);
    for (Statement* const stmt : block->Statements())
    {
        visitor.WalkTree(stmt->GetRootNodePointer(), nullptr);
    }
}

void ValueInstrumentor::Instrument(BasicBlock* block, Schema& schema, uint8_t* profileMemory)
{
    if (!block->HasFlag(BBF_HAS_VALUE_PROFILE))
    {
        return;
    }

    int histogramSchemaIndex = block->bbHistogramSchemaIndex;
    assert((histogramSchemaIndex >= 0) && (histogramSchemaIndex < (int)schema.size()));

    ValueHistogramProbeInserter insertProbes(schema, profileMemory, &histogramSchemaIndex, m_instrCount);
    ValueHistogramProbeVisitor<ValueHistogramProbeInserter> visitor(m_comp, insertProbes);
    for (Statement* const stmt : block->Statements())
    {
        visitor.WalkTree(stmt->GetRootNodePointer(), nullptr);
    }
}

//------------------------------------------------------------------------
// fgPrepareToInstrumentMethod: prepare for instrumentation
//
// Notes:
//   Runs before importation, so instrumentation schemes can get a pure
//   look at the flowgraph before any internal blocks are added.
//
// Returns:
//   appropriate phase status
//
PhaseStatus Compiler::fgPrepareToInstrumentMethod()
{
    noway_assert(!compIsForInlining());

    // Choose instrumentation technology.
    //
    // We enable edge profiling by default, except when:
    //
    // * disabled by option
    // * we are AOT compiling
    //
    const bool edgesEnabled    = (JitConfig.JitEdgeProfiling() > 0);
    const bool prejit          = IsAot();
    const bool useEdgeProfiles = edgesEnabled && !prejit;
    const bool minimalProfiling =
        prejit ? (JitConfig.JitMinimalPrejitProfiling() > 0) : (JitConfig.JitMinimalJitProfiling() > 0);

    // In majority of cases, methods marked with [Intrinsic] are imported directly
    // in Tier1 so the profile will never be consumed. Thus, let's avoid unnecessary probes...
    if (minimalProfiling && (info.compFlags & CORINFO_FLG_INTRINSIC) != 0)
    {
        //... except a few intrinsics that might still need it:
        bool           shouldBeInstrumented = false;
        NamedIntrinsic ni                   = lookupNamedIntrinsic(info.compMethodHnd);
        switch (ni)
        {
            // These are marked as [Intrinsic] only to be handled (unrolled) for constant inputs.
            // In other cases they have large managed implementations we want to profile.
            case NI_System_String_Equals:
            case NI_System_SpanHelpers_Memmove:
            case NI_System_MemoryExtensions_Equals:
            case NI_System_MemoryExtensions_SequenceEqual:
            case NI_System_MemoryExtensions_StartsWith:
            case NI_System_SpanHelpers_Fill:
            case NI_System_SpanHelpers_SequenceEqual:
            case NI_System_SpanHelpers_ClearWithoutReferences:

            // Same here, these are only folded when JIT knows the exact types
            case NI_System_Type_IsAssignableFrom:
            case NI_System_Type_IsAssignableTo:
            case NI_System_Type_op_Equality:
            case NI_System_Type_op_Inequality:
                shouldBeInstrumented = true;
                break;

            default:
                // Some Math intrinsics have large managed implementations we want to profile.
                shouldBeInstrumented = ni >= NI_SYSTEM_MATH_START && ni <= NI_SYSTEM_MATH_END;
                break;
        }

        if (!shouldBeInstrumented)
        {
            fgCountInstrumentor     = new (this, CMK_Pgo) NonInstrumentor(this);
            fgHistogramInstrumentor = new (this, CMK_Pgo) NonInstrumentor(this);
            fgValueInstrumentor     = new (this, CMK_Pgo) NonInstrumentor(this);
            return PhaseStatus::MODIFIED_NOTHING;
        }
    }

    if (minimalProfiling && (fgBBcount < 2))
    {
        // Don't instrumenting small single-block methods.
        JITDUMP("Not using any block profiling (fgBBcount < 2)\n");
        fgCountInstrumentor = new (this, CMK_Pgo) NonInstrumentor(this);
    }
    else if (useEdgeProfiles)
    {
        JITDUMP("Using edge profiling\n");
        fgCountInstrumentor = new (this, CMK_Pgo) EfficientEdgeCountInstrumentor(this, minimalProfiling);
    }
    else
    {
        JITDUMP("Using block profiling, because %s\n", prejit ? "prejitting" : "edge profiling disabled");
        fgCountInstrumentor = new (this, CMK_Pgo) BlockCountInstrumentor(this);
    }

    // Enable class profiling by default, when jitting.
    // Todo: we may also want this on by default for prejitting.
    //
    const bool useClassProfiles    = (JitConfig.JitClassProfiling() > 0);
    const bool useDelegateProfiles = (JitConfig.JitDelegateProfiling() > 0);
    const bool useVTableProfiles   = (JitConfig.JitVTableProfiling() > 0);
    if (!prejit && (useClassProfiles || useDelegateProfiles || useVTableProfiles))
    {
        fgHistogramInstrumentor = new (this, CMK_Pgo) HandleHistogramProbeInstrumentor(this);
    }
    else
    {
        JITDUMP("Not doing class/method profiling, because %s\n", prejit ? "prejit" : "class/method profiles disabled");
        fgHistogramInstrumentor = new (this, CMK_Pgo) NonInstrumentor(this);
    }

    if (!prejit && JitConfig.JitProfileValues())
    {
        fgValueInstrumentor = new (this, CMK_Pgo) ValueInstrumentor(this);
    }
    else
    {
        JITDUMP("Not doing generic profiling, because %s\n", prejit ? "prejit" : "DOTNET_JitProfileValues=0")
        fgValueInstrumentor = new (this, CMK_Pgo) NonInstrumentor(this);
    }

    // Make pre-import preparations.
    //
    const bool isPreImport = true;
    fgCountInstrumentor->Prepare(isPreImport);
    fgHistogramInstrumentor->Prepare(isPreImport);
    fgValueInstrumentor->Prepare(isPreImport);

    return PhaseStatus::MODIFIED_NOTHING;
}

//------------------------------------------------------------------------
// fgInstrumentMethod: add instrumentation probes to the method
//
// Returns:
//   appropriate phase status
//
// Note:
//
//   By default this instruments each non-internal block with
//   a counter probe.
//
//   Optionally adds class probes to virtual and interface calls.
//
//   Probe structure is described by a schema array, which is created
//   here based on flowgraph and IR structure.
//
PhaseStatus Compiler::fgInstrumentMethod()
{
    noway_assert(!compIsForInlining());

    // Make post-import preparations.
    //
    const bool isPreImport = false;
    fgCountInstrumentor->Prepare(isPreImport);
    fgHistogramInstrumentor->Prepare(isPreImport);
    fgValueInstrumentor->Prepare(isPreImport);

    // Walk the flow graph to build up the instrumentation schema.
    //
    Schema schema(getAllocator(CMK_Pgo));
    for (BasicBlock* const block : Blocks())
    {
        if (fgCountInstrumentor->ShouldProcess(block))
        {
            fgCountInstrumentor->BuildSchemaElements(block, schema);
        }

        if (fgHistogramInstrumentor->ShouldProcess(block))
        {
            fgHistogramInstrumentor->BuildSchemaElements(block, schema);
        }

        if (fgValueInstrumentor->ShouldProcess(block))
        {
            fgValueInstrumentor->BuildSchemaElements(block, schema);
        }
    }

    // Even though we haven't yet instrumented, we may have made changes in anticipation...
    //
    const bool madeAnticipatoryChanges = fgCountInstrumentor->ModifiedFlow() ||
                                         fgHistogramInstrumentor->ModifiedFlow() || fgValueInstrumentor->ModifiedFlow();
    const PhaseStatus earlyExitPhaseStatus =
        madeAnticipatoryChanges ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;

    // Optionally, when jitting, if there were no class probes, no value probes and only one count probe,
    // suppress instrumentation.
    //
    // We leave instrumentation in place for AOT as the sample hits in the method
    // may be used to determine if the method should be AOT or not.
    //
    // For jitting, no information is conveyed by the count in a single=block method.
    //
    bool minimalProbeMode = false;

    if (IsAot())
    {
        minimalProbeMode = (JitConfig.JitMinimalPrejitProfiling() > 0);
    }
    else
    {
        minimalProbeMode = (JitConfig.JitMinimalJitProfiling() > 0);
    }

    if (minimalProbeMode && (fgCountInstrumentor->SchemaCount() == 1) &&
        (fgHistogramInstrumentor->SchemaCount() == 0) && (fgValueInstrumentor->SchemaCount() == 0))
    {
        JITDUMP("Not instrumenting method: minimal probing enabled, and method has only one counter and no class and "
                "no value probes\n");

        return earlyExitPhaseStatus;
    }

    if (schema.size() == 0)
    {
        JITDUMP("Not instrumenting method: no schemas were created\n");
        return earlyExitPhaseStatus;
    }

    JITDUMP("Instrumenting method: %d count probes, %d class probes and %d value probes\n",
            fgCountInstrumentor->SchemaCount(), fgHistogramInstrumentor->SchemaCount(),
            fgValueInstrumentor->SchemaCount())

    assert(schema.size() > 0);

    // Allocate/retrieve the profile buffer.
    //
    // If this is an OSR method, we should use the same buffer that the Tier0 method used.
    //
    // This is supported by allocPgoInsrumentationDataBySchema, which will verify the schema
    // we provide here matches the one from Tier0, and will fill in the data offsets in
    // our schema properly.
    //
    uint8_t* profileMemory;
    HRESULT  res = info.compCompHnd->allocPgoInstrumentationBySchema(info.compMethodHnd, schema.data(),
                                                                     (UINT32)schema.size(), &profileMemory);

    // Deal with allocation failures.
    //
    if (!SUCCEEDED(res))
    {
        JITDUMP("Unable to instrument: schema allocation failed: 0x%x\n", res);

        // The E_NOTIMPL status is returned when we are profiling a generic method from a different assembly
        //
        if (res != E_NOTIMPL)
        {
            noway_assert(!"Error: unexpected hresult from allocPgoInstrumentationBySchema");
        }

        return earlyExitPhaseStatus;
    }

    JITDUMP("Instrumentation data base address is %p\n", dspPtr(profileMemory));

    // Add the instrumentation code
    //
    for (BasicBlock* const block : Blocks())
    {
        if (fgCountInstrumentor->ShouldInstrument(block))
        {
            fgCountInstrumentor->Instrument(block, schema, profileMemory);
        }

        if (fgHistogramInstrumentor->ShouldInstrument(block))
        {
            fgHistogramInstrumentor->Instrument(block, schema, profileMemory);
        }

        if (fgValueInstrumentor->ShouldInstrument(block))
        {
            fgValueInstrumentor->Instrument(block, schema, profileMemory);
        }
    }

    // Verify we instrumented everything we created schemas for.
    //
    assert(fgCountInstrumentor->InstrCount() <= fgCountInstrumentor->SchemaCount());

    // Verify we instrumented for each probe
    //
    assert(fgHistogramInstrumentor->InstrCount() == info.compHandleHistogramProbeCount);

    return PhaseStatus::MODIFIED_EVERYTHING;
}

//------------------------------------------------------------------------
// fgIncorporateProfileData: add block/edge profile data to the flowgraph
//   and compute profile scale for inlinees
//
// Returns:
//   appropriate phase status
//
PhaseStatus Compiler::fgIncorporateProfileData()
{
    // Are we doing profile stress?
    //
    if (fgStressBBProf() > 0)
    {
        JITDUMP("JitStress -- incorporating random profile data\n");
        fgIncorporateBlockCounts();
        ProfileSynthesis::Run(this, ProfileSynthesisOption::RepairLikelihoods);
        fgApplyProfileScale();
        return PhaseStatus::MODIFIED_EVERYTHING;
    }

    // For now we only rely on profile data when optimizing.
    //
    if (!opts.OptimizationEnabled())
    {
        JITDUMP("not optimizing, so not incorporating any profile data\n");
        return PhaseStatus::MODIFIED_NOTHING;
    }

#ifdef DEBUG
    // Optionally run synthesis
    //
    if (JitConfig.JitSynthesizeCounts() > 0)
    {
        if ((JitConfig.JitSynthesizeCounts() == 1) || ((JitConfig.JitSynthesizeCounts() == 2) && !fgHaveProfileData()))
        {
            JITDUMP("Synthesizing profile data\n");
            ProfileSynthesis::Run(this, ProfileSynthesisOption::AssignLikelihoods);
            fgApplyProfileScale();
            return PhaseStatus::MODIFIED_EVERYTHING;
        }
    }

    // Or run synthesis and save the data out as the actual profile data
    //
    if (opts.jitFlags->IsSet(JitFlags::JIT_FLAG_BBINSTR) &&
        (JitConfig.JitPropagateSynthesizedCountsToProfileData() > 0))
    {
        JITDUMP("Synthesizing profile data and writing it out as the actual profile data\n");
        ProfileSynthesis::Run(this, ProfileSynthesisOption::AssignLikelihoods);
        fgApplyProfileScale();
        return PhaseStatus::MODIFIED_EVERYTHING;
    }
#endif

    // Do we have profile data?
    //
    if (!fgHaveProfileData())
    {
        // No...
        //
        if (opts.jitFlags->IsSet(JitFlags::JIT_FLAG_BBOPT))
        {
            JITDUMP("BBOPT set, but no profile data available (hr=%08x)\n", fgPgoQueryResult);
        }
        else
        {
            JITDUMP("BBOPT not set\n");
        }

        // Is dynamic PGO active? If so, run synthesis.
        //
        if (fgPgoDynamic)
        {
            JITDUMP("Dynamic PGO active, synthesizing profile data\n");
            ProfileSynthesis::Run(this, ProfileSynthesisOption::AssignLikelihoods);
        }

        // Scale the "synthetic" block weights.
        //
        fgApplyProfileScale();

        return compIsForInlining() ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
    }

    // Summarize profile data
    //
    JITDUMP("Have %s: %d schema records (schema at %p, data at %p)\n", compGetPgoSourceName(), fgPgoSchemaCount,
            dspPtr(fgPgoSchema), dspPtr(fgPgoData));

    fgNumProfileRuns      = 0;
    unsigned otherRecords = 0;

    for (UINT32 iSchema = 0; iSchema < fgPgoSchemaCount; iSchema++)
    {
        switch (fgPgoSchema[iSchema].InstrumentationKind)
        {
            case ICorJitInfo::PgoInstrumentationKind::NumRuns:
                fgNumProfileRuns += fgPgoSchema[iSchema].Other;
                break;

            case ICorJitInfo::PgoInstrumentationKind::BasicBlockIntCount:
            case ICorJitInfo::PgoInstrumentationKind::BasicBlockLongCount:
                fgPgoBlockCounts++;
                break;

            case ICorJitInfo::PgoInstrumentationKind::EdgeIntCount:
            case ICorJitInfo::PgoInstrumentationKind::EdgeLongCount:
                fgPgoEdgeCounts++;
                break;

            case ICorJitInfo::PgoInstrumentationKind::GetLikelyClass:
                fgPgoClassProfiles++;
                break;

            case ICorJitInfo::PgoInstrumentationKind::GetLikelyMethod:
                fgPgoMethodProfiles++;
                break;

            case ICorJitInfo::PgoInstrumentationKind::HandleHistogramIntCount:
            case ICorJitInfo::PgoInstrumentationKind::HandleHistogramLongCount:
                if (iSchema + 1 < fgPgoSchemaCount)
                {
                    if (fgPgoSchema[iSchema + 1].InstrumentationKind ==
                        ICorJitInfo::PgoInstrumentationKind::HandleHistogramTypes)
                    {
                        fgPgoClassProfiles++;
                        iSchema++;
                        break;
                    }
                    if (fgPgoSchema[iSchema + 1].InstrumentationKind ==
                        ICorJitInfo::PgoInstrumentationKind::HandleHistogramMethods)
                    {
                        fgPgoMethodProfiles++;
                        iSchema++;
                        break;
                    }
                }

                __fallthrough;

            default:
                JITDUMP("Unknown PGO record type 0x%x in schema entry %u (offset 0x%x count 0x%x other 0x%x)\n",
                        fgPgoSchema[iSchema].InstrumentationKind, iSchema, fgPgoSchema[iSchema].ILOffset,
                        fgPgoSchema[iSchema].Count, fgPgoSchema[iSchema].Other);
                otherRecords++;
                break;
        }
    }

    if (fgNumProfileRuns == 0)
    {
        fgNumProfileRuns = 1;
    }

    JITDUMP("Profile summary: %d runs, %d block probes, %d edge probes, %d class profiles, %d method profiles, %d "
            "other records\n",
            fgNumProfileRuns, fgPgoBlockCounts, fgPgoEdgeCounts, fgPgoClassProfiles, fgPgoMethodProfiles, otherRecords);

    const bool haveBlockCounts = fgPgoBlockCounts > 0;
    const bool haveEdgeCounts  = fgPgoEdgeCounts > 0;

    fgPgoHaveWeights = haveBlockCounts || haveEdgeCounts;

    if (fgPgoHaveWeights)
    {
        // If for some reason we have both block and edge counts, prefer the edge counts.
        //
        if (haveEdgeCounts)
        {
            fgIncorporateEdgeCounts();
        }
        else if (haveBlockCounts)
        {
            fgIncorporateBlockCounts();
        }

        // We now always run repair, to get consistent initial counts
        //
        JITDUMP("\nRepairing profile...\n");
        ProfileSynthesis::Run(this, ProfileSynthesisOption::RepairLikelihoods);
    }

#ifdef DEBUG
    // Optionally blend and recompute counts.
    //
    if (JitConfig.JitSynthesizeCounts() == 3)
    {
        JITDUMP("Synthesizing profile data and blending it with the actual profile data\n");
        ProfileSynthesis::Run(this, ProfileSynthesisOption::BlendLikelihoods);
    }
#endif

    // Scale data as appropriate
    //
    fgApplyProfileScale();

    return PhaseStatus::MODIFIED_EVERYTHING;
}

//------------------------------------------------------------------------
// fgIncorporateBlockCounts: read block count based profile data
//   and set block weights
//
// Returns:
//   True if data is in good shape
//
// Notes:
//   Since we are now running before the importer, we do not know which
//   blocks will be imported, and we should not see any internal blocks.
//
// Todo:
//   Normalize counts.
//
//   Take advantage of the (likely) correspondence between block order
//   and schema order?
//
//   Find some other mechanism for handling cases where handler entry
//   blocks must be in the hot section.
//
bool Compiler::fgIncorporateBlockCounts()
{
    for (BasicBlock* const block : Blocks())
    {
        weight_t profileWeight;

        if (fgGetProfileWeightForBasicBlock(block->bbCodeOffs, &profileWeight))
        {
            block->setBBProfileWeight(profileWeight);
        }
    }

    // For now assume data is always good.
    //
    return true;
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor: reconstruct block counts from sparse
//   edge counts.
//
// Notes:
//    The algorithm is conceptually simple, but requires a bit of bookkeeping.
//
//    First, we should have a correspondence between the edge count schema
//    entries and the non-tree edges of the spanning tree.
//
//    The instrumentation schema may be partial, if any importer folding was
//    done. Say for instance we have a method that is ISA sensitive to x64 and
//    arm64, and we instrument on x64 and are now jitting on arm64. If so
//    there may be missing schema entries. If we are confident the IL and
//    jit IL to block computations are the same, these missing entries can
//    safely be presumed to be zero.
//
//    Second, we need to be able to reason about the sets of known and
//    unknown edges that are incoming and outgoing from any block. These
//    may not quite be the edges we'd see from iterating successors or
//    building pred lists, because we create special pseudo-edges during
//    instrumentation. So, we also need to build up data structures
//    keeping track of those.
//
//    Solving is done in four steps:
//    * Prepare
//      *  walk the blocks setting up per block info, and a map
//         for block schema keys to blocks.
//      * walk the schema to create info for the known edges, and
//         a map from edge schema keys to edges.
//    * Evolve Spanning Tree
//      * for non-tree edges, presume any missing edge is zero
//        (and hence, can be ignored during the solving process
//      * for tree edges, verify there is no schema entry, and
//        add in an unknown count edge.
//    * Solve
//      * repeatedly walk blocks, looking for blocks where all
//        incoming or outgoing edges are known. This determines
//        the block counts.
//      * for blocks with known counts, look for cases where just
//        one incoming or outgoing edge is unknown, and solve for
//        them.
//    * Propagate
//      * update block counts. bail if there were errors.
//        * mark rare blocks, and special case handler entries
//        * (eventually) try "fixing" counts
//      * (eventually) normalize
//
//   If we've done everything right, the solving is guaranteed to
//   converge.
//
//   Along the way we may find edges with negative counts; this
//   is an indication that the count data is not self-consistent.
//
class EfficientEdgeCountReconstructor : public SpanningTreeVisitor
{
private:
    Compiler*     m_comp;
    CompAllocator m_allocator;
    unsigned      m_blocks;
    unsigned      m_edges;
    unsigned      m_unknownBlocks;
    unsigned      m_unknownEdges;
    unsigned      m_zeroEdges;

    // Map correlating block keys to blocks.
    //
    typedef JitHashTable<int32_t, JitSmallPrimitiveKeyFuncs<int32_t>, BasicBlock*> KeyToBlockMap;
    KeyToBlockMap                                                                  m_keyToBlockMap;

    // Key for finding an edge based on schema info.
    //
    struct EdgeKey
    {
        int32_t const m_sourceKey;
        int32_t const m_targetKey;

        EdgeKey(int32_t sourceKey, int32_t targetKey)
            : m_sourceKey(sourceKey)
            , m_targetKey(targetKey)
        {
        }

        EdgeKey(BasicBlock* sourceBlock, BasicBlock* targetBlock)
            : m_sourceKey(EfficientEdgeCountBlockToKey(sourceBlock))
            , m_targetKey(EfficientEdgeCountBlockToKey(targetBlock))
        {
        }

        static bool Equals(const EdgeKey& e1, const EdgeKey& e2)
        {
            return (e1.m_sourceKey == e2.m_sourceKey) && (e1.m_targetKey == e2.m_targetKey);
        }

        static unsigned GetHashCode(const EdgeKey& e)
        {
            return (unsigned)(e.m_sourceKey ^ (e.m_targetKey << 16));
        }
    };

    // Per edge info
    //
    struct Edge
    {
        weight_t    m_weight;
        BasicBlock* m_sourceBlock;
        BasicBlock* m_targetBlock;
        Edge*       m_nextOutgoingEdge;
        Edge*       m_nextIncomingEdge;
        bool        m_weightKnown;
        bool        m_isPseudoEdge;

        Edge(BasicBlock* source, BasicBlock* target)
            : m_weight(BB_ZERO_WEIGHT)
            , m_sourceBlock(source)
            , m_targetBlock(target)
            , m_nextOutgoingEdge(nullptr)
            , m_nextIncomingEdge(nullptr)
            , m_weightKnown(false)
            , m_isPseudoEdge(false)
        {
        }
    };

    // Map for correlating EdgeIntCount schema entries with edges
    //
    typedef JitHashTable<EdgeKey, EdgeKey, Edge*> EdgeKeyToEdgeMap;
    EdgeKeyToEdgeMap                              m_edgeKeyToEdgeMap;

    // Per block data
    //
    struct BlockInfo
    {
        weight_t m_weight;
        Edge*    m_incomingEdges;
        Edge*    m_outgoingEdges;
        int      m_incomingUnknown;
        int      m_outgoingUnknown;
        bool     m_weightKnown;

        BlockInfo()
            : m_weight(BB_ZERO_WEIGHT)
            , m_incomingEdges(nullptr)
            , m_outgoingEdges(nullptr)
            , m_incomingUnknown(0)
            , m_outgoingUnknown(0)
            , m_weightKnown(false)
        {
        }
    };

    // Map a block to its info
    //
    BlockInfo* BlockToInfo(BasicBlock* block)
    {
        assert(block->bbSparseCountInfo != nullptr);
        return (BlockInfo*)block->bbSparseCountInfo;
    }

    // Set up block info for a block.
    //
    void SetBlockInfo(BasicBlock* block, BlockInfo* info)
    {
        assert(block->bbSparseCountInfo == nullptr);
        block->bbSparseCountInfo = info;
    }

    void MarkInterestingBlocks(BasicBlock* block, BlockInfo* info);
    void MarkInterestingSwitches(BasicBlock* block, BlockInfo* info);

    void PropagateEdges(BasicBlock* block, BlockInfo* info, unsigned nSucc);
    void PropagateOSREntryEdges(BasicBlock* block, BlockInfo* info, unsigned nSucc);

    // Flags for noting and handling various error cases.
    //
    bool m_badcode;
    bool m_mismatch;
    bool m_negativeCount;
    bool m_failedToConverge;
    bool m_allWeightsZero;
    bool m_entryWeightZero;

public:
    EfficientEdgeCountReconstructor(Compiler* comp)
        : SpanningTreeVisitor()
        , m_comp(comp)
        , m_allocator(comp->getAllocator(CMK_Pgo))
        , m_blocks(0)
        , m_edges(0)
        , m_unknownBlocks(0)
        , m_unknownEdges(0)
        , m_zeroEdges(0)
        , m_keyToBlockMap(m_allocator)
        , m_edgeKeyToEdgeMap(m_allocator)
        , m_badcode(false)
        , m_mismatch(false)
        , m_negativeCount(false)
        , m_failedToConverge(false)
        , m_allWeightsZero(true)
        , m_entryWeightZero(false)
    {
    }

    void Prepare();
    void Solve();
    void Propagate();

    void Badcode() override
    {
        m_badcode = true;
    }

    void NegativeCount()
    {
        m_negativeCount = true;
    }

    void Mismatch()
    {
        m_mismatch = true;
    }

    void FailedToConverge()
    {
        m_failedToConverge = true;
    }

    void EntryWeightZero()
    {
        m_entryWeightZero = true;
    }

    // Are there are reparable issues with the reconstruction?
    //
    bool IsGood() const
    {
        return !(m_entryWeightZero || m_negativeCount);
    }

    void VisitBlock(BasicBlock*) override
    {
    }

    void VisitTreeEdge(BasicBlock* source, BasicBlock* target) override
    {
        // Tree edges should not be in the schema.
        //
        // If they are, we have somekind of mismatch between instrumentation and
        // reconstruction. Flag this.
        //
        EdgeKey key(source, target);

        if (m_edgeKeyToEdgeMap.Lookup(key))
        {
            JITDUMP("Did not expect tree edge " FMT_BB " -> " FMT_BB " to be present in the schema (key %08x, %08x)\n",
                    source->bbNum, target->bbNum, key.m_sourceKey, key.m_targetKey);

            Mismatch();
            return;
        }

        Edge* const edge = new (m_allocator) Edge(source, target);
        m_edges++;
        m_unknownEdges++;

        BlockInfo* const sourceInfo = BlockToInfo(source);
        edge->m_nextOutgoingEdge    = sourceInfo->m_outgoingEdges;
        sourceInfo->m_outgoingEdges = edge;
        sourceInfo->m_outgoingUnknown++;

        BlockInfo* const targetInfo = BlockToInfo(target);
        edge->m_nextIncomingEdge    = targetInfo->m_incomingEdges;
        targetInfo->m_incomingEdges = edge;
        targetInfo->m_incomingUnknown++;

        JITDUMP(" ... unknown edge " FMT_BB " -> " FMT_BB "\n", source->bbNum, target->bbNum);
    }

    void VisitNonTreeEdge(BasicBlock* source, BasicBlock* target, SpanningTreeVisitor::EdgeKind kind) override
    {
        // We may have this edge in the schema, and so already added this edge to the map.
        //
        EdgeKey key(source, target);
        Edge*   edge = nullptr;

        BlockInfo* const sourceInfo = BlockToInfo(source);

        if (!m_edgeKeyToEdgeMap.Lookup(key, &edge))
        {
            // If the edge is missing, assume it is zero.
            //
            JITDUMP("Schema is missing non-tree edge " FMT_BB " -> " FMT_BB ", will presume zero\n", source->bbNum,
                    target->bbNum);
            edge = new (m_allocator) Edge(source, target);
            m_edges++;
            m_zeroEdges++;

            edge->m_weightKnown = true;
            edge->m_weight      = 0;
        }

        edge->m_nextOutgoingEdge    = sourceInfo->m_outgoingEdges;
        sourceInfo->m_outgoingEdges = edge;

        BlockInfo* const targetInfo = BlockToInfo(target);
        edge->m_nextIncomingEdge    = targetInfo->m_incomingEdges;
        targetInfo->m_incomingEdges = edge;

        edge->m_isPseudoEdge = (kind == EdgeKind::Pseudo);
        JITDUMP(" ... %s edge " FMT_BB " -> " FMT_BB "\n", edge->m_isPseudoEdge ? "pseudo " : "known  ", source->bbNum,
                target->bbNum);
    }
};

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::Prepare: set up mapping information and
//    prepare for spanning tree walk and solver
//
void EfficientEdgeCountReconstructor::Prepare()
{
#ifdef DEBUG
    // If we're going to assign random counts we want to make sure
    // at least one BBJ_RETURN block has nonzero counts.
    //
    unsigned nReturns     = 0;
    unsigned nZeroReturns = 0;
#endif

    // Create per-block info, and set up the key to block map.
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        m_keyToBlockMap.Set(EfficientEdgeCountBlockToKey(block), block);
        BlockInfo* const info = new (m_allocator) BlockInfo();
        SetBlockInfo(block, info);

        // No block counts are known, initially.
        //
        m_blocks++;
        m_unknownBlocks++;

#ifdef DEBUG
        if (block->KindIs(BBJ_RETURN))
        {
            nReturns++;
        }
#endif
    }

    // Create edges for schema entries with edge counts, and set them up in
    // the edge key to edge map.
    //
    for (UINT32 iSchema = 0; iSchema < m_comp->fgPgoSchemaCount; iSchema++)
    {
        const ICorJitInfo::PgoInstrumentationSchema& schemaEntry = m_comp->fgPgoSchema[iSchema];
        switch (schemaEntry.InstrumentationKind)
        {
            case ICorJitInfo::PgoInstrumentationKind::EdgeIntCount:
            case ICorJitInfo::PgoInstrumentationKind::EdgeLongCount:
            {
                // Find the blocks.
                //
                BasicBlock* sourceBlock = nullptr;

                if (!m_keyToBlockMap.Lookup(schemaEntry.ILOffset, &sourceBlock))
                {
                    JITDUMP("Could not find source block for schema entry %d (IL offset/key %08x)\n", iSchema,
                            schemaEntry.ILOffset);
                }

                BasicBlock* targetBlock = nullptr;

                if (!m_keyToBlockMap.Lookup(schemaEntry.Other, &targetBlock))
                {
                    JITDUMP("Could not find target block for schema entry %d (IL offset/key %08x)\n", iSchema,
                            schemaEntry.ILOffset);
                }

                if ((sourceBlock == nullptr) || (targetBlock == nullptr))
                {
                    // Looks like there is skew between schema and graph.
                    //
                    Mismatch();
                    continue;
                }

                // Optimization TODO: if profileCount is zero, we can just ignore this edge
                // and the right things will happen.
                //
                uint64_t profileCount =
                    schemaEntry.InstrumentationKind == ICorJitInfo::PgoInstrumentationKind::EdgeIntCount
                        ? *(uint32_t*)(m_comp->fgPgoData + schemaEntry.Offset)
                        : *(uint64_t*)(m_comp->fgPgoData + schemaEntry.Offset);

#ifdef DEBUG
                // Optional stress mode to use a random count. Because edge profile counters have
                // little redundancy, random count assignments should generally lead to a consistent
                // set of block counts.
                //
                const bool useRandom = (JitConfig.JitRandomEdgeCounts() != 0) && (nReturns > 0);

                if (useRandom)
                {
                    // Reuse the random inliner's random state.
                    // Config setting will serve as the random seed, if no other seed has been supplied already.
                    //
                    CLRRandom* const random =
                        m_comp->impInlineRoot()->m_inlineStrategy->GetRandom(JitConfig.JitRandomEdgeCounts());

                    const bool isReturn = sourceBlock->KindIs(BBJ_RETURN);

                    // We simulate the distribution of counts seen in StdOptimizationData.Mibc.
                    //
                    const double rval = random->NextDouble();

                    // Ensure at least one return has nonzero counts.
                    //
                    if ((rval <= 0.5) && (!isReturn || (nZeroReturns < (nReturns - 1))))
                    {
                        profileCount = 0;
                        if (isReturn)
                        {
                            nZeroReturns++;
                        }
                    }
                    else if (rval <= 0.85)
                    {
                        profileCount = random->Next(1, 101);
                    }
                    else if (rval <= 0.96)
                    {
                        profileCount = random->Next(101, 10001);
                    }
                    else if (rval <= 0.995)
                    {
                        profileCount = random->Next(10001, 100001);
                    }
                    else
                    {
                        profileCount = random->Next(100001, 1000001);
                    }
                }
#endif

                weight_t const weight = (weight_t)profileCount;

                m_allWeightsZero &= (profileCount == 0);

                Edge* const edge = new (m_allocator) Edge(sourceBlock, targetBlock);

                JITDUMP("... adding known edge " FMT_BB " -> " FMT_BB ": weight " FMT_WT "\n",
                        edge->m_sourceBlock->bbNum, edge->m_targetBlock->bbNum, weight);

                edge->m_weightKnown = true;
                edge->m_weight      = weight;

                EdgeKey edgeKey(schemaEntry.ILOffset, schemaEntry.Other);
                m_edgeKeyToEdgeMap.Set(edgeKey, edge);

                m_edges++;
            }
            break;

            default:
                break;
        }
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::Solve: solve for missing edge and block counts
//
void EfficientEdgeCountReconstructor::Solve()
{
    // If issues arose earlier, then don't try solving.
    //
    if (m_badcode || m_mismatch || m_allWeightsZero)
    {
        JITDUMP("... not solving because of the %s\n", m_badcode          ? "badcode"
                                                       : m_allWeightsZero ? "zero counts"
                                                                          : "mismatch");
        return;
    }

    // If this is an OSR method, we might need to add an edge from the
    // OSR entry block to the method entry block.
    //
    // If so we give this edge a known weight of 1.0 to represent the
    // missing flow for invocations of the original method that
    // transferred control to the patchpoint.
    //
    // Note it's possible the original method transferred control to the
    // OSR method many times, so the actual weight might need to be larger.
    //
    if (m_comp->opts.IsOSR())
    {
        EdgeKey key(m_comp->fgOSREntryBB, m_comp->fgFirstBB);
        Edge*   edge = nullptr;
        if (!m_edgeKeyToEdgeMap.Lookup(key, &edge))
        {
            JITDUMP("Method is OSR, adding pseudo edge from osr entry to first block\n");
            edge = new (m_allocator) Edge(m_comp->fgOSREntryBB, m_comp->fgFirstBB);
            m_edges++;
            edge->m_weightKnown = true;
            edge->m_weight      = 1.0;
            m_edgeKeyToEdgeMap.Set(key, edge);
            VisitNonTreeEdge(m_comp->fgOSREntryBB, m_comp->fgFirstBB, EdgeKind::Pseudo);
        }
        else
        {
            assert(edge->m_weightKnown);
        }
    }

    unsigned       nPasses = 0;
    unsigned const nLimit  = 10;

    JITDUMP("\nSolver: %u blocks, %u unknown; %u edges, %u unknown, %u zero\n", m_blocks, m_unknownBlocks, m_edges,
            m_unknownEdges, m_zeroEdges);

    while ((m_unknownBlocks > 0) && (nPasses < nLimit))
    {
        nPasses++;
        JITDUMP("\nPass [%u]: %u unknown blocks, %u unknown edges\n", nPasses, m_unknownBlocks, m_unknownEdges);

        // TODO: no point walking all the blocks here, we should find a way to just walk
        // the subset with unknown counts or edges.
        //
        // The ideal solver order is likely reverse postorder over the depth-first spanning tree.
        // We approximate it here by running from last node to first.
        //
        for (BasicBlock* block = m_comp->fgLastBB; (block != nullptr); block = block->Prev())
        {
            BlockInfo* const info = BlockToInfo(block);

            // Try and determine block weight.
            //
            if (!info->m_weightKnown)
            {
                JITDUMP(FMT_BB ": %u incoming unknown, %u outgoing unknown\n", block->bbNum, info->m_incomingUnknown,
                        info->m_outgoingUnknown);

                weight_t weight      = BB_ZERO_WEIGHT;
                bool     weightKnown = false;
                if (info->m_incomingUnknown == 0)
                {
                    JITDUMP(FMT_BB ": all incoming edge weights known, summing...\n", block->bbNum);
                    for (Edge* edge = info->m_incomingEdges; edge != nullptr; edge = edge->m_nextIncomingEdge)
                    {
                        if (!edge->m_weightKnown)
                        {
                            JITDUMP("... odd, expected " FMT_BB " -> " FMT_BB " to have known weight\n",
                                    edge->m_sourceBlock->bbNum, edge->m_targetBlock->bbNum);
                        }
                        assert(edge->m_weightKnown);
                        JITDUMP("  " FMT_BB " -> " FMT_BB " has weight " FMT_WT "\n", edge->m_sourceBlock->bbNum,
                                edge->m_targetBlock->bbNum, edge->m_weight);
                        weight += edge->m_weight;
                    }
                    JITDUMP(FMT_BB ": all incoming edge weights known, sum is " FMT_WT "\n", block->bbNum, weight);
                    weightKnown = true;
                }
                else if (info->m_outgoingUnknown == 0)
                {
                    JITDUMP(FMT_BB ": all outgoing edge weights known, summing...\n", block->bbNum);
                    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
                    {
                        if (!edge->m_weightKnown)
                        {
                            JITDUMP("... odd, expected " FMT_BB " -> " FMT_BB " to have known weight\n",
                                    edge->m_sourceBlock->bbNum, edge->m_targetBlock->bbNum);
                        }
                        assert(edge->m_weightKnown);
                        JITDUMP("  " FMT_BB " -> " FMT_BB " has weight " FMT_WT "\n", edge->m_sourceBlock->bbNum,
                                edge->m_targetBlock->bbNum, edge->m_weight);
                        weight += edge->m_weight;
                    }
                    JITDUMP(FMT_BB ": all outgoing edge weights known, sum is " FMT_WT "\n", block->bbNum, weight);
                    weightKnown = true;
                }

                if (weightKnown)
                {
                    info->m_weight      = weight;
                    info->m_weightKnown = true;
                    assert(m_unknownBlocks > 0);
                    m_unknownBlocks--;
                }
            }

            // If we still don't know the block weight, move on to the next block.
            //
            if (!info->m_weightKnown)
            {
                continue;
            }

            // If we know the block weight, see if we can resolve any edge weights.
            //
            if (info->m_incomingUnknown == 1)
            {
                weight_t weight       = BB_ZERO_WEIGHT;
                Edge*    resolvedEdge = nullptr;
                for (Edge* edge = info->m_incomingEdges; edge != nullptr; edge = edge->m_nextIncomingEdge)
                {
                    if (edge->m_weightKnown)
                    {
                        weight += edge->m_weight;
                    }
                    else
                    {
                        assert(resolvedEdge == nullptr);
                        resolvedEdge = edge;
                    }
                }

                assert(resolvedEdge != nullptr);

                weight = info->m_weight - weight;

                JITDUMP(FMT_BB " -> " FMT_BB
                               ": target block weight and all other incoming edge weights known, so weight is " FMT_WT
                               "\n",
                        resolvedEdge->m_sourceBlock->bbNum, resolvedEdge->m_targetBlock->bbNum, weight);

                // If we arrive at a negative count for this edge, set it to a small fraction of the block weight.
                //
                // Note this can happen somewhat frequently because of inconsistent counts from
                // scalable or racing counters.
                //
                if (weight < 0)
                {
                    NegativeCount();
                    weight = info->m_weight * ProfileSynthesis::epsilon;
                    JITDUMP(" .... weight was negative, setting it to " FMT_WT "\n", weight);
                }

                resolvedEdge->m_weight      = weight;
                resolvedEdge->m_weightKnown = true;

                // Update source and target info.
                //
                assert(BlockToInfo(resolvedEdge->m_sourceBlock)->m_outgoingUnknown > 0);
                BlockToInfo(resolvedEdge->m_sourceBlock)->m_outgoingUnknown--;
                info->m_incomingUnknown--;
                assert(m_unknownEdges > 0);
                m_unknownEdges--;
            }

            if (info->m_outgoingUnknown == 1)
            {
                weight_t weight       = BB_ZERO_WEIGHT;
                Edge*    resolvedEdge = nullptr;
                for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
                {
                    if (edge->m_weightKnown)
                    {
                        weight += edge->m_weight;
                    }
                    else
                    {
                        assert(resolvedEdge == nullptr);
                        resolvedEdge = edge;
                    }
                }

                assert(resolvedEdge != nullptr);

                weight = info->m_weight - weight;

                JITDUMP(FMT_BB " -> " FMT_BB
                               ": source block weight and all other outgoing edge weights known, so weight is " FMT_WT
                               "\n",
                        resolvedEdge->m_sourceBlock->bbNum, resolvedEdge->m_targetBlock->bbNum, weight);

                // If we arrive at a negative count for this edge, set it to a small fraction of the block weight.
                //
                // Note this can happen somewhat frequently because of inconsistent counts from
                // scalable or racing counters.
                //
                if (weight < 0)
                {
                    NegativeCount();
                    weight = info->m_weight * ProfileSynthesis::epsilon;
                    JITDUMP(" .... weight was negative, setting it to " FMT_WT "\n", weight);
                }

                resolvedEdge->m_weight      = weight;
                resolvedEdge->m_weightKnown = true;

                // Update source and target info.
                //
                info->m_outgoingUnknown--;
                assert(BlockToInfo(resolvedEdge->m_targetBlock)->m_incomingUnknown > 0);
                BlockToInfo(resolvedEdge->m_targetBlock)->m_incomingUnknown--;
                assert(m_unknownEdges > 0);
                m_unknownEdges--;
            }
        }
    }

    if (m_unknownBlocks != 0)
    {
        JITDUMP("\nSolver: failed to converge in %u passes, %u blocks and %u edges remain unsolved\n", nPasses,
                m_unknownBlocks, m_unknownEdges);
        FailedToConverge();
        return;
    }

    JITDUMP("\nSolver: converged in %u passes\n", nPasses);

    // If, after solving, the entry weight ends up as zero, note
    // this so we can run a profile repair immediately.
    //
    BlockInfo* const firstInfo = BlockToInfo(m_comp->fgFirstBB);
    if (firstInfo->m_weight == BB_ZERO_WEIGHT)
    {
        assert(!m_allWeightsZero);
        JITDUMP("\nSolver: entry block weight is zero\n");
        EntryWeightZero();
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::Propagate: actually set block weights
//    and edge likelihoods.
//
void EfficientEdgeCountReconstructor::Propagate()
{
    // Mismatches are currently expected as the flow for static pgo doesn't prevent them now.
    //    assert(!m_mismatch);

    assert(!m_failedToConverge);

    // If any issues arose during reconstruction, don't set weights.
    //
    if (m_badcode || m_mismatch || m_failedToConverge || m_allWeightsZero)
    {
        // Make sure nothing else in the jit looks at the count profile data.
        //
        m_comp->fgPgoHaveWeights = false;

        if (m_badcode)
        {
            m_comp->fgPgoFailReason = "PGO data available, but IL was malformed";
        }
        else if (m_mismatch)
        {
            m_comp->fgPgoFailReason = "PGO data available, but IL did not match";
        }
        else if (m_failedToConverge)
        {
            m_comp->fgPgoFailReason = "PGO data available, but solver did not converge";
        }
        else
        {
            m_comp->fgPgoFailReason = "PGO data available, profile data was all zero";
        }

        JITDUMP("... discarding profile count data: %s\n", m_comp->fgPgoFailReason);
        return;
    }

    // Set weight on all blocks and edges.
    //
    for (BasicBlock* const block : m_comp->Blocks())
    {
        BlockInfo* const info = BlockToInfo(block);
        assert(info->m_weightKnown);
        block->setBBProfileWeight(info->m_weight);

        const unsigned nSucc = block->NumSucc();
        if (nSucc == 0)
        {
            // No edges to worry about.
            //
            continue;
        }

        bool const isOSREntry = m_comp->opts.IsOSR() && (block == m_comp->fgOSREntryBB);

        if (isOSREntry)
        {
            PropagateOSREntryEdges(block, info, nSucc);
        }
        else
        {
            PropagateEdges(block, info, nSucc);
        }

        // Mark blocks that might be worth optimizing further, given
        // what we know about the PGO data.
        //
        MarkInterestingBlocks(block, info);
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::PropagateOSREdges: set edge likelihoods
//    for the OSR entry block.
//
// Arguments:
//    block - block in question (OSR entry)
//    info - model info for the block
//    nSucc - number of successors of the block in the flow graph
//
// Notes:
//    This block requires special handling because original method flow
//    was interrupted here.
//
void EfficientEdgeCountReconstructor::PropagateOSREntryEdges(BasicBlock* block, BlockInfo* info, unsigned nSucc)
{
    // We expect one pseudo-edge and at least one normal edge.
    //
    Edge*    pseudoEdge       = nullptr;
    weight_t pseudoEdgeWeight = 0;
    unsigned nEdges           = 0;
    weight_t successorWeight  = BB_ZERO_WEIGHT;

    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
    {
        if (edge->m_isPseudoEdge)
        {
            assert(pseudoEdge == nullptr);
            pseudoEdge       = edge;
            pseudoEdgeWeight = edge->m_weight;
            continue;
        }

        successorWeight += edge->m_weight;
        nEdges++;
    }

    // However, if the OSR entry is also the first block (which can happen if the first
    // block in the method is a self-loop and we put a patchpoint there), we won't have
    // a pseudo-edge.
    //
    if ((block != m_comp->fgFirstBB) && (pseudoEdge == nullptr))
    {
        JITDUMP("Missing special OSR pseudo-edge from " FMT_BB "-> " FMT_BB "\n", block->bbNum,
                m_comp->fgFirstBB->bbNum);
        assert(pseudoEdge != nullptr);
    }

    assert(nEdges == nSucc);

    if ((info->m_weight == BB_ZERO_WEIGHT) || (successorWeight == BB_ZERO_WEIGHT))
    {
        JITDUMP("\nPropagate: OSR entry block or successor weight is zero\n");
        EntryWeightZero();
        return;
    }

    // Transfer model edge weight onto the FlowEdges as likelihoods.
    //
    JITDUMP("Normalizing OSR successor likelihoods with factor 1/" FMT_WT "\n", successorWeight);

    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
    {
        assert(block == edge->m_sourceBlock);

        // The pseudo edge doesn't correspond to a flow edge.
        //
        if (edge == pseudoEdge)
        {
            continue;
        }

        assert(!edge->m_isPseudoEdge);
        FlowEdge* const flowEdge = m_comp->fgGetPredForBlock(edge->m_targetBlock, block);

        assert(flowEdge != nullptr);

        // Naive likelihood should have been set during pred initialization in fgLinkBasicBlocks
        //
        assert(flowEdge->hasLikelihood());
        weight_t likelihood = 0;

        if (nEdges == 1)
        {
            // Go with what we know for sure, edge should be 100% likely.
            //
            likelihood = 1.0;
            JITDUMP("Setting likelihood of " FMT_BB " -> " FMT_BB " to " FMT_WT " (uniq)\n", block->bbNum,
                    edge->m_targetBlock->bbNum, likelihood);
            flowEdge->setLikelihood(likelihood);
            break;
        }

        likelihood = edge->m_weight / successorWeight;
        JITDUMP("Setting likelihood of " FMT_BB " -> " FMT_BB " to " FMT_WT " (pgo)\n", block->bbNum,
                edge->m_targetBlock->bbNum, likelihood);
        flowEdge->setLikelihood(likelihood);
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::PropagateEdges: set edge likelihoods
//    for a block.
//
// Arguments:
//    block - block in question
//    info - model info for the block
//    nSucc - number of successors of the block in the flow graph
//
void EfficientEdgeCountReconstructor::PropagateEdges(BasicBlock* block, BlockInfo* info, unsigned nSucc)
{
    // There is at least one FlowEdge.
    //
    // Check the reconstruction graph edges. For normal blocks, if we have
    // any pseudo-edges there should be only one pseudo-edge, and no regular edges.
    //
    Edge*    pseudoEdge      = nullptr;
    unsigned nEdges          = 0;
    weight_t successorWeight = BB_ZERO_WEIGHT;

    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
    {
        assert(pseudoEdge == nullptr);
        if (edge->m_isPseudoEdge)
        {
            pseudoEdge = edge;
            continue;
        }

        successorWeight += edge->m_weight;
        nEdges++;
    }

    // If there is a pseudo edge,
    // There should be only one successor for block. The flow
    // from block to successor will not represent real flow.
    // Likelihood should be set to 1.0 already, as we already know
    // this block has only one successor.
    //
    // Note the flowEdge target may not be the same as the pseudo edge target.
    //
    if (pseudoEdge != nullptr)
    {
        assert(nSucc == 1);
        assert(block == pseudoEdge->m_sourceBlock);
        assert(block->HasInitializedTarget());
        FlowEdge* const flowEdge = block->GetTargetEdge();
        assert(flowEdge != nullptr);
        assert(flowEdge->getLikelihood() == 1.0);
        return;
    }

    // We may not have have the same number of model edges and flow edges.
    //
    // This can happen because bome BBJ_LEAVE blocks may have been missed during
    // our spanning tree walk since we don't know where all the finallies can return
    // to just yet (specially, in WalkSpanningTree, we may not add the target of
    // a BBJ_LEAVE to the worklist).
    //
    // Worst case those missed blocks dominate other blocks so we can't limit
    // the screening here to specific BBJ kinds.
    //
    // Handle those specially by just assuming equally likely successors.
    //
    // Do likewise, if the block weight is zero, since examination of edge weights
    // shouldn't tell us anything about edge likelihoods.
    //
    // (TODO: use synthesis here)
    //
    if ((nEdges != nSucc) || (info->m_weight == BB_ZERO_WEIGHT) || (successorWeight == BB_ZERO_WEIGHT))
    {
        JITDUMP(FMT_BB " %s , setting outgoing likelihoods heuristically\n", block->bbNum,
                (nEdges != nSucc) ? "has inaccurate flow model" : "has zero weight");

        weight_t equalLikelihood = 1.0 / nSucc;

        for (FlowEdge* const succEdge : block->SuccEdges())
        {
            BasicBlock* const succBlock = succEdge->getDestinationBlock();
            JITDUMP("Setting likelihood of " FMT_BB " -> " FMT_BB " to " FMT_WT " (heur)\n", block->bbNum,
                    succBlock->bbNum, equalLikelihood);
            succEdge->setLikelihood(equalLikelihood);
        }

        return;
    }

    // Transfer model edge weight onto the FlowEdges as likelihoods.
    //
    assert(nEdges == nSucc);
    JITDUMP("Normalizing successor likelihoods with factor 1/" FMT_WT "\n", successorWeight);

    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
    {
        assert(block == edge->m_sourceBlock);
        FlowEdge* const flowEdge = m_comp->fgGetPredForBlock(edge->m_targetBlock, block);
        assert(flowEdge != nullptr);
        weight_t likelihood = 0;

        if (nEdges == 1)
        {
            assert(nSucc == 1);
            likelihood = 1.0;
            JITDUMP("Setting likelihood of " FMT_BB " -> " FMT_BB " to " FMT_WT " (uniq)\n", block->bbNum,
                    edge->m_targetBlock->bbNum, likelihood);
            flowEdge->setLikelihood(likelihood);
            break;
        }

        likelihood = edge->m_weight / successorWeight;
        JITDUMP("Setting likelihood of " FMT_BB " -> " FMT_BB " to " FMT_WT " (pgo)\n", block->bbNum,
                edge->m_targetBlock->bbNum, likelihood);
        flowEdge->setLikelihood(likelihood);
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::MarkInterestingBlocks: look for blocks
//   that are worth specially optimizing, given the block and edge profile data
//
// Arguments:
//    block - block of interest
//    info - associated block info
//
// Notes:
//    We do this during reconstruction because we have a clean look at the edge
//    weights. If we defer until we recompute edge weights later we may fail to solve
//    for them.
//
//    Someday we'll keep the edge profile info viable all throughout compilation and
//    we can defer this screening until later. Doing so will catch more cases as
//    optimizations can sharpen the profile data.
//
void EfficientEdgeCountReconstructor::MarkInterestingBlocks(BasicBlock* block, BlockInfo* info)
{
    switch (block->GetKind())
    {
        case BBJ_SWITCH:
            MarkInterestingSwitches(block, info);
            break;

        default:
            break;
    }
}

//------------------------------------------------------------------------
// EfficientEdgeCountReconstructor::MarkInterestingSwitches: look for switch blocks
//   that are worth specially optimizing, given the block and edge profile data
//
// Arguments:
//    block - block of interest
//    info - associated block info
//
// Notes:
//    See if one of the non-default switch cases dominates and should be peeled
//    from the switch during flow opts.
//
//    If so, information is added to the bbJmpSwt for the block for use later.
//
void EfficientEdgeCountReconstructor::MarkInterestingSwitches(BasicBlock* block, BlockInfo* info)
{
    assert(block->KindIs(BBJ_SWITCH));

    // Thresholds for detecting a dominant switch case.
    //
    // We need to see enough hits on the switch to have a plausible sense of the distribution of cases.
    // We also want to enable peeling for switches that are executed at least once per call.
    // By default, we're guaranteed to see at least 30 calls to instrumented method, for dynamic PGO.
    // Hence we require at least 30 observed switch executions.
    //
    // The profitability of peeling is related to the dominant fraction. The cost has a constant portion
    // (at a minimum the cost of a not-taken branch) and a variable portion, plus increased code size.
    // So we don't want to peel in cases where the dominant fraction is too small.
    //
    const weight_t sufficientSamples  = 30.0;
    const weight_t sufficientFraction = 0.55;

    if (info->m_weight < sufficientSamples)
    {
        JITDUMP("Switch in " FMT_BB " was hit " FMT_WT " < " FMT_WT " times, NOT checking for dominant edge\n",
                block->bbNum, info->m_weight, sufficientSamples);
        return;
    }

    JITDUMP("Switch in " FMT_BB " was hit " FMT_WT " >= " FMT_WT " times, checking for dominant edge\n", block->bbNum,
            info->m_weight, sufficientSamples);
    Edge* dominantEdge = nullptr;

    // We don't expect to see any unknown edge weights; if we do, just bail out.
    //
    for (Edge* edge = info->m_outgoingEdges; edge != nullptr; edge = edge->m_nextOutgoingEdge)
    {
        if (!edge->m_weightKnown)
        {
            JITDUMP("Found edge with unknown weight.\n");
            return;
        }

        if ((dominantEdge == nullptr) || (edge->m_weight > dominantEdge->m_weight))
        {
            dominantEdge = edge;
        }
    }

    assert(dominantEdge != nullptr);
    weight_t fraction = dominantEdge->m_weight / info->m_weight;

    // Because of count inconsistency we can see nonsensical ratios. Cap these.
    //
    if (fraction > 1.0)
    {
        fraction = 1.0;
    }

    if (fraction < sufficientFraction)
    {
        JITDUMP("Maximum edge likelihood is " FMT_WT " < " FMT_WT "; not sufficient to trigger peeling)\n", fraction,
                sufficientFraction);
        return;
    }

    // Despite doing "edge" instrumentation, we only use a single edge probe for a given successor block.
    // Multiple switch cases may lead to this block. So we also need to show that there's just one switch
    // case that can lead to the dominant edge's target block.
    //
    // If it turns out often we fail at this stage, we might consider building a histogram of switch case
    // values at runtime, similar to what we do for classes at virtual call sites.
    //
    const unsigned   caseCount    = block->GetSwitchTargets()->GetCaseCount();
    FlowEdge** const jumpTab      = block->GetSwitchTargets()->GetCases();
    unsigned         dominantCase = caseCount;

    for (unsigned i = 0; i < caseCount; i++)
    {
        BasicBlock* jumpTarget = jumpTab[i]->getDestinationBlock();
        if (jumpTarget == dominantEdge->m_targetBlock)
        {
            if (dominantCase != caseCount)
            {
                JITDUMP("Both case %u and %u lead to " FMT_BB "-- can't optimize\n", i, dominantCase,
                        jumpTarget->bbNum);
                dominantCase = caseCount;
                break;
            }

            dominantCase = i;
        }
    }

    if (dominantCase == caseCount)
    {
        // Multiple (or no) cases lead to the dominant case target.
        //
        return;
    }

    if (block->GetSwitchTargets()->HasDefaultCase() && (dominantCase == caseCount - 1))
    {
        // Dominant case is the default case.
        // This effectively gets peeled already, so defer.
        //
        JITDUMP("Default case %u uniquely leads to target " FMT_BB " of dominant edge, so will be peeled already\n",
                dominantCase, dominantEdge->m_targetBlock->bbNum);
        return;
    }

    JITDUMP("Non-default case %u uniquely leads to target " FMT_BB " of dominant edge with likelihood " FMT_WT
            "; marking for peeling\n",
            dominantCase, dominantEdge->m_targetBlock->bbNum, fraction);

    block->GetSwitchTargets()->SetDominantCase(dominantCase);
}

//------------------------------------------------------------------------
// fgIncorporateEdgeCounts: read sparse edge count based profile data
//   and set block weights
//
// Returns:
//    true if incorporated profile is in good shape (consistent, etc).
//    false if some repair seems necessary
//
// Notes:
//   Because edge counts are sparse, we need to solve for the missing
//   edge counts; in the process, we also determine block counts.
//
// Todo:
//   Normalize counts.
//   Since we have edge weights here, we might as well set them
//   (or likelihoods)
//
bool Compiler::fgIncorporateEdgeCounts()
{
    JITDUMP("\nReconstructing block counts from sparse edge instrumentation\n");

    EfficientEdgeCountReconstructor e(this);
    e.Prepare();
    WalkSpanningTree(&e);
    e.Solve();
    e.Propagate();

    return e.IsGood();
}

//-------------------------------------------------------------
// fgComputeBlockWeights: determine weights for blocks
//
// Returns:
//    Suitable phase status
//
PhaseStatus Compiler::fgComputeBlockWeights()
{
    fgModified = false;

#if DEBUG
    if (verbose)
    {
        fgDispBasicBlocks();
        printf("\n");
    }
#endif // DEBUG

    if (fgIsUsingProfileWeights())
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }

    return fgComputeMissingBlockWeights() ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//-------------------------------------------------------------
// fgComputeMissingBlockWeights: determine weights for blocks
//   that were not profiled and do not yet have weights.
//
// Returns:
//    true if any changes made
//
bool Compiler::fgComputeMissingBlockWeights()
{
    BasicBlock* bSrc;
    BasicBlock* bDst;
    unsigned    iterations = 0;
    bool        changed;
    bool        modified = false;

    // If we have any blocks that did not have profile derived weight
    // we will try to fix their weight up here
    //
    modified = false;
    do // while (changed)
    {
        changed = false;
        iterations++;

        for (bDst = fgFirstBB; bDst != nullptr; bDst = bDst->Next())
        {
            if (!bDst->hasProfileWeight() && (bDst->bbPreds != nullptr))
            {
                BasicBlock* bOnlyNext;

                // This block does not have a profile derived weight
                //
                weight_t newWeight = BB_MAX_WEIGHT;

                if (bDst->countOfInEdges() == 1)
                {
                    // Only one block flows into bDst
                    bSrc = bDst->bbPreds->getSourceBlock();

                    // Does this block flow into only one other block
                    if (bSrc->KindIs(BBJ_ALWAYS))
                    {
                        bOnlyNext = bSrc->GetTarget();
                    }
                    else
                    {
                        bOnlyNext = nullptr;
                    }

                    if ((bOnlyNext == bDst) && bSrc->hasProfileWeight())
                    {
                        // We know the exact weight of bDst
                        newWeight = bSrc->bbWeight;
                    }
                }

                // Does this block flow into only one other block
                if (bDst->KindIs(BBJ_ALWAYS))
                {
                    bOnlyNext = bDst->GetTarget();
                }
                else if (bDst->KindIs(BBJ_CALLFINALLYRET)) // TODO-Quirk: remove (was added to reduce asmdiffs)
                {
                    bOnlyNext = bDst->GetFinallyContinuation();
                }
                else
                {
                    bOnlyNext = nullptr;
                }

                if ((bOnlyNext != nullptr) && (bOnlyNext->bbPreds != nullptr))
                {
                    // Does only one block flow into bOnlyNext
                    if (bOnlyNext->countOfInEdges() == 1)
                    {
                        noway_assert(bOnlyNext->bbPreds->getSourceBlock() == bDst);

                        // We know the exact weight of bDst
                        newWeight = bOnlyNext->bbWeight;
                    }
                }

                // Handler entries are assumed to run rarely, except for
                // finally blocks: These are executed regardless of if
                // an exception is thrown, and thus should inherit weight.
                if (bbIsHandlerBeg(bDst))
                {
                    bSrc = bDst->bbPreds->getSourceBlock();

                    // To minimize asmdiffs for now, modify weights only if splitting.
                    if (fgFirstColdBlock != nullptr)
                    {
                        if (bSrc->KindIs(BBJ_CALLFINALLY))
                        {
                            newWeight = bSrc->bbWeight;
                        }
                        else
                        {
                            newWeight = BB_ZERO_WEIGHT;
                        }
                    }
                }

                if ((newWeight != BB_MAX_WEIGHT) && (bDst->bbWeight != newWeight))
                {
                    changed        = true;
                    modified       = true;
                    bDst->bbWeight = newWeight;
                }
            }
            else if (!bDst->hasProfileWeight() && bbIsHandlerBeg(bDst) && !bDst->isRunRarely())
            {
                // Assume handler/filter entries are rarely executed.
                // To avoid unnecessary loop iterations, set weight
                // only if bDst->bbWeight is not already zero.

                // To minimize asmdiffs for now, modify weights only if splitting.
                if (fgFirstColdBlock != nullptr)
                {
                    changed  = true;
                    modified = true;
                    bDst->bbSetRunRarely();
                }
            }
        }
    }
    // Generally when we synthesize profile estimates we do it in a way where this algorithm will converge
    // but downstream opts that remove conditional branches may create a situation where this is not the case.
    // For instance a loop that becomes unreachable creates a sort of 'ring oscillator' (See test b539509)
    while (changed && iterations < 10);

#if DEBUG
    if (verbose && modified)
    {
        printf("fgComputeMissingBlockWeights() adjusted the weight of some blocks\n");
        fgDispBasicBlocks();
        printf("\n");
    }
#endif

    return modified;
}

//------------------------------------------------------------------------
// fgProfileWeightsEqual: check if two profile weights are equal
//   (or nearly so)
//
// Arguments:
//   weight1 -- first weight
//   weight2 -- second weight
//   epsilon -- maximum absolute difference for weights to be considered equal
//
// Notes:
//   In most cases you should probably call fgProfileWeightsConsistent instead
//   of this method.
//
bool Compiler::fgProfileWeightsEqual(weight_t weight1, weight_t weight2, weight_t epsilon)
{
    return fabs(weight1 - weight2) <= epsilon;
}

//------------------------------------------------------------------------
// fgProfileWeightsConsistent: check if two profile weights are within
//   some small percentage of one another.
//
// Arguments:
//   weight1 -- first weight
//   weight2 -- second weight
//
bool Compiler::fgProfileWeightsConsistent(weight_t weight1, weight_t weight2)
{
    if (weight2 == BB_ZERO_WEIGHT)
    {
        return fgProfileWeightsEqual(weight1, weight2);
    }

    weight_t const relativeDiff = (weight2 - weight1) / weight2;

    return fgProfileWeightsEqual(relativeDiff, BB_ZERO_WEIGHT);
}

//------------------------------------------------------------------------
// fgProfileWeightsConsistentOrSmall: check if two profile weights are within
//   some small percentage of one another, or are both less than some epsilon.
//
// Arguments:
//   weight1 -- first weight
//   weight2 -- second weight
//   epsilon -- small weight threshold
//
bool Compiler::fgProfileWeightsConsistentOrSmall(weight_t weight1, weight_t weight2, weight_t epsilon)
{
    if (weight2 == BB_ZERO_WEIGHT)
    {
        return fgProfileWeightsEqual(weight1, weight2, epsilon);
    }

    weight_t const delta = fabs(weight2 - weight1);

    if (delta <= epsilon)
    {
        return true;
    }

    weight_t const relativeDelta = delta / weight2;

    return fgProfileWeightsEqual(relativeDelta, BB_ZERO_WEIGHT);
}

#ifdef DEBUG

//------------------------------------------------------------------------
// fgDebugCheckProfile: verify profile data on flow graph is self-consistent
//   (or nearly so)
//
// Arguments:
//   checks -- [optional] phase checks in force
//
// Notes:
//   Will check full profile or just likelihoods, depending on the phase check arg.
//
//   Can be altered via external config.
//
void Compiler::fgDebugCheckProfile(PhaseChecks checks)
{
    const bool configEnabled = (JitConfig.JitProfileChecks() >= 0) && fgHaveProfileWeights() && fgPredsComputed;

    assert(checks != PhaseChecks::CHECK_NONE);

    if (configEnabled)
    {
        fgDebugCheckProfileWeights((ProfileChecks)JitConfig.JitProfileChecks());
    }
    else if (hasFlag(checks, PhaseChecks::CHECK_PROFILE))
    {
        ProfileChecks profileChecks = ProfileChecks::CHECK_LIKELY | ProfileChecks::RAISE_ASSERT;

        if (hasFlag(checks, PhaseChecks::CHECK_PROFILE_FLAGS))
        {
            profileChecks |= ProfileChecks::CHECK_FLAGS;
        }

        fgDebugCheckProfileWeights(profileChecks);
    }
    else if (hasFlag(checks, PhaseChecks::CHECK_LIKELIHOODS))
    {
        ProfileChecks profileChecks =
            ProfileChecks::CHECK_HASLIKELIHOOD | ProfileChecks::CHECK_LIKELIHOODSUM | ProfileChecks::RAISE_ASSERT;
        fgDebugCheckProfileWeights(profileChecks);
    }
}

//------------------------------------------------------------------------
// fgDebugCheckProfileWeights: verify profile weights are self-consistent
//   (or nearly so)
//
// Arguments:
//   checks - checker options
//
// Returns:
//   True if all enabled checks pass
//
// Notes:
//   For each profiled block, check that the flow of counts into
//   the block matches the flow of counts out of the block.
//
//   We ignore EH flow as we don't have explicit edges and generally
//   we expect EH edge counts to be small, so errors from ignoring
//   them should be rare.
//
//   There's no point checking until we've built pred lists, as
//   we can't easily reason about consistency without them.
//
bool Compiler::fgDebugCheckProfileWeights(ProfileChecks checks)
{
    // We can check classic (min/max, late computed) weights
    //   and/or
    // new likelihood based weights.
    //
    const bool verifyLikelyWeights = hasFlag(checks, ProfileChecks::CHECK_LIKELY);
    const bool verifyHasLikelihood = hasFlag(checks, ProfileChecks::CHECK_HASLIKELIHOOD);
    const bool verifyLikelihoodSum = hasFlag(checks, ProfileChecks::CHECK_LIKELIHOODSUM);
    const bool checkProfileFlag    = hasFlag(checks, ProfileChecks::CHECK_FLAGS) && fgIsUsingProfileWeights();
    const bool assertOnFailure     = hasFlag(checks, ProfileChecks::RAISE_ASSERT) && fgPgoConsistent;
    const bool checkAllBlocks      = hasFlag(checks, ProfileChecks::CHECK_ALL_BLOCKS);

    if (!verifyLikelyWeights && !verifyHasLikelihood)
    {
        JITDUMP("[profile weight checks disabled]\n");
        return true;
    }

    if (fgPgoDeferredInconsistency)
    {
        // We have a deferred consistency check failure. Just return w/o checking further
        // We will assert later once we see the method has valid IL.
        //
        JITDUMP("[deferred prior check failed -- skipping this check]\n");
        return false;
    }

    JITDUMP("Checking Profile Weights (flags:0x%x)\n", checks);
    unsigned problemBlocks    = 0;
    unsigned unprofiledBlocks = 0;
    unsigned profiledBlocks   = 0;
    unsigned unflaggedBlocks  = 0;
    bool     entryProfiled    = false;
    bool     exitProfiled     = false;
    bool     hasTry           = false;
    weight_t entryWeight      = 0;
    weight_t exitWeight       = 0;

    // Verify each profiled block.
    //
    for (BasicBlock* const block : Blocks())
    {
        if (!block->hasProfileWeight())
        {
            if (checkProfileFlag && (block->bbPreds != nullptr))
            {
                // Block has flow into it that isn't marked as profile-derived.
                //
                unflaggedBlocks++;
            }

            if (!checkAllBlocks)
            {
                unprofiledBlocks++;
                continue;
            }
        }

        // There is some profile data to check.
        //
        profiledBlocks++;

        // If there is a try region in the method, we won't be able
        // to reliably verify entry/exit counts.
        //
        // Technically this checking will fail only if there's a try that
        // must be exited via exception, but that's not worth checking for,
        // either here or in the solver.
        //
        hasTry |= block->hasTryIndex();

        // Currently using raw counts. Consider using normalized counts instead?
        //
        weight_t blockWeight = block->bbWeight;

        bool verifyIncoming = true;
        bool verifyOutgoing = true;

        // First, look for blocks that require special treatment.
        //
        // Note from a profile standpoint OSR methods are strange; the
        // profile data they have may reflect partial execution of the
        // original method (so exit profiles are unreliable), and they
        // will be missing most of the method's initial code (so entry
        // profiles are unreliable).

        // Entry blocks
        //
        if (block == fgFirstBB)
        {
            entryWeight += blockWeight;
            entryProfiled  = !opts.IsOSR();
            verifyIncoming = false;
        }

        // Exit blocks
        //
        if (block->KindIs(BBJ_RETURN))
        {
            exitWeight += blockWeight;
            exitProfiled   = true;
            verifyOutgoing = false;
        }
        else if (block->KindIs(BBJ_THROW))
        {
            bool const isCatchableThrow = block->hasTryIndex();

            if (isCatchableThrow)
            {
                assert(hasTry);
            }
            else
            {
                exitWeight += blockWeight;
                exitProfiled = true;
            }

            verifyOutgoing = false;
        }

        // OSR Entries
        //
        // These will frequently have a profile imbalance as
        // original method execution was hijacked at this block.
        //
        if (block == fgOSREntryBB)
        {
            verifyIncoming = false;
        }

        // Original entries in OSR methods that also are
        // loop headers.
        //
        // These will frequently have a profile imbalance as
        // synthesis will have injected profile weight for
        // method entry, but when we transform flow for OSR,
        // only the loop back edges remain.
        //
        if (block == fgEntryBB)
        {
            verifyIncoming = false;
        }

        // Handler entries
        //
        if (block->hasEHBoundaryIn())
        {
            verifyIncoming = false;
        }

        // Handler exits
        //
        if (block->hasEHBoundaryOut())
        {
            verifyOutgoing = false;
        }

        // We generally expect that the incoming flow, block weight and outgoing
        // flow should all match.
        //
        // But we have two edge counts... so for now we simply check if the block
        // count falls within the [min,max] range.
        //
        bool incomingConsistent = true;
        bool outgoingConsistent = true;

        if (verifyIncoming)
        {
            incomingConsistent = fgDebugCheckIncomingProfileData(block, checks);
        }

        if (verifyOutgoing)
        {
            outgoingConsistent = fgDebugCheckOutgoingProfileData(block, checks);
        }

        if (!incomingConsistent || !outgoingConsistent)
        {
            problemBlocks++;
        }
    }

    // Verify overall entry-exit balance.
    //
    if (verifyLikelyWeights)
    {
        // If there's a try, significant weight might pass along exception edges.
        // We don't model that, and it can throw off entry-exit balance.
        //
        if (entryProfiled && exitProfiled && !hasTry)
        {
            // Note these may not agree, if fgEntryBB is a loop header.
            //
            if (fgFirstBB->bbRefs > 1)
            {
                JITDUMP("  Method entry " FMT_BB " is loop head, can't check entry/exit balance\n");
            }
            else if (!fgProfileWeightsConsistent(entryWeight, exitWeight))
            {
                problemBlocks++;
                JITDUMP("  Method entry " FMT_WT " method exit " FMT_WT " weight mismatch\n", entryWeight, exitWeight);
            }
        }
    }

    // Summarize what we discovered.
    //
    if (problemBlocks == 0)
    {
        if (profiledBlocks == 0)
        {
            JITDUMP("No blocks were profiled, so nothing to check\n");
        }
        else if (verifyLikelyWeights)
        {
            JITDUMP("Profile is self-consistent (%d profiled blocks, %d unprofiled)\n", profiledBlocks,
                    unprofiledBlocks);
        }
        else if (verifyLikelihoodSum)
        {
            JITDUMP("All block successor flow edge likelihoods sum to 1.0\n");
        }
        else if (verifyHasLikelihood)
        {
            JITDUMP("All flow edges have likelihoods\n");
        }
    }
    else
    {
        JITDUMP("Profile is NOT self-consistent, found %d problems (%d profiled blocks, %d unprofiled)\n",
                problemBlocks, profiledBlocks, unprofiledBlocks);

        // Note we only assert when we think the profile data should be consistent.
        //
        if (assertOnFailure)
        {
            assert(!"Inconsistent profile data");
        }
    }

    if (unflaggedBlocks > 0)
    {
        JITDUMP("%d blocks are missing BBF_PROF_WEIGHT flag.\n", unflaggedBlocks);
        assert(!"Missing BBF_PROF_WEIGHT flag");
    }

    return (problemBlocks == 0);
}

//------------------------------------------------------------------------
// fgDebugCheckIncomingProfileData: verify profile data flowing into a
//   block matches the profile weight of the block.
//
// Arguments:
//   block  - block to check
//   checks - checker options
//
// Returns:
//   true if counts consistent or checking disabled, false otherwise.
//
// Notes:
//   Only useful to call on blocks with predecessors.
//
bool Compiler::fgDebugCheckIncomingProfileData(BasicBlock* block, ProfileChecks checks)
{
    const bool verifyLikelyWeights = hasFlag(checks, ProfileChecks::CHECK_LIKELY);
    const bool verifyHasLikelihood = hasFlag(checks, ProfileChecks::CHECK_HASLIKELIHOOD);

    if (!verifyLikelyWeights && !verifyHasLikelihood)
    {
        return true;
    }

    weight_t const blockWeight          = block->bbWeight;
    weight_t       incomingLikelyWeight = 0;
    unsigned       missingLikelyWeight  = 0;
    bool           foundPreds           = false;

    for (FlowEdge* const predEdge : block->PredEdges())
    {
        if (predEdge->hasLikelihood())
        {
            incomingLikelyWeight += predEdge->getLikelyWeight();
        }
        else
        {
            JITDUMP("Missing likelihood on %p " FMT_BB "->" FMT_BB "\n", predEdge, predEdge->getSourceBlock()->bbNum,
                    block->bbNum);
            missingLikelyWeight++;
        }

        foundPreds = true;
    }

    bool likelyWeightsValid = true;

    // If we have EH preds we may not have consistent incoming flow.
    //
    if (foundPreds)
    {
        if (verifyLikelyWeights)
        {
            if (!fgProfileWeightsConsistentOrSmall(blockWeight, incomingLikelyWeight))
            {
                JITDUMP("  " FMT_BB " - block weight " FMT_WT " inconsistent with incoming likely weight " FMT_WT "\n",
                        block->bbNum, blockWeight, incomingLikelyWeight);
                likelyWeightsValid = false;
            }
        }

        if (verifyHasLikelihood)
        {
            if (missingLikelyWeight > 0)
            {
                JITDUMP("  " FMT_BB " -- %u incoming edges are missing likely weights\n", block->bbNum,
                        missingLikelyWeight);
                likelyWeightsValid = false;
            }
        }
    }

    return likelyWeightsValid;
}

//------------------------------------------------------------------------
// fgDebugCheckOutgoingProfileData: verify profile data flowing out of
//   a block matches the profile weight of the block.
//
// Arguments:
//   block - block to check
//   checks - checker options
//
// Returns:
//   true if counts consistent or checking disabled, false otherwise.
//
// Notes:
//   Only useful to call on blocks with successors.
//
bool Compiler::fgDebugCheckOutgoingProfileData(BasicBlock* block, ProfileChecks checks)
{
    const bool verifyHasLikelihood = hasFlag(checks, ProfileChecks::CHECK_HASLIKELIHOOD);
    const bool verifyLikelihoodSum = hasFlag(checks, ProfileChecks::CHECK_LIKELIHOODSUM);

    if (!verifyHasLikelihood && !verifyLikelihoodSum)
    {
        return true;
    }

    bool likelyWeightsValid = true;

    // We want switch targets unified, but not EH edges.
    //
    const unsigned numSuccs = block->NumSucc();

    if ((numSuccs > 0) && !block->KindIs(BBJ_EHFAULTRET, BBJ_EHFILTERRET))
    {
        weight_t const blockWeight        = block->bbWeight;
        weight_t       outgoingLikelihood = 0;

        // Walk successor edges and add up flow counts.
        //
        unsigned missingEdges      = 0;
        unsigned missingLikelihood = 0;

        for (FlowEdge* succEdge : block->SuccEdges())
        {
            assert(succEdge != nullptr);
            BasicBlock* succBlock = succEdge->getDestinationBlock();

            if (succEdge->hasLikelihood())
            {
                outgoingLikelihood += succEdge->getLikelihood();
            }
            else
            {
                JITDUMP("Missing likelihood on %p " FMT_BB "->" FMT_BB "\n", succEdge, block->bbNum, succBlock->bbNum);
                missingLikelihood++;
            }
        }

        if (missingEdges > 0)
        {
            JITDUMP("  " FMT_BB " - missing %d successor edges\n", block->bbNum, missingEdges);
            likelyWeightsValid = false;
        }

        if (verifyHasLikelihood)
        {
            if (missingLikelihood > 0)
            {
                JITDUMP("  " FMT_BB " - missing likelihood on %d successor edges\n", block->bbNum, missingLikelihood);
                likelyWeightsValid = false;
            }
        }

        if (verifyLikelihoodSum)
        {
            if (!fgProfileWeightsConsistent(outgoingLikelihood, 1.0))
            {
                JITDUMP("  " FMT_BB " - outgoing likelihood " FMT_WT " should be 1.0\n", block->bbNum,
                        outgoingLikelihood);

                // We currently don't expect the OSR entry to have consistent outgoing likelihood,
                // since the loop it was in won't have exited enough.
                //
                if (block == fgOSREntryBB)
                {
                    JITDUMP("   ignoring this as block is the OSR entry\n");
                }
                else
                {
                    likelyWeightsValid = false;

#ifdef DEBUG
                    if (verbose)
                    {
                        for (const FlowEdge* succEdge : block->SuccEdges())
                        {
                            const BasicBlock* succBlock = succEdge->getDestinationBlock();
                            if (succEdge->hasLikelihood())
                            {
                                printf("  " FMT_BB " -> " FMT_BB ": " FMT_WT "\n", block->bbNum, succBlock->bbNum,
                                       succEdge->getLikelihood());
                            }
                            else
                            {
                                printf("  " FMT_BB " -> " FMT_BB ": no likelihood\n", block->bbNum, succBlock->bbNum);
                            }
                        }
                    }
#endif // DEBUG
                }
            }
        }
    }

    return likelyWeightsValid;
}

#endif // DEBUG

//------------------------------------------------------------------------
// fgRepairProfile: If we have PGO data and the profile is inconsistent,
//   run synthesis to re-establish consistency.
//
// Returns:
//   PhaseStatus indicating if profile synthesis ran or not.
//
PhaseStatus Compiler::fgRepairProfile()
{
    if (fgIsUsingProfileWeights())
    {
        if (fgPgoConsistent)
        {
            JITDUMP("Profile is already consistent.\n");
        }
        else
        {
            ProfileSynthesis::Run(this, ProfileSynthesisOption::RetainLikelihoods);
            return PhaseStatus::MODIFIED_EVERYTHING;
        }
    }
    else
    {
        JITDUMP("No PGO data. Skipping profile repair.\n");
    }

    return PhaseStatus::MODIFIED_NOTHING;
}

//------------------------------------------------------------------------
// fgRepairProfileCondToUncond: attempt to repair profile after modifying
//   a conditional branch to an unconditional branch.
//
// Arguments:
//   block        - block that was just altered
//   retainedEdge - flow edge that remains
//   removedEdge  - flow edge that was removed
//   metric       - [in/out, optional] metric to update if profile becomes inconsistent
//
void Compiler::fgRepairProfileCondToUncond(BasicBlock* block,
                                           FlowEdge*   retainedEdge,
                                           FlowEdge*   removedEdge,
                                           int*        metric /* = nullptr */)
{
    assert(block->KindIs(BBJ_ALWAYS));
    assert(block->GetTargetEdge() == retainedEdge);

    // If block does not have profile data, there's nothing to do.
    //
    if (!block->hasProfileWeight())
    {
        return;
    }

    // If the removed edge was not carrying away any profile, there's nothing to do.
    //
    weight_t const weight = removedEdge->getLikelyWeight();

    if (weight == BB_ZERO_WEIGHT)
    {
        return;
    }

    // If the branch was degenerate, there is nothing to do
    //
    if (retainedEdge == removedEdge)
    {
        return;
    }

    // This flow graph change will affect profile transitively, so in general
    // the profile will become inconsistent.
    //
    bool repairWasComplete  = false;
    bool missingProfileData = false;

    // Target block weight will increase.
    //
    BasicBlock* const target = block->GetTarget();

    if (target->hasProfileWeight())
    {
        target->increaseBBProfileWeight(weight);
    }
    else
    {
        missingProfileData = true;
    }

    // Alternate weight will decrease
    //
    BasicBlock* const alternate = removedEdge->getDestinationBlock();

    if (alternate->hasProfileWeight())
    {
        alternate->decreaseBBProfileWeight(weight);
    }
    else
    {
        missingProfileData = true;
    }

    // Check for the special cases where both successors are leaves,
    // or the block's postdominator is target's target (simple if/then/else/join).
    //
    // TODO: try a bit harder to find a postdominator, if it's "nearby"
    //
    if (!missingProfileData)
    {
        if ((target->NumSucc() == 0) && (alternate->NumSucc() == 0))
        {
            repairWasComplete = true;
        }
        else if (target->KindIs(BBJ_ALWAYS))
        {
            repairWasComplete = target->TargetIs(alternate->GetUniqueSucc());
        }
    }

    if (missingProfileData)
    {
        JITDUMP("Profile data could not be locally repaired. Data was missing.\n");
    }

    if (!repairWasComplete)
    {
        JITDUMP("Profile data could not be locally repaired. Data %s inconsistent.\n",
                fgPgoConsistent ? "is now" : "was already");

        if (fgPgoConsistent)
        {
            if (metric != nullptr)
            {
                *metric++;
            }
            fgPgoConsistent = false;
        }
    }
}
