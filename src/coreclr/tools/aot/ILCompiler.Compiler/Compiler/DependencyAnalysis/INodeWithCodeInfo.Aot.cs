// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace ILCompiler.DependencyAnalysis
{
    public interface INodeWithCodeInfo
    {
        FrameInfo[] FrameInfos
        {
            get;
        }

        byte[] GCInfo
        {
            get;
        }

        DebugEHClauseInfo[] DebugEHClauseInfos
        {
            get;
        }

        MethodExceptionHandlingInfoNode EHInfo
        {
            get;
        }

        // Only used by MethodColdCodeNode; null for MethodCodeNode
        INodeWithCodeInfo HotCodeNode
        {
            get;
        }

        // Only used by MethodCodeNode with cold code; null for MethodColdCodeNode
        INodeWithCodeInfo ColdCodeNode
        {
            get;
        }

        ISymbolNode GetAssociatedDataNode(NodeFactory factory);
    }
}
