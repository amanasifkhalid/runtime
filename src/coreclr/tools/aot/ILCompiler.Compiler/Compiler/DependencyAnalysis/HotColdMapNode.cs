// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;

using Internal.Text;

namespace ILCompiler.DependencyAnalysis
{
    public class HotColdMapNode : ObjectNode, ISymbolDefinitionNode, INodeWithSize
    {
        private int? _size;
        int INodeWithSize.Size => _size.Value;

        private List<INodeWithCodeInfo> _mapping = new List<INodeWithCodeInfo>();

        // ClassCode is one greater than MethodColdCodeNode, to guarantee all code nodes are emitted
        // before HotColdMap is generated.
        public override int ClassCode => 788492409;

        public int Offset => 0;

        public override bool IsShareable => false;

        public override ObjectNodeSection GetSection(NodeFactory factory) => ObjectNodeSection.DataSection;

        public override bool StaticDependenciesAreComputed => true;

        protected override string GetName(NodeFactory factory) => this.GetMangledName(factory.NameMangler);

        public void AddEntry(INodeWithCodeInfo coldCodeNode)
        {
            Debug.Assert(coldCodeNode.HotCodeNode != null);
            _mapping.Add(coldCodeNode);
        }

        public void AppendMangledName(NameMangler nameMangler, Utf8StringBuilder sb)
        {
            sb.Append(nameMangler.CompilationUnitPrefix);
            sb.Append("__HotColdMap");
        }

        public override ObjectData GetData(NodeFactory factory, bool relocsOnly = false)
        {
            // This node does not trigger generation of other nodes.
            if (relocsOnly)
                return new ObjectData(Array.Empty<byte>(), Array.Empty<Relocation>(), 1, new ISymbolDefinitionNode[] { this });

            ObjectDataBuilder builder = new ObjectDataBuilder(factory, relocsOnly);
            builder.AddSymbol(this);

            foreach (INodeWithCodeInfo coldCodeNode in _mapping)
            {
                builder.EmitReloc(
                    (ISymbolNode)coldCodeNode, RelocType.IMAGE_REL_BASED_ABSOLUTE, delta: factory.Target.CodeDelta);
                builder.EmitReloc(
                    (ISymbolNode)coldCodeNode.HotCodeNode, RelocType.IMAGE_REL_BASED_ABSOLUTE, delta: factory.Target.CodeDelta);
            }

            _size = builder.CountBytes;
            return builder.ToObjectData();
        }
    }
}
