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

        // List of (hot MethodIndex, number of cold FrameInfos)
        // Once we know the total number of hot runtime functions, we can use
        // each cold runtime function's size (in FrameInfos) to calculate its MethodIndex
        private List<Tuple<uint, uint>> _mapping = new List<Tuple<uint, uint>>();

        public uint NumHotRuntimeFunctions { get; set; }

        public override int ClassCode => 28963035;

        public int Offset => 0;

        public override bool IsShareable => false;

        public override ObjectNodeSection GetSection(NodeFactory factory) => ObjectNodeSection.DataSection;

        public override bool StaticDependenciesAreComputed => true;

        protected override string GetName(NodeFactory factory) => this.GetMangledName(factory.NameMangler);

        public void AppendMangledName(NameMangler nameMangler, Utf8StringBuilder sb)
        {
            sb.Append(nameMangler.CompilationUnitPrefix);
            sb.Append("__HotColdMap");
        }

        public void Add(uint hotMethodIndex, uint numColdFrameInfos)
        {
            _mapping.Add(Tuple.Create(hotMethodIndex, numColdFrameInfos));
        }

        public override ObjectData GetData(NodeFactory factory, bool relocsOnly = false)
        {
            // This node does not trigger generation of other nodes.
            if (relocsOnly)
                return new ObjectData(Array.Empty<byte>(), Array.Empty<Relocation>(), 1, new ISymbolDefinitionNode[] { this });

            ObjectDataBuilder builder = new ObjectDataBuilder(factory, relocsOnly);
            builder.AddSymbol(this);

            uint nextColdMethodIndex = NumHotRuntimeFunctions;
            foreach (var pair in _mapping)
            {
                // Mapping: cold MethodIndex, followed by hot MethodIndex
                builder.EmitUInt(nextColdMethodIndex);
                builder.EmitUInt(pair.Item1);
                nextColdMethodIndex += pair.Item2;
            }

            _size = builder.CountBytes;
            return builder.ToObjectData();
        }
    }
}
