// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.ComponentModel.Composition.Hosting;
using System.ComponentModel.Composition.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Threading;
using Microsoft.Internal;
using Microsoft.Internal.Collections;

namespace System.ComponentModel.Composition
{
    // Provides helpers for creating and dealing with Exports
    internal static partial class ExportServices
    {
        private static readonly MethodInfo _createStronglyTypedLazyOfTM = typeof(ExportServices).GetMethod("CreateStronglyTypedLazyOfTM", BindingFlags.NonPublic | BindingFlags.Static)!;
        private static readonly MethodInfo _createStronglyTypedLazyOfT = typeof(ExportServices).GetMethod("CreateStronglyTypedLazyOfT", BindingFlags.NonPublic | BindingFlags.Static)!;
        private static readonly MethodInfo _createSemiStronglyTypedLazy = typeof(ExportServices).GetMethod("CreateSemiStronglyTypedLazy", BindingFlags.NonPublic | BindingFlags.Static)!;

        internal static readonly Type DefaultMetadataViewType = typeof(IDictionary<string, object>);
        internal static readonly Type DefaultExportedValueType = typeof(object);

        internal static bool IsDefaultMetadataViewType(Type metadataViewType)
        {
            ArgumentNullException.ThrowIfNull(metadataViewType);

            // Consider all types that IDictionary<string, object> derives from, such
            // as ICollection<KeyValuePair<TKey, TValue>>, IEnumerable<KeyValuePair<TKey, TValue>>
            // and IEnumerable, as default metadata view
            return metadataViewType.IsAssignableFrom(DefaultMetadataViewType);
        }

        internal static bool IsDictionaryConstructorViewType(Type metadataViewType)
        {
            ArgumentNullException.ThrowIfNull(metadataViewType);

            // Does the view type have a constructor that is a Dictionary<string, object>
            return metadataViewType.GetConstructor(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                                                    Type.DefaultBinder,
                                                    new Type[] { typeof(IDictionary<string, object>) },
                                                    Array.Empty<ParameterModifier>()) != null;
        }

        internal static Func<Export, object> CreateStronglyTypedLazyFactory(Type? exportType, Type? metadataViewType)
        {
            MethodInfo genericMethod;
            if (metadataViewType != null)
            {
                genericMethod = _createStronglyTypedLazyOfTM.MakeGenericMethod(exportType ?? ExportServices.DefaultExportedValueType, metadataViewType);
            }
            else
            {
                genericMethod = _createStronglyTypedLazyOfT.MakeGenericMethod(exportType ?? ExportServices.DefaultExportedValueType);
            }

            ArgumentNullException.ThrowIfNull(genericMethod);

            return (Func<Export, object>)Delegate.CreateDelegate(typeof(Func<Export, object>), genericMethod);
        }

        internal static Func<Export, Lazy<object, object>> CreateSemiStronglyTypedLazyFactory(Type? exportType, Type? metadataViewType)
        {
            MethodInfo genericMethod = _createSemiStronglyTypedLazy.MakeGenericMethod(
                exportType ?? ExportServices.DefaultExportedValueType,
                metadataViewType ?? ExportServices.DefaultMetadataViewType);
            ArgumentNullException.ThrowIfNull(genericMethod);
            return (Func<Export, Lazy<object, object>>)Delegate.CreateDelegate(typeof(Func<Export, Lazy<object, object>>), genericMethod);
        }

        internal static Lazy<T, M> CreateStronglyTypedLazyOfTM<T, M>(Export export)
        {
            if (export is IDisposable disposable)
            {
                return new DisposableLazy<T, M>(
                    () => ExportServices.GetCastedExportedValue<T>(export),
                    AttributedModelServices.GetMetadataView<M>(export.Metadata),
                    disposable,
                    LazyThreadSafetyMode.PublicationOnly);
            }
            else
            {
                return new Lazy<T, M>(
                    () => ExportServices.GetCastedExportedValue<T>(export),
                    AttributedModelServices.GetMetadataView<M>(export.Metadata),
                    LazyThreadSafetyMode.PublicationOnly);
            }
        }

        internal static Lazy<T> CreateStronglyTypedLazyOfT<T>(Export export)
        {
            if (export is IDisposable disposable)
            {
                return new DisposableLazy<T>(
                    () => ExportServices.GetCastedExportedValue<T>(export),
                    disposable,
                    LazyThreadSafetyMode.PublicationOnly);
            }
            else
            {
                return new Lazy<T>(() => ExportServices.GetCastedExportedValue<T>(export), LazyThreadSafetyMode.PublicationOnly);
            }
        }

        internal static Lazy<object?, object> CreateSemiStronglyTypedLazy<T, M>(Export export)
        {
            if (export is IDisposable disposable)
            {
                return new DisposableLazy<object?, object>(
                    () => ExportServices.GetCastedExportedValue<T>(export),
                    AttributedModelServices.GetMetadataView<M>(export.Metadata)!,
                    disposable,
                    LazyThreadSafetyMode.PublicationOnly);
            }
            else
            {
                return new Lazy<object?, object>(
                    () => ExportServices.GetCastedExportedValue<T>(export),
                    AttributedModelServices.GetMetadataView<M>(export.Metadata)!,
                    LazyThreadSafetyMode.PublicationOnly);
            }
        }

        internal static T GetCastedExportedValue<T>(Export export)
        {
            return CastExportedValue<T>(export.ToElement(), export.Value);
        }

        internal static T CastExportedValue<T>(ICompositionElement element, object? exportedValue)
        {
            bool succeeded = ContractServices.TryCast(typeof(T), exportedValue, out object? typedExportedValue);
            if (!succeeded)
            {
                throw new CompositionContractMismatchException(SR.Format(
                    SR.ContractMismatch_ExportedValueCannotBeCastToT,
                    element.DisplayName,
                    typeof(T)));
            }

            return (T)typedExportedValue!;
        }

        internal static ExportCardinalityCheckResult CheckCardinality<T>(ImportDefinition definition, IEnumerable<T>? enumerable)
        {
            EnumerableCardinality actualCardinality = (enumerable != null) ? enumerable.GetCardinality() : EnumerableCardinality.Zero;

            return MatchCardinality(actualCardinality, definition.Cardinality);
        }

        private static ExportCardinalityCheckResult MatchCardinality(EnumerableCardinality actualCardinality, ImportCardinality importCardinality)
        {
            switch (actualCardinality)
            {
                case EnumerableCardinality.Zero:
                    if (importCardinality == ImportCardinality.ExactlyOne)
                    {
                        return ExportCardinalityCheckResult.NoExports;
                    }
                    break;

                case EnumerableCardinality.TwoOrMore:
                    if (importCardinality.IsAtMostOne())
                    {
                        return ExportCardinalityCheckResult.TooManyExports;
                    }
                    break;

                default:
                    if (actualCardinality != EnumerableCardinality.One)
                    {
                        throw new Exception(SR.Diagnostic_InternalExceptionMessage);
                    }
                    break;

            }

            return ExportCardinalityCheckResult.Match;
        }
    }
}
