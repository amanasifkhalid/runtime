// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Reflection;

namespace System.Composition.Diagnostics
{
    internal static class CompositionTrace
    {
        public static void Registration_ConstructorConventionOverridden(Type type)
        {
            if (type == null)
                throw new Exception(SR.Diagnostic_InternalExceptionMessage);

            if (CompositionTraceSource.CanWriteInformation)
            {
                CompositionTraceSource.WriteInformation(CompositionTraceId.Registration_ConstructorConventionOverridden,
                    SR.Registration_ConstructorConventionOverridden,
                    type.FullName);
            }
        }

        public static void Registration_TypeExportConventionOverridden(Type type)
        {
            if (type == null)
                throw new Exception(SR.Diagnostic_InternalExceptionMessage);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_TypeExportConventionOverridden,
                    SR.Registration_TypeExportConventionOverridden,
                    type.FullName);
            }
        }

        public static void Registration_MemberExportConventionOverridden(Type type, MemberInfo member)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(member);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_MemberExportConventionOverridden,
                    SR.Registration_MemberExportConventionOverridden,
                    member.Name, type.FullName);
            }
        }

        public static void Registration_MemberImportConventionOverridden(Type type, MemberInfo member)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(member);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_MemberImportConventionOverridden,
                    SR.Registration_MemberImportConventionOverridden,
                    member.Name, type.FullName);
            }
        }

        public static void Registration_OnSatisfiedImportNotificationOverridden(Type type, MemberInfo member)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(member);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_OnSatisfiedImportNotificationOverridden,
                    SR.Registration_OnSatisfiedImportNotificationOverridden,
                    member.Name, type.FullName);
            }
        }

        public static void Registration_PartCreationConventionOverridden(Type type)
        {
            ArgumentNullException.ThrowIfNull(type);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_PartCreationConventionOverridden,
                    SR.Registration_PartCreationConventionOverridden,
                    type.FullName);
            }
        }

        public static void Registration_MemberImportConventionMatchedTwice(Type type, MemberInfo member)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(member);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_MemberImportConventionMatchedTwice,
                    SR.Registration_MemberImportConventionMatchedTwice,
                    member.Name, type.FullName);
            }
        }

        public static void Registration_PartMetadataConventionOverridden(Type type)
        {
            ArgumentNullException.ThrowIfNull(type);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_PartMetadataConventionOverridden,
                    SR.Registration_PartMetadataConventionOverridden,
                    type.FullName);
            }
        }

        public static void Registration_ParameterImportConventionOverridden(ParameterInfo parameter, ConstructorInfo constructor)
        {
            ArgumentNullException.ThrowIfNull(parameter);
            ArgumentNullException.ThrowIfNull(constructor);

            if (CompositionTraceSource.CanWriteWarning)
            {
                CompositionTraceSource.WriteWarning(CompositionTraceId.Registration_ParameterImportConventionOverridden,
                    SR.Registration_ParameterImportConventionOverridden,
                    parameter.Name, constructor.Name);
            }
        }
    }
}
