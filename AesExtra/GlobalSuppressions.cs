// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Security", "CA5358:Review cipher mode usage with cryptography experts", Justification = "Done :)")]
[assembly: SuppressMessage("Security", "CA5401:Do not use CreateEncryptor with non-default IV", Justification = "We only use ECB, which does not use an IV")] // DevSkim: ignore DS187371
[assembly: SuppressMessage("Maintainability", "CA1512:Use ArgumentOutOfRangeException throw helper", Justification = "Not available in netstandard2.0.")]
[assembly: SuppressMessage("Maintainability", "CA1513:Use ObjectDisposedException throw helper", Justification = "Not available in netstandard2.0.")]
[assembly: SuppressMessage("Maintainability", "CA1510:Use ArgumentNullException throw helper", Justification = "Not available in netstandard2.0.")]
[assembly: SuppressMessage("Performance", "CA1835:Prefer the 'Memory'-based overloads for 'ReadAsync' and 'WriteAsync'", Justification = "Not available in netstandard2.0.")]
