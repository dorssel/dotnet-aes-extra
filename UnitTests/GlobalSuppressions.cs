﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Security", "CA5358:Review cipher mode usage with cryptography experts", Justification = "Done :)")]
[assembly: SuppressMessage("Security", "CA5401:Symmetric encryption uses non-default initialization vector, which could be potentially repeatable",
    Justification = "Required for Known-Answer-Tests (KAT)")]
[assembly: SuppressMessage("Performance", "CA1812:Internal class is never instantiated", Justification = "We use internal test classes")]
[assembly: SuppressMessage("Style", "IDE0053:Use expression body for lambda expression", Justification = "Better readability for Assert.ThrowsException")]
[assembly: SuppressMessage("Style", "IDE0058:Expression value is never used", Justification = "Not useful for tests")]
[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "Not required for tests.")]
