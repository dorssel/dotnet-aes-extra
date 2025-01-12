// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Performance", "CA1812:Internal class is never instantiated", Justification = "We use internal test classes")]
[assembly: SuppressMessage("Style", "IDE0058:Expression value is never used", Justification = "Not useful for tests")]
