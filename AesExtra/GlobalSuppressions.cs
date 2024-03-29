﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Security", "CA5358:Review cipher mode usage with cryptography experts", Justification = "Done :)")]
[assembly: SuppressMessage("Security", "CA5401:Do not use CreateEncryptor with non-default IV", Justification = "We only use ECB, which does not use an IV")] // DevSkim: ignore DS187371
