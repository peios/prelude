---
title: Bootstrap Descriptors
type: concept
description: Why seed-sd uses a narrow initial access policy and why
  runtime trees can need a different descriptor.
---

A newly mounted filesystem needs access control before boot tools can use
it. The `seed-sd` helper establishes that initial security descriptor. Its
bootstrap policy gives SYSTEM and Administrators full access and adds an
inherit-only rule for the creator of each new object.

## A template reaches later objects

Inheritance applies the directory's template when a child is created.
Changing the directory later does not rewrite every existing child.
Prelude therefore calls `seed-sd` recursively on `/dev`, covering the nodes
already present as well as the directory that supplies later inheritance.

The walker writes a node's descriptor before inspecting its descendants.
That order allows it to enter a directory whose missing descriptor would
otherwise deny access. Symlinks receive their own descriptor; the walker
does not follow their targets.

## Bootstrap policy has a limited purpose

The default is suitable for making a fresh tree administrable. It is not a
complete access policy for a running system. Granting Everyone read access
at the device root would also reach newly created raw disk nodes, where
reading the disk can bypass file-level access control.

A caller that prepares a different tree can supply an explicit descriptor
with `seed-sd --sddl`. That caller owns the broader policy and its scope.
The command's options, required privileges, and exit statuses are recorded
in `seed-sd(8)`.

## Partial failure is visible

Recursive seeding continues after errors where traversal remains possible.
It reports failures and returns an unsuccessful status, but it does not
undo descriptors already written. An installer or hook must use that
status when deciding whether its own work succeeded.

The helper rejects command-line arguments containing invalid UTF-8 before
applying any descriptor. During a recursive walk, a descendant name that
cannot be represented as UTF-8 is reported as a failure and skipped.
