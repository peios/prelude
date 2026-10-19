# Prelude Documentation Scope

The migration reviews the Learn staging tree without taking ownership of
cross-component contracts. The following source pages remain in staging:

- `peios.product/1--security-fundamentals.antho/500--boot-and-trust-establishment.topic/300--initramfs-stage.md`
  covers bootstrap tokens, image assembly, kernel modules, Prelude, and
  handoff to peinit. Its image integrity and package lifecycle discussion
  needs a shared review rather than relocation into the Prelude repository.
- `peios.product/4--developing-for-peios.antho/200--shipping-software.shelf/450--writing-boot-hooks.topic/100--writing-a-boot-hook.md`
  covers package layout, mkirf source metadata, capability vocabulary, and
  Prelude execution. It is a shared writer/reader contract.

No complete staging page found in this review is exclusively Prelude-owned.
The component-owned explanations are rewritten under `docs/learn/`:
Prelude's runtime role, recovery procedure, and bootstrap descriptor policy.
The manuals record the executable and runtime sequence interfaces. Building
and implementation details stay outside the published Learn tree.

The source code is the evidence for this rewrite, starting from Prelude
`75c909adf61c52f04efa8a23759f9e513570474a`. Existing staged security claims
about image immutability or future verification are not carried into these
pages as guarantees made by Prelude.
