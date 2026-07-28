# ART multiplatform (artmp) Windows sources

Folded from product `compat/windows/art` into this nested ART tree on
`artmp_android-16.0.0_r4`.

| Path | Role |
|------|------|
| `runtime/multiplatform/windows/*_windows.cc` | VEH/UEF, thread, monitor, sigchain spines |
| `openjdkjvm/openjdkjvm_memory_windows.cc` | JVM_* memory exports for PE Runtime natives |
| `multiplatform/windows/*_stub.*` | Build stubs (unwind/lzma/procinfo) for Windows x64 |

Product build systems should reference these paths instead of a separate
compat overlay.
