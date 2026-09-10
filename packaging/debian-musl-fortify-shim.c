/*
 * Debian builds its LLVM libunwind archive with glibc's fortified stdio
 * entry points.  The archive is otherwise libc-agnostic, so the Debian
 * reference build supplies the two ABI-compatible wrappers below when
 * linking it against musl.  They are not used by the native Peios build,
 * whose packaged Rust target carries its own musl-built unwind runtime.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list args) {
    (void)flag;
    return vfprintf(stream, format, args);
}

int __vsnprintf_chk(char *buffer, size_t length, int flag, size_t object_size,
                    const char *format, va_list args) {
    (void)flag;
    if (length > object_size) {
        length = object_size;
    }
    return vsnprintf(buffer, length, format, args);
}
