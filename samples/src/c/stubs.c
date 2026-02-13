#include "polyfill.h"

/*
 * Why this file exists:
 * - Sample C files in this tree are decompiler-style artifacts and can reference
 *   external symbols that do not exist in our standalone sample build
 *   environment.
 * - This .c file provides one link-time location for placeholder definitions so
 *   `make` can produce sample binaries without pulling in real platform SDK
 *   implementations.
 *
 * Why this must remain a .c file (not header-only inline stubs):
 * - Header-defined bodies can create duplicate definitions or per-translation
 *   unit static copies, which is not what we want for unresolved externs.
 * - The build expects globally linkable symbols that satisfy references across
 *   all sample objects.
 *
 * Scope:
 * - Stubs are compile/link placeholders only; they are intentionally minimal
 *   and not expected to be runtime-correct implementations.
 *
 * When adding new stubs:
 * - Add here when a new sample introduces unresolved externals at link time
 *   (e.g., LNK2019/undefined reference).
 * - Keep implementations as no-op or deterministic constant-return helpers.
 * - Add a short comment near the new stub with the source sample/reason.
 */

/* Stub definitions for undefined external symbols */
int get_external_value(void) { return 0; }
void external_side_effect(int x) { (void)x; }
int external_transform(int x) { return x; }
void printf2(const char *fmt, ...) { (void)fmt; }
int lolclose(unsigned __int64 hObject) { (void)hObject; return 0; }
void unk_1802CCC58(int x) { (void)x; }
void sub_1800D3BF0(int a1, int a2, int a3, int a4, __int64 a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; }
void sub_180221640(unsigned __int64 a1, int a2, int a3, unsigned __int64 a4, int a5, int a6) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; }

/* Stubs for approov_flattened.c */
void sub_D28B(void) { }
void sub_216C8(void) { }
void sub_258F0(void) { }
void sub_26A5ae(void) { }
