#include "polyfill.h"

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

