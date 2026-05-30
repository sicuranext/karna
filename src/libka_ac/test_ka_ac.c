/*
 * Standalone smoke test for libka_ac. Run with:
 *   cd src/libka_ac && gcc -O2 -Wall -o test ka_ac.c test_ka_ac.c && ./test
 *
 * Verifies: simple matches, overlapping matches, case-insensitive matching,
 * suffix matches via the output function, no false positives, empty bitmap
 * for non-matching input, large input correctness.
 */
#include "ka_ac.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bit_test(const uint8_t* bm, size_t pid) {
    return (bm[pid >> 3] >> (pid & 7)) & 1u;
}

static int test_basic(void) {
    const char* pats[] = {"foo", "bar", "baz"};
    const size_t lens[] = {3, 3, 3};
    ka_ac_t* ac = ka_ac_build(pats, lens, 3);
    assert(ac);

    uint8_t bm[1] = {0};
    assert(ka_ac_scan(ac, "hello foo world", 15, bm) == 0);
    assert(bit_test(bm, 0));   /* foo */
    assert(!bit_test(bm, 1));  /* bar */
    assert(!bit_test(bm, 2));  /* baz */

    memset(bm, 0, sizeof(bm));
    assert(ka_ac_scan(ac, "barbaz foo", 10, bm) == 0);
    assert(bit_test(bm, 0) && bit_test(bm, 1) && bit_test(bm, 2));

    memset(bm, 0, sizeof(bm));
    assert(ka_ac_scan(ac, "nothing here", 12, bm) == 0);
    assert(!bit_test(bm, 0) && !bit_test(bm, 1) && !bit_test(bm, 2));

    ka_ac_free(ac);
    printf("test_basic: OK\n");
    return 0;
}

static int test_case_insensitive(void) {
    const char* pats[] = {"union", "select"};
    const size_t lens[] = {5, 6};
    ka_ac_t* ac = ka_ac_build(pats, lens, 2);
    assert(ac);

    uint8_t bm[1] = {0};
    assert(ka_ac_scan(ac, "1 UNION SELECT password FROM users", 34, bm) == 0);
    assert(bit_test(bm, 0));  /* union */
    assert(bit_test(bm, 1));  /* select */

    memset(bm, 0, sizeof(bm));
    assert(ka_ac_scan(ac, "UnIoN sElEcT", 12, bm) == 0);
    assert(bit_test(bm, 0) && bit_test(bm, 1));

    ka_ac_free(ac);
    printf("test_case_insensitive: OK\n");
    return 0;
}

static int test_overlapping_via_output_function(void) {
    /* "she" suffix of "ushers". Classic Aho-Corasick example. */
    const char* pats[] = {"he", "she", "his", "hers"};
    const size_t lens[] = {2, 3, 3, 4};
    ka_ac_t* ac = ka_ac_build(pats, lens, 4);
    assert(ac);

    uint8_t bm[1] = {0};
    assert(ka_ac_scan(ac, "ushers", 6, bm) == 0);
    /* "ushers" contains "she", "he", "hers" — not "his". */
    assert(bit_test(bm, 0));   /* he */
    assert(bit_test(bm, 1));   /* she */
    assert(!bit_test(bm, 2));  /* his */
    assert(bit_test(bm, 3));   /* hers */

    ka_ac_free(ac);
    printf("test_overlapping_via_output_function: OK\n");
    return 0;
}

static int test_large_pattern_set(void) {
    /* 200 patterns of the shape "tok_NNN" — verify all match when present. */
    enum { N = 200 };
    char* pats[N];
    size_t lens[N];
    for (int i = 0; i < N; i++) {
        char buf[16];
        int n = snprintf(buf, sizeof(buf), "tok_%d", i);
        pats[i] = strdup(buf);
        lens[i] = (size_t)n;
    }
    ka_ac_t* ac = ka_ac_build((const char**)pats, lens, N);
    assert(ac);

    /* Build an input that contains every pattern. */
    size_t total = 0;
    for (int i = 0; i < N; i++) total += lens[i] + 1;  /* +1 separator */
    char* input = (char*)malloc(total + 1);
    size_t off = 0;
    for (int i = 0; i < N; i++) {
        memcpy(input + off, pats[i], lens[i]);
        off += lens[i];
        input[off++] = ' ';
    }

    uint8_t bm[(N + 7) / 8] = {0};
    assert(ka_ac_scan(ac, input, off, bm) == 0);
    for (int i = 0; i < N; i++) {
        if (!bit_test(bm, (size_t)i)) {
            printf("MISSING pattern %d (%s)\n", i, pats[i]);
            assert(0);
        }
    }

    /* And non-matching input should yield empty bitmap. */
    memset(bm, 0, sizeof(bm));
    assert(ka_ac_scan(ac, "xxxxxxxxxxxx", 12, bm) == 0);
    for (int i = 0; i < N; i++) assert(!bit_test(bm, (size_t)i));

    free(input);
    for (int i = 0; i < N; i++) free(pats[i]);
    ka_ac_free(ac);
    printf("test_large_pattern_set: OK (%d patterns)\n", N);
    return 0;
}

static int test_n_patterns_and_memory(void) {
    const char* pats[] = {"a", "b"};
    const size_t lens[] = {1, 1};
    ka_ac_t* ac = ka_ac_build(pats, lens, 2);
    assert(ka_ac_n_patterns(ac) == 2);
    assert(ka_ac_memory_bytes(ac) > 0);
    ka_ac_free(ac);
    printf("test_n_patterns_and_memory: OK\n");
    return 0;
}

static int test_bad_input(void) {
    const char* pats[] = {""};
    const size_t lens[] = {0};
    /* Empty pattern → reject. */
    assert(ka_ac_build(pats, lens, 1) == NULL);

    /* NULL args → reject. */
    assert(ka_ac_build(NULL, lens, 1) == NULL);

    /* NULL bitmap → scan returns -1. */
    const char* p[] = {"x"};
    const size_t l[] = {1};
    ka_ac_t* ac = ka_ac_build(p, l, 1);
    assert(ka_ac_scan(ac, "abc", 3, NULL) == -1);
    ka_ac_free(ac);

    printf("test_bad_input: OK\n");
    return 0;
}

int main(void) {
    test_basic();
    test_case_insensitive();
    test_overlapping_via_output_function();
    test_large_pattern_set();
    test_n_patterns_and_memory();
    test_bad_input();
    printf("\nALL TESTS PASSED\n");
    return 0;
}
