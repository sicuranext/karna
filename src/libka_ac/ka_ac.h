/*
 * libka_ac — Aho-Corasick multi-pattern prefilter for Karna.
 *
 * Built once at init_worker from the set of literal substrings extracted from
 * CRS @rx rules, then queried per request value to obtain the bitmap of
 * patterns that COULD potentially match — so the engine can skip the full
 * regex on rules whose required literal is not in the input.
 *
 * Case-insensitive ASCII (matches case-folded byte for byte). Inputs above the
 * ASCII range are passed through unchanged (UTF-8 multi-byte sequences become
 * arbitrary bytes for matching — the same semantics CRS effectively uses).
 *
 * The automaton is built once and is read-only at scan time — safe for
 * concurrent scans from a single Lua worker.
 */

#ifndef KA_AC_H
#define KA_AC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ka_ac_t ka_ac_t;

/*
 * Build an automaton from `n_patterns` strings. Pattern i has bytes
 * patterns[i] of length pattern_lens[i]. Pattern IDs are assigned in input
 * order (0 .. n_patterns-1). Duplicates are allowed but waste memory — caller
 * should dedupe.
 *
 * Patterns of length 0 are rejected (return NULL).
 *
 * Returns NULL on allocation failure or bad input.
 */
ka_ac_t* ka_ac_build(const char** patterns, const size_t* pattern_lens, size_t n_patterns);

/* Free everything. NULL-safe. */
void ka_ac_free(ka_ac_t*);

/*
 * Scan `text` (length `text_len`) case-insensitively. For every pattern p
 * that occurs anywhere in `text`, set bit p of `out_bitmap`:
 *     out_bitmap[p >> 3] |= (1u << (p & 7));
 * Bits for non-matching patterns are LEFT UNTOUCHED — caller MUST zero
 * `out_bitmap` before calling. Buffer must be at least (n_patterns+7)/8
 * bytes.
 *
 * Returns 0 on success, -1 on bad input.
 */
int ka_ac_scan(const ka_ac_t*, const char* text, size_t text_len, uint8_t* out_bitmap);

/*
 * Returns 1 if ANY pattern occurs anywhere in `text` (case-insensitive),
 * 0 if none, -1 on bad input. Early-exits on the first match and needs no
 * bitmap — the boolean form used to replace the Lua @pm / @pmFromFile loops
 * (one linear pass instead of N substring searches).
 */
int ka_ac_match_any(const ka_ac_t*, const char* text, size_t text_len);

/* Number of patterns the automaton was built with. */
size_t ka_ac_n_patterns(const ka_ac_t*);

/* Memory used by the trie (informational, in bytes). */
size_t ka_ac_memory_bytes(const ka_ac_t*);

#ifdef __cplusplus
}
#endif

#endif /* KA_AC_H */
