/*
 * libka_re2 — multi-pattern RE2::Set matcher for Karna.
 *
 * Direction B of the perf plan (see memory karna-re2-spike): replace the
 * per-(rule x value) Lua @rx dispatch in the BENIGN no-match common case with
 * ONE C scan per request value over the WHOLE @rx set. RE2::Set compiles N
 * regexes into a single automaton and, in one linear pass over the input,
 * returns the IDs of ALL patterns that match — so the engine can answer
 * "which CRS rules could possibly match this value?" without looping the rules
 * in Lua.
 *
 * Why RE2 (not sregex / Hyperscan): RE2 honours inline (?i) and (?i:...) and
 * \b natively (CRS uses both, no PCRE-only features — verified 0/292), is
 * linear-time (no ReDoS), BSD-3, cross-compiles x86+arm64, and is production-
 * proven in OpenResty WAFs (Cloudflare). RE2::Set returns the FULL match set
 * (sregex's multi returns only the first-precedence match).
 *
 * The automaton is built once per worker at init_worker and is read-only at
 * scan time. nginx workers are single-threaded, so a per-handle scratch buffer
 * for match output is safe (FFI calls run to completion, never preempted).
 *
 * C ABI over a C++ (RE2) core — compile this .cc with g++ and link -lre2.
 */

#ifndef KA_RE2_H
#define KA_RE2_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ka_re2_t ka_re2_t;

/*
 * Create an empty pattern set.
 *   dot_nl : non-zero => '.' matches newline (RE2 set_dot_nl(true), matching
 *            Karna's ngx.re 's' flag). Karna uses "sjo" so pass 1.
 * Returns NULL on allocation failure.
 */
ka_re2_t *ka_re2_new(int dot_nl);

/*
 * Add one pattern. Pattern IDs are assigned sequentially in the order Add
 * succeeds (0, 1, 2, ...). Returns the assigned id (>= 0) on success, or -1 if
 * RE2 rejects the pattern (unsupported syntax). The caller MUST map the
 * returned id back to its rule and, on -1, fall that rule back to ngx.re.match
 * (NEVER silent-drop — that is a detection hole).
 *
 * Must be called before ka_re2_compile.
 */
int ka_re2_add(ka_re2_t *, const char *pattern, size_t pattern_len);

/*
 * Finalize the set. Must be called once after all ka_re2_add calls and before
 * any ka_re2_match. Returns 0 on success, -1 on compile failure.
 */
int ka_re2_compile(ka_re2_t *);

/*
 * Scan `text` (length `text_len`). Writes the ids of ALL patterns that match
 * anywhere in `text` into the caller-owned `out_ids` buffer (capacity
 * `max_ids` ints), ascending. Returns the TOTAL number of matches (which may
 * exceed max_ids — in that case only the first max_ids ids were written and
 * the caller should size the buffer to ka_re2_size()). Returns 0 for no match,
 * -1 on bad input / not-compiled.
 *
 * The set must have been compiled. Safe to call concurrently is NOT required
 * (single nginx worker thread); a per-handle scratch vector is reused.
 */
int ka_re2_match(ka_re2_t *, const char *text, size_t text_len,
                 int *out_ids, int max_ids);

/* Number of patterns successfully added. */
size_t ka_re2_size(const ka_re2_t *);

/* Free everything. NULL-safe. */
void ka_re2_free(ka_re2_t *);

#ifdef __cplusplus
}
#endif

#endif /* KA_RE2_H */
