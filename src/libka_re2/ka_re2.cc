/*
 * libka_re2 — RE2::Set multi-pattern matcher for Karna. See ka_re2.h.
 *
 * Build (mirrors the libinjection .so build in docker/kong/Dockerfile):
 *   g++ -shared -fPIC -O2 -std=c++17 -o /usr/local/lib/libka_re2.so \
 *       src/libka_re2/ka_re2.cc -lre2
 * Requires libre2-dev at build time and libre2 at runtime (one apt line).
 */

#include "ka_re2.h"

#include <re2/re2.h>
#include <re2/set.h>

#include <string>
#include <vector>

struct ka_re2_t {
    RE2::Set    *set;
    size_t       n;
    std::vector<int> scratch;   // reused match output (single-threaded worker)
};

extern "C" {

ka_re2_t *ka_re2_new(int dot_nl)
{
    RE2::Options opt;
    opt.set_log_errors(false);     // don't spew to stderr on a bad pattern
    opt.set_dot_nl(dot_nl != 0);   // 's' flag parity with Karna's ngx.re "sjo"
    opt.set_never_capture(true);   // Set membership only — no captures needed
    // BYTE mode parity with PCRE/ngx.re. Karna's ngx.re.match runs without the
    // 'u' flag => operates on raw bytes. RE2 defaults to UTF-8, where MALFORMED
    // byte sequences (e.g. CRS 941310's US-ASCII evasion \xbc\xbe...) match
    // differently than PCRE byte-mode — which silently broke detection once
    // body values were gated. Latin1 treats each byte as its own char = PCRE
    // byte semantics. (Validated by the CRS regression empty-diff.)
    opt.set_encoding(RE2::Options::EncodingLatin1);
    // RE2::Set::Compile() fails if the combined program exceeds max_mem
    // (default 8 MB). A CRS @rx set is ~150-200 patterns, some large, so bump
    // the budget generously (well under the 2 GB worker cap).
    opt.set_max_mem(static_cast<int64_t>(256) << 20);  // 256 MB

    ka_re2_t *h = nullptr;
    try {
        h = new ka_re2_t();
        h->set = new RE2::Set(opt, RE2::UNANCHORED);  // match anywhere, like ngx.re.match
        h->n   = 0;
    } catch (...) {
        if (h) { delete h->set; delete h; }
        return nullptr;
    }
    return h;
}

int ka_re2_add(ka_re2_t *h, const char *pattern, size_t pattern_len)
{
    if (h == nullptr || h->set == nullptr || pattern == nullptr) {
        return -1;
    }
    re2::StringPiece sp(pattern, pattern_len);
    std::string err;
    // RE2::Set::Add returns the index assigned to this pattern, or -1 if the
    // pattern fails to parse/compile.
    int idx = h->set->Add(sp, &err);
    if (idx >= 0) {
        h->n = static_cast<size_t>(idx) + 1;
    }
    return idx;
}

int ka_re2_compile(ka_re2_t *h)
{
    if (h == nullptr || h->set == nullptr) {
        return -1;
    }
    return h->set->Compile() ? 0 : -1;
}

int ka_re2_match(ka_re2_t *h, const char *text, size_t text_len,
                 int *out_ids, int max_ids)
{
    if (h == nullptr || h->set == nullptr || text == nullptr) {
        return -1;
    }
    re2::StringPiece sp(text, text_len);
    h->scratch.clear();
    if (!h->set->Match(sp, &h->scratch)) {
        return 0;
    }
    int total = static_cast<int>(h->scratch.size());
    if (out_ids != nullptr && max_ids > 0) {
        int n = total < max_ids ? total : max_ids;
        for (int i = 0; i < n; i++) {
            out_ids[i] = h->scratch[static_cast<size_t>(i)];
        }
    }
    return total;
}

size_t ka_re2_size(const ka_re2_t *h)
{
    return h ? h->n : 0;
}

void ka_re2_free(ka_re2_t *h)
{
    if (h == nullptr) {
        return;
    }
    delete h->set;
    delete h;
}

} /* extern "C" */
