/*
 * libka_ac — Aho-Corasick multi-pattern prefilter for Karna. See ka_ac.h.
 *
 * Implementation notes
 * --------------------
 * Standard goto / failure / output Aho-Corasick. The goto table is
 * "completed" during BFS so each state has a transition for every byte
 * (either to a real child, or via the failure chain back toward root, or
 * staying at root) — this makes the scan loop branchless on the hot path:
 *
 *     state = nodes[state].go[c];
 *     for each pid in nodes[state].matches: set bit in bitmap;
 *
 * Each node carries the FULL set of pattern IDs that match here OR at any
 * suffix of the path (the standard "output function" merged into the node's
 * match list during BFS). So a single state visit emits every pattern that
 * ends at any reachable suffix — no failure-chain walk at scan time.
 *
 * Memory layout: 256 int32 per node (1024 bytes) + match list pointer +
 * counts. For ~500-2000 literals from CRS, total node count is typically
 * <20k, so ~20 MB per worker. That's per-worker (each Lua VM builds its
 * own automaton). Acceptable for a benchmark/production deployment.
 */

#include "ka_ac.h"
#include <stdlib.h>
#include <string.h>

/* ASCII lower-case (no locale, no UTF-8 awareness — bytes above 0x7F pass through). */
static inline unsigned char ac_tolower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20) : c;
}

typedef struct {
    int32_t  go[256];           /* completed goto table — never -1 after build */
    int32_t  fail;               /* failure link */
    uint32_t n_matches;
    uint32_t cap_matches;
    uint32_t* matches;           /* pattern IDs ending at or via suffix of this state */
} ka_node;

struct ka_ac_t {
    ka_node*  nodes;
    size_t    n_nodes;
    size_t    cap_nodes;
    size_t    n_patterns;
};

/* Append pattern id `pid` to node `n`'s match list, growing if needed. */
static int node_add_match(ka_node* n, uint32_t pid) {
    if (n->n_matches == n->cap_matches) {
        size_t new_cap = n->cap_matches ? (size_t)n->cap_matches * 2 : 4;
        uint32_t* arr = (uint32_t*)realloc(n->matches, new_cap * sizeof(uint32_t));
        if (!arr) return -1;
        n->matches = arr;
        n->cap_matches = (uint32_t)new_cap;
    }
    n->matches[n->n_matches++] = pid;
    return 0;
}

/* Allocate a fresh node, return its index or -1 on OOM. */
static int32_t alloc_node(ka_ac_t* ac) {
    if (ac->n_nodes == ac->cap_nodes) {
        size_t new_cap = ac->cap_nodes ? ac->cap_nodes * 2 : 64;
        ka_node* arr = (ka_node*)realloc(ac->nodes, new_cap * sizeof(ka_node));
        if (!arr) return -1;
        ac->nodes = arr;
        ac->cap_nodes = new_cap;
    }
    ka_node* n = &ac->nodes[ac->n_nodes];
    /* Pre-build: -1 = no transition. BFS will overwrite all -1 with completed transitions. */
    for (int i = 0; i < 256; i++) n->go[i] = -1;
    n->fail = 0;
    n->n_matches = 0;
    n->cap_matches = 0;
    n->matches = NULL;
    return (int32_t)ac->n_nodes++;
}

ka_ac_t* ka_ac_build(const char** patterns, const size_t* pattern_lens, size_t n_patterns) {
    if (!patterns || !pattern_lens) return NULL;
    for (size_t i = 0; i < n_patterns; i++) {
        if (!patterns[i] || pattern_lens[i] == 0) return NULL;  /* empty patterns disallowed */
    }

    ka_ac_t* ac = (ka_ac_t*)calloc(1, sizeof(ka_ac_t));
    if (!ac) return NULL;
    ac->n_patterns = n_patterns;

    /* Root = node 0. */
    if (alloc_node(ac) < 0) goto fail;

    /* Insert each pattern into the trie. */
    for (size_t p = 0; p < n_patterns; p++) {
        int32_t state = 0;
        const char* pat = patterns[p];
        size_t len = pattern_lens[p];
        for (size_t i = 0; i < len; i++) {
            unsigned char c = ac_tolower((unsigned char)pat[i]);
            if (ac->nodes[state].go[c] == -1) {
                int32_t nn = alloc_node(ac);
                if (nn < 0) goto fail;
                ac->nodes[state].go[c] = nn;
            }
            state = ac->nodes[state].go[c];
        }
        if (node_add_match(&ac->nodes[state], (uint32_t)p) < 0) goto fail;
    }

    /* BFS to compute failure links + complete the goto table. */
    int32_t* queue = (int32_t*)malloc(ac->n_nodes * sizeof(int32_t));
    if (!queue) goto fail;
    size_t qhead = 0, qtail = 0;

    /* Root's children fail to root; missing transitions at root loop to root. */
    for (int c = 0; c < 256; c++) {
        int32_t child = ac->nodes[0].go[c];
        if (child != -1) {
            ac->nodes[child].fail = 0;
            queue[qtail++] = child;
        } else {
            ac->nodes[0].go[c] = 0;  /* stay at root */
        }
    }

    /* Process the rest of the trie in BFS order so each fail link is computed
     * after its target (smaller depth) has been completed. */
    while (qhead < qtail) {
        int32_t u = queue[qhead++];
        int32_t fail_u = ac->nodes[u].fail;
        for (int c = 0; c < 256; c++) {
            int32_t v = ac->nodes[u].go[c];
            if (v == -1) {
                /* Missing transition: redirect to where fail_u would go. The
                 * goto table at fail_u is already completed (BFS order). */
                ac->nodes[u].go[c] = ac->nodes[fail_u].go[c];
            } else {
                /* Real child: its fail is fail_u's transition on c. */
                ac->nodes[v].fail = ac->nodes[fail_u].go[c];
                /* Merge fail-target's matches into v (output function). */
                int32_t fv = ac->nodes[v].fail;
                if (fv != 0) {  /* skip merging from root (no matches) */
                    uint32_t n_fv = ac->nodes[fv].n_matches;
                    for (uint32_t i = 0; i < n_fv; i++) {
                        if (node_add_match(&ac->nodes[v], ac->nodes[fv].matches[i]) < 0) {
                            free(queue);
                            goto fail;
                        }
                    }
                }
                queue[qtail++] = v;
            }
        }
    }
    free(queue);
    return ac;

fail:
    ka_ac_free(ac);
    return NULL;
}

void ka_ac_free(ka_ac_t* ac) {
    if (!ac) return;
    if (ac->nodes) {
        for (size_t i = 0; i < ac->n_nodes; i++) {
            free(ac->nodes[i].matches);
        }
        free(ac->nodes);
    }
    free(ac);
}

int ka_ac_scan(const ka_ac_t* ac, const char* text, size_t text_len, uint8_t* out_bitmap) {
    if (!ac || !out_bitmap) return -1;
    if (text_len == 0) return 0;
    if (!text) return -1;

    int32_t state = 0;
    const ka_node* nodes = ac->nodes;
    for (size_t i = 0; i < text_len; i++) {
        unsigned char c = ac_tolower((unsigned char)text[i]);
        state = nodes[state].go[c];
        uint32_t n_matches = nodes[state].n_matches;
        if (n_matches) {
            const uint32_t* m = nodes[state].matches;
            for (uint32_t j = 0; j < n_matches; j++) {
                uint32_t pid = m[j];
                out_bitmap[pid >> 3] |= (uint8_t)(1u << (pid & 7));
            }
        }
    }
    return 0;
}

int ka_ac_match_any(const ka_ac_t* ac, const char* text, size_t text_len) {
    if (!ac) return -1;
    if (text_len == 0) return 0;
    if (!text) return -1;

    int32_t state = 0;
    const ka_node* nodes = ac->nodes;
    for (size_t i = 0; i < text_len; i++) {
        unsigned char c = ac_tolower((unsigned char)text[i]);
        state = nodes[state].go[c];
        if (nodes[state].n_matches) {
            return 1;  /* any pattern occurs here -> early exit (boolean @pm) */
        }
    }
    return 0;
}

size_t ka_ac_n_patterns(const ka_ac_t* ac) {
    return ac ? ac->n_patterns : 0;
}

size_t ka_ac_memory_bytes(const ka_ac_t* ac) {
    if (!ac) return 0;
    size_t b = sizeof(ka_ac_t) + ac->cap_nodes * sizeof(ka_node);
    for (size_t i = 0; i < ac->n_nodes; i++) {
        b += ac->nodes[i].cap_matches * sizeof(uint32_t);
    }
    return b;
}
