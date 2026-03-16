#!/usr/bin/env bash
# build_blast.sh - Build the PKWARE DCL "blast" decompression shared library
# blast.c and blast.h are bundled (zlib License, Copyright Mark Adler)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v gcc &>/dev/null; then
    echo "ERROR: gcc not found. Install build-essential."
    exit 1
fi

cat > "$SCRIPT_DIR/blast_wrap.c" << 'CWRAP'
#include "blast.h"
#include <stdlib.h>
#include <string.h>

typedef struct { const unsigned char *buf; size_t len; size_t pos; } InState;
typedef struct { unsigned char *buf; size_t len; size_t pos; } OutState;

static unsigned inf_in(void *how, unsigned char **buf) {
    InState *s = (InState*)how;
    size_t avail = s->len - s->pos;
    if (!avail) return 0;
    size_t chunk = avail < 4096 ? avail : 4096;
    *buf = (unsigned char*)(s->buf + s->pos);
    s->pos += chunk;
    return (unsigned)chunk;
}

static int inf_out(void *how, unsigned char *buf, unsigned len) {
    OutState *s = (OutState*)how;
    if (s->pos + len > s->len) {
        s->len = (s->pos + len) * 2;
        s->buf = realloc(s->buf, s->len);
        if (!s->buf) return 1;
    }
    memcpy(s->buf + s->pos, buf, len);
    s->pos += len;
    return 0;
}

unsigned char* blast_decompress(const unsigned char *in, size_t in_len, size_t *out_len) {
    InState is = {in, in_len, 0};
    OutState os = {malloc(65536), 65536, 0};
    if (!os.buf) { *out_len = 0; return NULL; }
    int ret = blast(inf_in, &is, inf_out, &os, NULL, NULL);
    if (ret != 0 && os.pos == 0) { free(os.buf); *out_len = 0; return NULL; }
    *out_len = os.pos;
    return os.buf;
}
CWRAP

gcc -O2 -shared -fPIC \
    -o "$SCRIPT_DIR/libblast.so" \
    "$SCRIPT_DIR/blast_wrap.c" \
    "$SCRIPT_DIR/blast.c"

echo "Built: libblast.so"
echo "Run:   python3 is3extract.py data.z output_dir"
