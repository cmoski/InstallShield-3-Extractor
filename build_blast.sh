#!/usr/bin/env bash
# build_blast.sh - Build the PKWARE DCL "blast" decompression shared library
# Required by is3extract.py
#
# blast.c is from zlib/contrib/blast by Mark Adler.
# It implements PKWARE Data Compression Library "implode" decompression,
# the compression format used by InstallShield 3 archives.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building libblast.so..."

# Check for gcc
if ! command -v gcc &>/dev/null; then
    echo "ERROR: gcc not found. Install build-essential."
    exit 1
fi

# Check for blast.c - try several locations
BLAST_C=""
for candidate in \
    "$SCRIPT_DIR/blast.c" \
    "/usr/share/doc/zlib1g-dev/examples/blast.c" \
    "$(find /usr -name blast.c 2>/dev/null | head -1)" \
    "$(find / -path "*/zlib*/blast.c" 2>/dev/null | head -1)"; do
    if [ -f "$candidate" ]; then
        BLAST_C="$candidate"
        break
    fi
done

if [ -z "$BLAST_C" ]; then
    echo "blast.c not found. Downloading from zlib source..."
    # Try to get from dosbox-x or similar if available
    DOSBOX_BLAST=$(find /home -path "*/dosbox*/blast.c" 2>/dev/null | head -1)
    if [ -n "$DOSBOX_BLAST" ]; then
        cp "$DOSBOX_BLAST" "$SCRIPT_DIR/blast.c"
        cp "$(dirname $DOSBOX_BLAST)/blast.h" "$SCRIPT_DIR/blast.h"
        BLAST_C="$SCRIPT_DIR/blast.c"
        echo "Found blast.c in dosbox: $DOSBOX_BLAST"
    else
        echo "ERROR: blast.c not found. Please copy zlib/contrib/blast/blast.c here."
        echo "Source: https://github.com/madler/zlib/tree/master/contrib/blast"
        exit 1
    fi
fi

echo "Using blast.c from: $BLAST_C"
BLAST_DIR="$(dirname $BLAST_C)"

# Copy to build location if needed
if [ "$BLAST_C" != "$SCRIPT_DIR/blast.c" ]; then
    cp "$BLAST_C" "$SCRIPT_DIR/blast.c"
    cp "$BLAST_DIR/blast.h" "$SCRIPT_DIR/blast.h" 2>/dev/null || true
fi

# Write the wrapper
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

echo "Built: $SCRIPT_DIR/libblast.so"
echo "Done. Run: python3 is3extract.py data.z output_dir"
