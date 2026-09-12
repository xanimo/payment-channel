/* Seeds for fuzz_sig: real signatures, and the edges a mutator will not find.
 *
 * An empty corpus makes a dedicated target no better than the smoke it
 * replaced, because the interesting behaviour is all past the structural
 * checks and random bytes never get there. Every seed below is a bare DER
 * signature with no hashtype byte, which is what pc_sig_is_standard is handed.
 *
 *   ./fuzz/mksigseed fuzz/corpus/sig
 */

#include "channel.h"
#include "hex.h"
#include "ec.h"
#include "rng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char N[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
};
/* n/2, the largest S that is still low */
static const unsigned char HALF_N[32] = {
    0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
};

static int nwritten = 0;

static void emit(const char *dir, const char *name,
                 const unsigned char *b, size_t n)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    fwrite(b, 1, n, f);
    fclose(f);
    nwritten++;
}

/* DER-encode r and s as 32-byte big-endian integers, minimally. */
static size_t der_of(const unsigned char r[32], const unsigned char s[32],
                     unsigned char *out)
{
    unsigned char body[80];
    size_t o = 0;
    const unsigned char *v[2] = { r, s };
    for (int k = 0; k < 2; k++) {
        size_t lead = 0;
        while (lead < 31 && v[k][lead] == 0) lead++;
        int pad = (v[k][lead] & 0x80) ? 1 : 0;
        body[o++] = 0x02;
        body[o++] = (unsigned char)((32 - lead) + pad);
        if (pad) body[o++] = 0x00;
        memcpy(body + o, v[k] + lead, 32 - lead);
        o += 32 - lead;
    }
    out[0] = 0x30;
    out[1] = (unsigned char)o;
    memcpy(out + 2, body, o);
    return o + 2;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s DIR\n", argv[0]); return 2; }
    const char *dir = argv[1];
    if (!kw_ec_start()) return 1;

    /* A dozen real ones. Different keys and different messages, so r and s vary
       in length and the leading-zero cases turn up on their own. */
    for (int i = 0; i < 12; i++) {
        uint8_t sk[32], msg[32];
        if (!kw_random_bytes(sk, sizeof(sk))) return 1;
        for (int j = 0; j < 32; j++) msg[j] = (uint8_t)(i * 31 + j);
        unsigned char der[80];
        size_t dlen = sizeof(der);
        if (!kw_ec_sign(sk, msg, der, &dlen)) { i--; continue; }
        char name[64];
        snprintf(name, sizeof(name), "real%02d", i);
        emit(dir, name, der, dlen);

        if (i == 0) {
            /* the same signature one byte short, and with a byte appended:
               the length field and the actual length disagreeing is the class
               a mutator finds slowly and a seed finds at once */
            emit(dir, "short", der, dlen - 1);
            unsigned char longer[81];
            memcpy(longer, der, dlen);
            longer[dlen] = 0x00;
            emit(dir, "trailing", longer, dlen + 1);
            unsigned char offbyone[80];
            memcpy(offbyone, der, dlen);
            offbyone[1] = (unsigned char)(offbyone[1] + 1);
            emit(dir, "lenplus1", offbyone, dlen);
        }
        { volatile uint8_t *z = sk; for (int j = 0; j < 32; j++) z[j] = 0; }
    }

    unsigned char one[32] = {0};  one[31] = 1;
    unsigned char der[80];

    /* S exactly at n/2: the largest S that is still low, so this must be
       accepted and is the boundary the comparison gets wrong if it is ever
       written as >= rather than >. */
    emit(dir, "s_half_n", der, der_of(one, HALF_N, der));

    /* one koinu above it, which must not be */
    unsigned char over[32];
    memcpy(over, HALF_N, 32);
    over[31]++;
    emit(dir, "s_half_n_plus1", der, der_of(one, over, der));

    /* S = n - 1, the far end of high */
    unsigned char nm1[32];
    memcpy(nm1, N, 32);
    nm1[31]--;
    emit(dir, "s_n_minus_1", der, der_of(one, nm1, der));

    /* r and s with a leading zero that is necessary (top bit set) and one that
       is not, which is the padding rule in both directions */
    unsigned char topbit[32] = {0};
    topbit[0] = 0x80; topbit[31] = 1;
    emit(dir, "r_needs_pad", der, der_of(topbit, one, der));

    {
        /* an unnecessary leading zero, built by hand since der_of will not */
        unsigned char b[80];
        size_t o = 0;
        b[o++] = 0x30; b[o++] = 0x00;
        b[o++] = 0x02; b[o++] = 0x02; b[o++] = 0x00; b[o++] = 0x01;
        b[o++] = 0x02; b[o++] = 0x01; b[o++] = 0x01;
        b[1] = (unsigned char)(o - 2);
        emit(dir, "r_extra_zero", b, o);
    }
    {
        /* negative r: top bit set with no pad */
        unsigned char b[80];
        size_t o = 0;
        b[o++] = 0x30; b[o++] = 0x00;
        b[o++] = 0x02; b[o++] = 0x01; b[o++] = 0x80;
        b[o++] = 0x02; b[o++] = 0x01; b[o++] = 0x01;
        b[1] = (unsigned char)(o - 2);
        emit(dir, "r_negative", b, o);
    }
    {
        /* the shortest thing that is still well formed */
        static const unsigned char tiny[8] = {
            0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01
        };
        emit(dir, "minimal", tiny, sizeof(tiny));
    }
    {
        /* zero-length integers, both of them */
        static const unsigned char zr[8] = {
            0x30,0x06,0x02,0x00,0x01,0x02,0x01,0x01
        };
        emit(dir, "zero_len_r", zr, sizeof(zr));
    }

    kw_ec_stop();
    fprintf(stderr, "%d seeds in %s\n", nwritten, dir);
    return 0;
}
