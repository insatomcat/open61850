/* Copyright 2026 Florent Carli
 * SPDX-License-Identifier: Apache-2.0
 *
 * The C API of open61850 as a C program sees it: golden frames written by
 * open61850's Python codecs, every return code, then random mutations of
 * both frames through every decoder. Run by run.sh under ASan and UBSan.
 */

#include "open61850.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                               \
        }                                                                             \
    } while (0)

#define CHECK_RC(expr, rc)                                                                  \
    do {                                                                                    \
        int got_ = (expr);                                                                  \
        if (got_ != (rc)) {                                                                 \
            fprintf(stderr, "%s:%d: %s returned %d (%s), expected %d\n", __FILE__, __LINE__, \
                    #expr, got_, o61850_strerror(got_), (rc));                              \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

/* Written by open61850.sv.encode_sv_frame: 2 ASDUs "SV_1", smpCnt 0 and 1,
 * confRev 10000, smpSynch 2, 9 channels (i * 1000, quality 0), VLAN 100
 * priority 4, APPID 0x4000. */
static const uint8_t SV_FRAME[225] = {
    0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x81, 0x00, 0x80, 0x64,
    0x88, 0xba, 0x40, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x60, 0x81, 0xc4, 0x80, 0x01, 0x02,
    0xa2, 0x81, 0xbe, 0x30, 0x5d, 0x80, 0x04, 0x53, 0x56, 0x5f, 0x31, 0x82, 0x02, 0x00, 0x00, 0x83,
    0x04, 0x00, 0x00, 0x27, 0x10, 0x85, 0x01, 0x02, 0x87, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x1b, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x5d, 0x80, 0x04, 0x53, 0x56, 0x5f, 0x31, 0x82, 0x02, 0x00, 0x01, 0x83, 0x04,
    0x00, 0x00, 0x27, 0x10, 0x85, 0x01, 0x02, 0x87, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0b, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x1b, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x40, 0x00, 0x00, 0x00,
    0x00,
};

/* Written by open61850.goose.encode_goose_frame: gocbRef "IED01LD0/LLN0$GO",
 * TAL 2000, datSet "DS1", goID "G1", t 2026-01-01T00:00:00.5Z quality 0x0A,
 * stNum 128, sqNum 0, confRev 1, 2 entries (TRUE, Quality 0000/3), VLAN 5
 * priority 4, APPID 0x1000. */
static const uint8_t GOOSE_FRAME[98] = {
    0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x80, 0x05,
    0x88, 0xb8, 0x10, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x61, 0x46, 0x80, 0x10, 0x49, 0x45,
    0x44, 0x30, 0x31, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x47, 0x4f, 0x81, 0x02,
    0x07, 0xd0, 0x82, 0x03, 0x44, 0x53, 0x31, 0x83, 0x02, 0x47, 0x31, 0x84, 0x08, 0x69, 0x55, 0xb9,
    0x00, 0x80, 0x00, 0x00, 0x0a, 0x85, 0x02, 0x00, 0x80, 0x86, 0x01, 0x00, 0x87, 0x01, 0x00, 0x88,
    0x01, 0x01, 0x89, 0x01, 0x00, 0x8a, 0x01, 0x02, 0xab, 0x08, 0x83, 0x01, 0xff, 0x84, 0x03, 0x03,
    0x00, 0x00,
};
static int same(o61850_bytes b, const char *text)
{
    return b.ptr != NULL && b.len == strlen(text) && memcmp(b.ptr, text, b.len) == 0;
}

static o61850_bytes text(const char *s)
{
    o61850_bytes b = {(const uint8_t *)s, strlen(s)};
    return b;
}

static void test_strings(void)
{
    CHECK(strlen(o61850_version()) > 0);
    for (int code = 1; code >= -13; code--)
        CHECK(o61850_strerror(code) != NULL && strlen(o61850_strerror(code)) > 0);
}

static void test_sv(void)
{
    o61850_frame_info info;
    o61850_bytes security;
    o61850_sv_asdu asdus[4];
    size_t count = 99;

    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, sizeof SV_FRAME, &info, &security, asdus, 4, &count), O61850_OK);
    CHECK(count == 2);
    CHECK(info.has_vlan && info.vlan_id == 100 && info.vlan_priority == 4 && info.app_id == 0x4000);
    CHECK(info.src_mac[5] == 0x55 && info.dst_mac[3] == 0x04);
    CHECK(security.ptr == NULL);
    for (size_t i = 0; i < count; i++) {
        CHECK(same(asdus[i].sv_id, "SV_1"));
        CHECK(asdus[i].smp_cnt == i && asdus[i].conf_rev == 10000 && asdus[i].smp_synch == 2);
        CHECK(asdus[i].dat_set.ptr == NULL && asdus[i].gm_identity.ptr == NULL);
        CHECK(!asdus[i].has_refr_tm && !asdus[i].has_smp_rate && !asdus[i].has_smp_mod);
        int32_t values[16];
        uint32_t qualities[16];
        size_t channels = 0;
        CHECK_RC(o61850_sv_int32_samples(asdus[i].sample, values, qualities, 16, &channels), O61850_OK);
        CHECK(channels == 9);
        for (size_t ch = 0; ch < channels; ch++)
            CHECK(values[ch] == (int32_t)(ch * 1000) && qualities[ch] == 0);
        CHECK_RC(o61850_sv_int32_samples(asdus[i].sample, values, NULL, 4, &channels), O61850_ERR_BUFFER);
        CHECK(channels == 9);
    }

    /* From the APPID field, after the tag and the EtherType. */
    CHECK_RC(o61850_sv_decode_payload(SV_FRAME + 18, sizeof SV_FRAME - 18, &info, NULL, asdus, 4, &count),
             O61850_OK);
    CHECK(count == 2 && info.app_id == 0x4000 && !info.has_vlan && info.src_mac[5] == 0);

    /* One slot for two ASDUs: the first is filled. */
    memset(asdus, 0, sizeof asdus);
    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, sizeof SV_FRAME, NULL, NULL, asdus, 1, &count), O61850_ERR_BUFFER);
    CHECK(count == 2 && asdus[0].smp_cnt == 0 && asdus[1].sv_id.ptr == NULL);
    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, sizeof SV_FRAME, NULL, NULL, NULL, 0, &count), O61850_ERR_BUFFER);
    CHECK(count == 2);

    uint8_t frame[sizeof SV_FRAME];
    memcpy(frame, SV_FRAME, sizeof frame);
    frame[31] = 3; /* noASDU */
    CHECK_RC(o61850_sv_decode_frame(frame, sizeof frame, NULL, NULL, asdus, 4, &count), O61850_ERR_COUNT);
    memcpy(frame, SV_FRAME, sizeof frame);
    frame[43] = 0x8b; /* smpCnt [2] of the first ASDU becomes [11] */
    CHECK_RC(o61850_sv_decode_frame(frame, sizeof frame, NULL, NULL, asdus, 4, &count), O61850_ERR_FIELD);
    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, 100, &info, NULL, asdus, 4, &count), O61850_ERR_HEADER);
    CHECK(info.has_vlan && info.vlan_id == 100 && info.src_mac[5] == 0x55); /* what a refused frame tells */
    CHECK_RC(o61850_sv_decode_frame(GOOSE_FRAME, sizeof GOOSE_FRAME, NULL, NULL, asdus, 4, &count),
             O61850_ERR_ETHERTYPE);
    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, 17, NULL, NULL, asdus, 4, &count), O61850_ERR_ETHERTYPE);
    CHECK_RC(o61850_sv_decode_frame(NULL, 10, NULL, NULL, asdus, 4, &count), O61850_ERR_NULL);
    CHECK_RC(o61850_sv_decode_frame(SV_FRAME, sizeof SV_FRAME, NULL, NULL, NULL, 4, &count), O61850_ERR_NULL);
    o61850_bytes odd = {SV_FRAME, 12};
    CHECK_RC(o61850_sv_int32_samples(odd, NULL, NULL, 0, NULL), O61850_ERR_SAMPLES);
}

static o61850_goose_pdu goose_message(const o61850_data *values, size_t n)
{
    o61850_goose_pdu pdu;
    memset(&pdu, 0, sizeof pdu);
    pdu.gocb_ref = text("IED01LD0/LLN0$GO");
    pdu.time_allowed_to_live = 2000;
    pdu.dat_set = text("DS1");
    pdu.go_id = text("G1");
    pdu.t.seconds = 1767225600;
    pdu.t.fraction = 0x800000;
    pdu.t.quality = 0x0a;
    pdu.st_num = 128;
    pdu.conf_rev = 1;
    pdu.num_dat_set_entries = 2;
    pdu.all_data = values;
    pdu.all_data_len = n;
    return pdu;
}

static const o61850_address ADDRESS = {
    {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}, {0x02, 0, 0, 0, 0, 0x01}, 0x1000, true, 5, 4,
};

static void test_goose_encode(void)
{
    static const uint8_t quality[2] = {0, 0};
    o61850_data values[2];
    memset(values, 0, sizeof values);
    values[0].kind = O61850_DATA_BOOLEAN;
    values[0].value.boolean = 1;
    values[1].kind = O61850_DATA_BIT_STRING;
    values[1].value.bit_string.bits.ptr = quality;
    values[1].value.bit_string.bits.len = 2;
    values[1].value.bit_string.unused = 3;
    o61850_goose_pdu pdu = goose_message(values, 2);

    uint8_t out[256];
    size_t len = 0;
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_OK);
    CHECK(len == sizeof GOOSE_FRAME && memcmp(out, GOOSE_FRAME, len) == 0);
    CHECK_RC(o61850_goose_encode_pdu(&pdu, out, sizeof out, &len), O61850_OK);
    CHECK(len == sizeof GOOSE_FRAME - 26 && memcmp(out, GOOSE_FRAME + 26, len) == 0);

    /* Size query, then a buffer one octet short. */
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, NULL, 0, &len), O61850_ERR_BUFFER);
    CHECK(len == sizeof GOOSE_FRAME);
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof GOOSE_FRAME - 1, &len), O61850_ERR_BUFFER);

    o61850_address bad = ADDRESS;
    bad.vlan_id = 0x1000;
    CHECK_RC(o61850_goose_encode_frame(&pdu, &bad, out, sizeof out, &len), O61850_ERR_FRAME);
    CHECK_RC(o61850_goose_encode_frame(NULL, &ADDRESS, out, sizeof out, &len), O61850_ERR_NULL);
    CHECK_RC(o61850_goose_encode_frame(&pdu, NULL, out, sizeof out, &len), O61850_ERR_NULL);

    o61850_data broken[2];
    memcpy(broken, values, sizeof broken);
    broken[1].kind = 0;
    pdu = goose_message(broken, 2);
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_ERR_DATA);
    broken[1] = values[1];
    broken[0].kind = O61850_DATA_STRUCTURE;
    broken[0].value.members = 3;
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_ERR_DATA);
    broken[0] = values[0];
    broken[1].value.bit_string.unused = 8;
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_ERR_DATA);
    broken[1].value.bit_string.unused = 3;
    broken[1].value.bit_string.bits.ptr = NULL;
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_ERR_DATA);
    pdu = goose_message(NULL, 2);
    CHECK_RC(o61850_goose_encode_frame(&pdu, &ADDRESS, out, sizeof out, &len), O61850_ERR_NULL);
}

static void test_goose_decode(void)
{
    o61850_frame_info info;
    o61850_goose_received m;
    CHECK_RC(o61850_goose_decode_frame(GOOSE_FRAME, sizeof GOOSE_FRAME, &info, &m), O61850_OK);
    CHECK(info.has_vlan && info.vlan_id == 5 && info.vlan_priority == 4 && info.app_id == 0x1000);
    CHECK(same(m.gocb_ref, "IED01LD0/LLN0$GO") && same(m.dat_set, "DS1") && same(m.go_id, "G1"));
    CHECK(m.time_allowed_to_live == 2000 && m.st_num == 128 && m.sq_num == 0 && m.conf_rev == 1);
    CHECK(!m.simulation && !m.nds_com && m.num_dat_set_entries == 2 && m.entries == 2);
    CHECK(m.t.seconds == 1767225600 && m.t.fraction == 0x800000 && m.t.quality == 0x0a);

    o61850_data values[4];
    size_t count = 0;
    CHECK_RC(o61850_goose_values(m.all_data, values, 4, &count), O61850_OK);
    CHECK(count == 2);
    CHECK(values[0].kind == O61850_DATA_BOOLEAN && values[0].value.boolean == 1);
    CHECK(values[1].kind == O61850_DATA_BIT_STRING && values[1].value.bit_string.unused == 3 &&
          values[1].value.bit_string.bits.len == 2);
    CHECK_RC(o61850_goose_values(m.all_data, values, 1, &count), O61850_ERR_BUFFER);
    CHECK(count == 2);

    CHECK_RC(o61850_goose_decode_payload(GOOSE_FRAME + 18, sizeof GOOSE_FRAME - 18, &info, &m), O61850_OK);
    CHECK(info.app_id == 0x1000 && m.st_num == 128);

    uint8_t frame[sizeof GOOSE_FRAME];
    memcpy(frame, GOOSE_FRAME, sizeof frame);
    frame[69] = 0x8c; /* stNum [5] becomes [12], which is skipped */
    CHECK_RC(o61850_goose_decode_frame(frame, sizeof frame, &info, &m), O61850_ERR_FIELD);
    CHECK(m.gocb_ref.ptr == NULL && m.st_num == 0 && info.src_mac[5] == 0x01);
    memcpy(frame, GOOSE_FRAME, sizeof frame);
    memcpy(frame + 93, "\xa2\x03\x83\x05\x00", 5); /* a structure whose member runs past it */
    CHECK_RC(o61850_goose_decode_frame(frame, sizeof frame, &info, &m), O61850_ERR_BER);
    CHECK_RC(o61850_goose_decode_frame(SV_FRAME, sizeof SV_FRAME, &info, &m), O61850_ERR_ETHERTYPE);
    CHECK_RC(o61850_goose_decode_frame(GOOSE_FRAME, 30, &info, &m), O61850_ERR_HEADER);
    CHECK_RC(o61850_goose_decode_frame(GOOSE_FRAME, sizeof GOOSE_FRAME, &info, NULL), O61850_ERR_NULL);
}

/* xorshift64: the same mutations on every run. */
static uint64_t rng_state = 61850;

static uint64_t next_random(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_mutations(void)
{
    static uint8_t frame[512];
    o61850_sv_asdu asdus[8];
    o61850_data values[64];
    o61850_goose_received m;
    size_t accepted = 0;
    for (int round = 0; round < 200000; round++) {
        const uint8_t *source = round % 2 ? SV_FRAME : GOOSE_FRAME;
        size_t len = round % 2 ? sizeof SV_FRAME : sizeof GOOSE_FRAME;
        memcpy(frame, source, len);
        for (uint64_t k = next_random() % 4 + 1; k > 0; k--)
            frame[next_random() % len] = (uint8_t)next_random();
        if (next_random() % 5 == 0)
            len = next_random() % (len + 1);
        /* An exact-size copy on the heap, so ASan sees any read past the end. */
        uint8_t *exact = malloc(len ? len : 1);
        memcpy(exact, frame, len);
        size_t count = 0;
        if (o61850_sv_decode_frame(exact, len, NULL, NULL, asdus, 8, &count) == O61850_OK) {
            accepted++;
            for (size_t i = 0; i < count; i++) {
                int32_t v[32];
                o61850_sv_int32_samples(asdus[i].sample, v, NULL, 32, NULL);
            }
        }
        if (o61850_goose_decode_frame(exact, len, NULL, &m) == O61850_OK) {
            accepted++;
            o61850_goose_values(m.all_data, values, 64, &count);
        }
        if (len > 18) {
            o61850_sv_decode_payload(exact + 18, len - 18, NULL, NULL, asdus, 8, &count);
            o61850_goose_decode_payload(exact + 18, len - 18, NULL, &m);
        }
        free(exact);
    }
    CHECK(accepted > 1000); /* some mutations keep a valid frame */
}

int main(void)
{
    test_strings();
    test_sv();
    test_goose_encode();
    test_goose_decode();
    test_mutations();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    printf("C API of open61850 %s: all checks passed\n", o61850_version());
    return 0;
}
