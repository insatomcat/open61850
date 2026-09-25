# open61850 C API

Sampled Values decoding, GOOSE encoding and decoding for real-time C programs, from the Rust crate `open61850-core`. The header is [`include/open61850.h`](include/open61850.h), generated from `src/lib.rs` by cbindgen.

The codecs accept the input open61850's Python codecs accept and write the octets they write (`tests/test_*_native.py` compare them), and are fuzzed (`native/fuzz`).

## From a release

Each GitHub release carries `libopen61850-VERSION-ARCH-linux-gnu.tar.gz` for x86_64 and aarch64, built on glibc 2.17: `include/`, `lib/` (static library, shared library `libopen61850.so.0.MINOR` while the version is 0.x), and two pkg-config files.

```sh
tar xzf libopen61850-0.6.0-x86_64-linux-gnu.tar.gz
export PKG_CONFIG_PATH=$PWD/libopen61850-0.6.0-x86_64-linux-gnu/lib/pkgconfig
cc prog.c $(pkg-config --cflags --libs open61850-static)   # static
cc prog.c $(pkg-config --cflags --libs open61850)          # shared
```

`package-manylinux.sh OUTDIR` builds the same archive locally (Docker).

## Build and link

```sh
cd native
cargo build --release -p open61850-c
# target/release/libopen61850.a (static) and libopen61850.so (shared)
cc -I capi/include prog.c target/release/libopen61850.a -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
```

Rust is needed to build the library, not to use it: a C program links the `.a` and includes the header.

## Conventions

- Every function returns `O61850_OK` (0) or a negative `O61850_ERR_*` code; `o61850_strerror` describes it.
- Nothing is allocated and no state is kept: every function may be called from any thread, on the real-time path.
- Decoding borrows: strings and buffers of decoded values (`o61850_bytes`) point into the caller's frame and live as long as it does. `ptr` is NULL only for an absent optional field.
- An output array too small gives `O61850_ERR_BUFFER`, with the first `capacity` elements filled and the count needed returned; encoding with `out_size` 0 returns the size needed.
- For a refused frame, `o61850_frame_info` still holds the MAC addresses and the VLAN tag, so a receiver can recognise its own emission.
- Frame decoders start at the destination MAC; `_payload` variants start at the APPID field, the octets after the EtherType.
- allData values are an array in preorder: a `O61850_DATA_STRUCTURE` or `O61850_DATA_ARRAY` of `n` members is followed by its `n` members.
- A Rust panic (a bug) is caught and returned as `O61850_ERR_INTERNAL`.

## Example

```c
#include "open61850.h"

/* A received SV frame: every ASDU, every channel. */
o61850_sv_asdu asdus[8];
size_t count;
if (o61850_sv_decode_frame(frame, len, NULL, NULL, asdus, 8, &count) == O61850_OK) {
    for (size_t i = 0; i < count; i++) {
        int32_t values[16];
        uint32_t qualities[16];
        size_t channels;
        o61850_sv_int32_samples(asdus[i].sample, values, qualities, 16, &channels);
        /* asdus[i].smp_cnt, .smp_synch, .conf_rev ... */
    }
}

/* A trip GOOSE: TRUE and its Quality. */
static const uint8_t good[2] = {0x00, 0x00};
o61850_data all_data[2] = {
    {.kind = O61850_DATA_BOOLEAN, .value.boolean = 1},
    {.kind = O61850_DATA_BIT_STRING, .value.bit_string = {{good, 2}, 3}},
};
o61850_goose_pdu pdu = {
    .gocb_ref = {(const uint8_t *)"IED01PROT/LLN0$GO$gcbTrip", 25},
    .time_allowed_to_live = 2000,
    .dat_set = {(const uint8_t *)"IED01PROT/LLN0$DS_TRIP", 22},
    .t = {.seconds = now_s, .fraction = now_frac},
    .st_num = st_num, .sq_num = sq_num, .conf_rev = 1,
    .num_dat_set_entries = 2, .all_data = all_data, .all_data_len = 2,
};
o61850_address to = {{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}, {0x02, 0, 0, 0, 0, 0x01}, 0x0001, true, 5, 4};
uint8_t out[512];
size_t out_len;
if (o61850_goose_encode_frame(&pdu, &to, out, sizeof out, &out_len) == O61850_OK)
    send(fd, out, out_len, 0);
```

## Tests

`tests/run.sh` checks that the header is the one cbindgen generates, then builds `tests/test_capi.c` (C11, ASan and UBSan) against the static library and runs it: frames written by the Python codecs, every return code, 200,000 random mutations through every decoder. It also compiles the header as C++.

`tests/test_package.sh TARBALL` builds and runs the same program against a release archive, through both pkg-config files, and checks that the program needs the shared library by its soname.
