# cubefs

Content-addressed filesystem via KPACK recipes.

`cubefs` is the on-disk layout for an immutable filesystem. Metadata lives in
4096-byte B-tree pages. File bytes live in extents that name [`kpack`](https://docs.rs/kpack)
recipes. A reader projects a recipe into a caller-provided buffer. Nothing is
allocated.

`no_std`. The only dependency is `kpack`.

## Install

```toml
[dependencies]
cubefs = "0.1.1"
```

```sh
cargo add cubefs
```

## Pages

`BTreeNode` is `#[repr(C, align(4096))]`. The header is 8 bytes, the payload is
4056 bytes, and the trailing 32 bytes are the page identity.

| Field | Meaning |
| --- | --- |
| `magic` | Layout tag. Tests use `BNOD`. |
| `version` | Layout version. |
| `level` | `0` is a leaf. |
| `entry_count` | Entries packed in `payload`. |
| `payload` | Serialized keys and values. |
| `blake3_hash` | Identity of the page. Not part of the hashed prefix. |

A directory entry in `payload` is little-endian: `hash: u64`, `name_len: u16`,
`name_len` bytes, `val_type: u8`, `val_data: [u8; 32]`. `BTreeIterator` yields
those fields as `BTreeEntry`. A short payload ends the iterator. `val_type` is
caller-defined (`0` inode, `1` directory, `2` inline data in the comments).

`Inode` is a 32-byte id plus a logical size. `Checkpoint` records a sequence, a
hardware timestamp, the metadata-root id, the data-graph root, and a 64-byte
signature.

## Extents

An `Extent` maps a logical range to a run of chunks:

| Field | Meaning |
| --- | --- |
| `file_off`, `len` | Range covered, in bytes. |
| `first_chunk_id` | 32-byte id of the first recipe. |
| `count` | Number of chunks in the run. |
| `last_len` | Used bytes in the last chunk. |

`KpackReader` finds the extent containing `offset`. The chunk size is 65536.
The index `(offset - file_off) / 65536` must be `< count`. The fetch closure
is then called with `first_chunk_id` only.

## Recipe

A chunk buffer is a recipe, not raw file bytes:

1. `opcode: u8`, a `kpack::Opcode`
2. `param: u16` little-endian, widened to `u32`
3. the remaining bytes, the payload

`read_into_section` runs `kpack::execute` into `section_buffer` with no
reference image. An unknown opcode, an empty recipe, or an offset outside every
extent returns `Err`.

```rust
use cubefs::{Extent, KpackReader};

let extents = [Extent {
    file_off: 0,
    len: 65536,
    first_chunk_id: [0xAA; 32],
    count: 1,
    last_len: 65536,
}];
let reader = KpackReader::new(&extents);

// opcode RLE, param 8, fill byte 0x20
let recipe = [0x02, 0x08, 0x00, 0x20];
let mut section = [0u8; 8];
let n = reader
    .read_into_section(0, &mut section, |_| Ok(recipe.as_slice()))
    .expect("extent");
assert_eq!(n, 8);
assert_eq!(section, [0x20; 8]);
```

## Copy on write

`Nucleator::insert_byte` inserts one byte into a 4096-byte page and shifts the
tail right. The byte that falls off the end is returned. `offset >= 4096`
returns `None`. The caller keeps both pages: the original is not modified.

## Documentation

API docs are on [docs.rs/cubefs](https://docs.rs/cubefs).

## License

[AGPL-3.0-or-later](LICENSE).
