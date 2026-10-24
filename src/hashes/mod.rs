//! Cryptographic digests and import-table hashes.
//!
//! * [`FileDigests`]: MD5 / SHA-1 / SHA-256 of the whole file.
//! * [`imphash`]: Mandiant's import hash for PE files, byte-compatible with
//!   pefile's `PE.get_imphash()` (verified against pefile output in
//!   `tests/reference_vectors.rs`).
//! * [`symhash`]: MD5 over the sorted, de-duplicated imported symbol names,
//!   the definition popularised for Mach-O by CRITs; binscope applies the
//!   same definition to ELF.

mod ordinals;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Lower-case hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// MD5 of `data` as lower-case hex.
pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// Whole-file cryptographic digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigests {
    /// MD5 (hex).
    pub md5: String,
    /// SHA-1 (hex).
    pub sha1: String,
    /// SHA-256 (hex).
    pub sha256: String,
}

impl FileDigests {
    /// Compute all three digests in one pass over `data`.
    pub fn of(data: &[u8]) -> Self {
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        for chunk in data.chunks(1 << 16) {
            md5.update(chunk);
            sha1.update(chunk);
            sha256.update(chunk);
        }
        Self {
            md5: hex(&md5.finalize()),
            sha1: hex(&sha1.finalize()),
            sha256: hex(&sha256.finalize()),
        }
    }
}

/// How a PE import names its target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportRef<'a> {
    /// Imported by name.
    Name(&'a str),
    /// Imported by ordinal only.
    Ordinal(u16),
}

/// Resolve the function token pefile uses for one import.
fn imphash_func(dll_lower_full: &str, import: &ImportRef<'_>) -> String {
    match import {
        ImportRef::Name(name) => name.to_ascii_lowercase(),
        ImportRef::Ordinal(ord) => ordinals::table_for(dll_lower_full)
            .and_then(|t| t.binary_search_by_key(ord, |&(o, _)| o).ok().map(|i| t[i].1))
            .map_or_else(|| format!("ord{ord}"), str::to_ascii_lowercase),
    }
}

/// Library token pefile uses: lower-cased, `.dll`/`.ocx`/`.sys` stripped.
fn imphash_lib(dll: &str) -> String {
    let lower = dll.to_ascii_lowercase();
    match lower.rsplit_once('.') {
        Some((stem, ext)) if matches!(ext, "dll" | "ocx" | "sys") => stem.to_string(),
        _ => lower,
    }
}

/// The comma-joined string that [`imphash`] digests (exposed for reports and
/// debugging). `imports` must be in import-directory order.
pub fn imphash_input<'a, I>(imports: I) -> String
where
    I: IntoIterator<Item = (&'a str, ImportRef<'a>)>,
{
    let mut parts: Vec<String> = Vec::new();
    for (dll, import) in imports {
        if let ImportRef::Name(n) = import {
            if n.is_empty() {
                continue;
            }
        }
        let func = imphash_func(&dll.to_ascii_lowercase(), &import);
        parts.push(format!("{}.{}", imphash_lib(dll), func));
    }
    parts.join(",")
}

/// PE import hash, or `None` when the binary imports nothing (pefile then
/// returns an empty string).
pub fn imphash<'a, I>(imports: I) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, ImportRef<'a>)>,
{
    let input = imphash_input(imports);
    if input.is_empty() {
        None
    } else {
        Some(md5_hex(input.as_bytes()))
    }
}

/// Symbol hash: MD5 of the sorted, de-duplicated symbol names joined by `,`.
/// Returns `None` for an empty set.
pub fn symhash<'a, I>(symbols: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut names: Vec<&str> = symbols.into_iter().filter(|s| !s.is_empty()).collect();
    if names.is_empty() {
        return None;
    }
    names.sort_unstable();
    names.dedup();
    Some(md5_hex(names.join(",").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        let d = FileDigests::of(b"abc");
        assert_eq!(d.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(d.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            d.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn imphash_input_matches_pefile_conventions() {
        let imports = vec![
            ("KERNEL32.dll", ImportRef::Name("GetStdHandle")),
            ("ws2_32.dll", ImportRef::Ordinal(4)),
            ("WS2_32.DLL", ImportRef::Ordinal(9999)),
            ("custom.ocx", ImportRef::Name("Foo")),
            ("weird.bin", ImportRef::Ordinal(7)),
            ("MSVCRT.dll", ImportRef::Name("")),
        ];
        assert_eq!(
            imphash_input(imports),
            "kernel32.getstdhandle,ws2_32.connect,ws2_32.ord9999,custom.foo,weird.bin.ord7"
        );
    }

    #[test]
    fn oleaut32_and_wsock32_ordinals_resolve() {
        assert_eq!(imphash_func("oleaut32.dll", &ImportRef::Ordinal(2)), "sysallocstring");
        assert_eq!(imphash_func("wsock32.dll", &ImportRef::Ordinal(3)), "closesocket");
        assert_eq!(imphash_func("user32.dll", &ImportRef::Ordinal(3)), "ord3");
    }

    #[test]
    fn imphash_empty_is_none() {
        assert_eq!(imphash(Vec::new()), None);
        assert_eq!(
            imphash(vec![("a.dll", ImportRef::Name("B"))]),
            Some(md5_hex(b"a.b"))
        );
    }

    #[test]
    fn symhash_sorts_and_dedups() {
        let a = symhash(["_puts", "_exit", "_puts"]);
        let b = symhash(["_exit", "_puts"]);
        assert_eq!(a, b);
        assert_eq!(a, Some(md5_hex(b"_exit,_puts")));
        assert_eq!(symhash(Vec::<&str>::new()), None);
    }
}
