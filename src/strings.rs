//! Printable-string extraction (ASCII and UTF-16LE) with lightweight tagging.
//!
//! Extraction is a single linear scan per encoding: O(n) time, O(k) output.
//! The UTF-16LE scanner advances one byte after a failed code unit so it
//! finds runs at both even and odd alignments without a second pass.

use std::sync::OnceLock;

use regex::RegexSet;
use serde::{Deserialize, Serialize};

/// Text encoding of an extracted string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    /// 7-bit printable ASCII.
    Ascii,
    /// UTF-16 little endian restricted to the printable ASCII range.
    Utf16Le,
}

/// Category assigned to strings that are commonly interesting during triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringTag {
    /// `scheme://host/...` URL.
    Url,
    /// Dotted-quad IPv4 address with valid octets.
    Ipv4,
    /// Something shaped like an e-mail address.
    Email,
    /// `C:\...` or `\\server\share` path.
    WindowsPath,
    /// Absolute POSIX path with at least two components.
    UnixPath,
    /// Windows registry key (`HKEY_*`, `HKLM\...`).
    Registry,
    /// Shared-library file name (`.dll`, `.so`, `.dylib`).
    LibraryName,
    /// Long run of base64 alphabet characters (possible encoded payload).
    Base64Like,
}

impl StringTag {
    /// All tags in declaration order (index matches the regex set).
    pub const ALL: [StringTag; 8] = [
        StringTag::Url,
        StringTag::Ipv4,
        StringTag::Email,
        StringTag::WindowsPath,
        StringTag::UnixPath,
        StringTag::Registry,
        StringTag::LibraryName,
        StringTag::Base64Like,
    ];

    /// Stable kebab-case name, as used in rule files and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            StringTag::Url => "url",
            StringTag::Ipv4 => "ipv4",
            StringTag::Email => "email",
            StringTag::WindowsPath => "windows-path",
            StringTag::UnixPath => "unix-path",
            StringTag::Registry => "registry",
            StringTag::LibraryName => "library-name",
            StringTag::Base64Like => "base64-like",
        }
    }

    /// Parse the kebab-case name back into a tag.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }
}

/// One extracted string.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtractedString {
    /// File offset of the first byte.
    pub offset: u64,
    /// Encoding the string was found in.
    pub encoding: Encoding,
    /// Decoded text (possibly truncated to `max_len` characters).
    pub value: String,
    /// Length in characters before truncation.
    pub length: usize,
    /// Interesting-string categories that matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<StringTag>,
}

/// Extraction knobs.
#[derive(Clone, Debug)]
pub struct StringOptions {
    /// Minimum run length in characters (default 4, like GNU `strings`).
    pub min_len: usize,
    /// Longer strings are truncated to this many characters (default 512).
    pub max_len: usize,
    /// Also scan for UTF-16LE strings (default true).
    pub utf16: bool,
}

impl Default for StringOptions {
    fn default() -> Self {
        Self { min_len: 4, max_len: 512, utf16: true }
    }
}

#[inline]
fn printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

fn make(offset: usize, encoding: Encoding, chars: &[u8], max_len: usize) -> ExtractedString {
    let length = chars.len();
    let kept = &chars[..length.min(max_len)];
    // Every byte is printable ASCII, so this conversion is lossless.
    let value: String = kept.iter().map(|&b| char::from(b)).collect();
    let tags = tag(&value);
    ExtractedString { offset: offset as u64, encoding, value, length, tags }
}

/// Extract ASCII runs of at least `opts.min_len` printable characters.
pub fn extract_ascii(data: &[u8], opts: &StringOptions) -> Vec<ExtractedString> {
    let min = opts.min_len.max(1);
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut run = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            if run >= min {
                out.push(make(start, Encoding::Ascii, &data[start..i], opts.max_len));
            }
            run = 0;
        }
    }
    if run >= min {
        out.push(make(start, Encoding::Ascii, &data[start..], opts.max_len));
    }
    out
}

/// Extract UTF-16LE runs (printable ASCII code units) of at least
/// `opts.min_len` characters, at any alignment.
pub fn extract_utf16le(data: &[u8], opts: &StringOptions) -> Vec<ExtractedString> {
    let min = opts.min_len.max(1);
    let mut out = Vec::new();
    let mut chars: Vec<u8> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + 1 < data.len() {
        if printable(data[i]) && data[i + 1] == 0 {
            if chars.is_empty() {
                start = i;
            }
            chars.push(data[i]);
            i += 2;
        } else {
            if chars.len() >= min {
                out.push(make(start, Encoding::Utf16Le, &chars, opts.max_len));
            }
            chars.clear();
            i += 1;
        }
    }
    if chars.len() >= min {
        out.push(make(start, Encoding::Utf16Le, &chars, opts.max_len));
    }
    out
}

/// Extract ASCII (and, if enabled, UTF-16LE) strings, sorted by offset.
pub fn extract(data: &[u8], opts: &StringOptions) -> Vec<ExtractedString> {
    let mut all = extract_ascii(data, opts);
    if opts.utf16 {
        all.extend(extract_utf16le(data, opts));
        all.sort_by_key(|s| (s.offset, s.encoding == Encoding::Utf16Le));
    }
    all
}

fn tag_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        RegexSet::new([
            // url
            r"(?i)\b(?:https?|ftp|wss?)://[a-z0-9.\-]+(?::\d+)?(?:/\S*)?",
            // ipv4 (each octet 0-255)
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            // email
            r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b",
            // windows path
            r"(?i)(?:\b[a-z]:\\|\\\\[a-z0-9_.\-]+\\)[^\x00]*",
            // unix path
            r"(?:^|[\s'\x22=])/(?:[A-Za-z0-9._\-]+/)+[A-Za-z0-9._\-]*",
            // registry
            r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)\\",
            // shared library names
            r"(?i)\b[a-z0-9_.\-]+\.(?:dll|dylib|so(?:\.\d+)*)\b",
            // base64-ish: 40+ alphabet chars, optional padding
            r"^[A-Za-z0-9+/]{40,}={0,2}$",
        ])
        .expect("built-in string tag patterns are valid")
    })
}

/// Return the tags that match `value`, in [`StringTag::ALL`] order.
pub fn tag(value: &str) -> Vec<StringTag> {
    tag_set().matches(value).into_iter().map(|i| StringTag::ALL[i]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(min: usize) -> StringOptions {
        StringOptions { min_len: min, ..StringOptions::default() }
    }

    #[test]
    fn ascii_runs_respect_min_len_and_offsets() {
        let data = b"\x00abc\x00hello\x01world!\x00";
        let s = extract_ascii(data, &opts(4));
        let got: Vec<(u64, &str)> = s.iter().map(|x| (x.offset, x.value.as_str())).collect();
        assert_eq!(got, vec![(5, "hello"), (11, "world!")]);
    }

    #[test]
    fn ascii_run_at_end_of_buffer() {
        let s = extract_ascii(b"\xffTAIL", &opts(4));
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, "TAIL");
    }

    #[test]
    fn utf16_runs_at_both_alignments() {
        let mut data = vec![0xffu8];
        data.extend("odd!".encode_utf16().flat_map(u16::to_le_bytes));
        data.extend([0xff, 0xff]);
        data.extend("even".encode_utf16().flat_map(u16::to_le_bytes));
        let s = extract_utf16le(&data, &opts(4));
        let got: Vec<(u64, &str)> = s.iter().map(|x| (x.offset, x.value.as_str())).collect();
        assert_eq!(got, vec![(1, "odd!"), (11, "even")]);
    }

    #[test]
    fn utf16_run_at_end() {
        let data: Vec<u8> = "wide".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let s = extract_utf16le(&data, &opts(4));
        assert_eq!(s[0].value, "wide");
        assert_eq!(s[0].encoding, Encoding::Utf16Le);
    }

    #[test]
    fn truncation_keeps_length() {
        let data = vec![b'A'; 100];
        let o = StringOptions { min_len: 4, max_len: 10, utf16: false };
        let s = extract(&data, &o);
        assert_eq!(s[0].value.len(), 10);
        assert_eq!(s[0].length, 100);
    }

    #[test]
    fn merged_output_is_sorted() {
        // Two NULs: a single NUL after "...e" would make "e\0" the first
        // UTF-16 code unit (the same ambiguity GNU strings -el has).
        let mut data = b"ascii-one\x00\x00".to_vec();
        data.extend("wide-two".encode_utf16().flat_map(u16::to_le_bytes));
        data.extend(b"\x00\x00ascii-three");
        let s = extract(&data, &opts(4));
        let offs: Vec<u64> = s.iter().map(|x| x.offset).collect();
        let mut sorted = offs.clone();
        sorted.sort_unstable();
        assert_eq!(offs, sorted);
        assert!(s.iter().any(|x| x.value == "wide-two"));
    }

    #[test]
    fn tags_cover_common_indicators() {
        assert_eq!(tag("see http://example.test/a"), vec![StringTag::Url]);
        assert!(tag("connect 127.0.0.1 now").contains(&StringTag::Ipv4));
        assert!(!tag("version 1.2.3.400").contains(&StringTag::Ipv4));
        assert!(tag("ops@example.test").contains(&StringTag::Email));
        assert!(tag(r"C:\Windows\Temp\x.tmp").contains(&StringTag::WindowsPath));
        assert!(tag("/tmp/binscope_roundtrip.tmp").contains(&StringTag::UnixPath));
        assert!(tag(r"HKEY_LOCAL_MACHINE\Software").contains(&StringTag::Registry));
        assert!(tag("kernel32.dll").contains(&StringTag::LibraryName));
        assert!(tag("libc.so.6").contains(&StringTag::LibraryName));
        assert!(tag("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZn").contains(&StringTag::Base64Like));
        assert!(tag("plain words").is_empty());
    }

    #[test]
    fn tag_names_round_trip() {
        for t in StringTag::ALL {
            assert_eq!(StringTag::from_name(t.as_str()), Some(t));
        }
        assert_eq!(StringTag::from_name("nope"), None);
    }
}
