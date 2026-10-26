//! Input normalization pipeline — mirrors the Go 9-phase pipeline in analyze.go.
//!
//! This ensures the Rust pattern matcher sees the same normalized input as the
//! Go engine, closing the evasion blind spot where attackers use encoding tricks
//! to bypass Rust-side detection while Go catches them.

/// Run the full 9-phase normalization pipeline on input text.
pub fn normalize(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = input.to_string();

    // Phase 1: URL percent decoding (triple-pass for double/triple encoding)
    result = decode_url_percent(&result);
    result = decode_url_percent(&result);
    result = decode_url_percent(&result);

    // Phase 2: HTML entity decoding
    result = decode_html_entities(&result);

    // Phase 3: Backslash escape decoding
    result = decode_backslash_escapes(&result);

    // Phase 4: Strip null bytes
    result = result.replace('\0', "");

    // Phase 5: Strip SQL/C-style inline comments
    result = strip_inline_comments(&result);

    // Phase 6: Normalize whitespace variants to regular spaces
    result = normalize_whitespace(&result);

    // Phase 7: Unicode homoglyph normalization
    result = normalize_homoglyphs(&result);

    // Phase 8: Unicode NFKC folding (fullwidth/mathematical → ASCII)
    result = fold_unicode(&result);

    // Phase 9: Collapse redundant whitespace
    result = collapse_spaces(&result);

    result
}

fn unhex(c: u8) -> i32 {
    match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a' + 10) as i32,
        b'A'..=b'F' => (c - b'A' + 10) as i32,
        _ => -1,
    }
}

fn decode_url_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = unhex(bytes[i + 1]);
            let lo = unhex(bytes[i + 2]);
            if hi >= 0 && lo >= 0 {
                out.push((hi << 4 | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_html_entities(s: &str) -> String {
    // Named entities
    let named: &[(&str, &str)] = &[
        ("&lt;", "<"),
        ("&LT;", "<"),
        ("&gt;", ">"),
        ("&GT;", ">"),
        ("&amp;", "&"),
        ("&AMP;", "&"),
        ("&quot;", "\""),
        ("&QUOT;", "\""),
        ("&apos;", "'"),
        ("&APOS;", "'"),
        ("&sol;", "/"),
        ("&bsol;", "\\"),
        ("&lpar;", "("),
        ("&rpar;", ")"),
        ("&semi;", ";"),
        ("&comma;", ","),
        ("&equals;", "="),
        ("&plus;", "+"),
        ("&num;", "#"),
        ("&excl;", "!"),
        ("&colon;", ":"),
        ("&Tab;", "\t"),
        ("&NewLine;", "\n"),
    ];

    let mut result = s.to_string();
    for (entity, replacement) in named {
        result = result.replace(entity, replacement);
    }

    // Numeric entities: &#60; &#x3C;
    let bytes = result.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 2 < bytes.len() && bytes[i + 1] == b'#' {
            if let Some(end) = bytes[i..(i + 10).min(bytes.len())]
                .iter()
                .position(|&b| b == b';')
            {
                if end > 0 && end < 10 {
                    let num_slice = &bytes[i + 2..i + end];
                    let val = if !num_slice.is_empty()
                        && (num_slice[0] == b'x' || num_slice[0] == b'X')
                    {
                        parse_hex(&num_slice[1..])
                    } else {
                        parse_decimal(num_slice)
                    };
                    if (0..128).contains(&val) {
                        out.push(val as u8);
                        i += end + 1;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_hex(bytes: &[u8]) -> i32 {
    let mut val: i32 = 0;
    for &b in bytes {
        let h = unhex(b);
        if h < 0 {
            return -1;
        }
        val = val * 16 + h;
    }
    val
}

fn parse_decimal(bytes: &[u8]) -> i32 {
    let mut val: i32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return -1;
        }
        val = val * 10 + (b - b'0') as i32;
    }
    val
}

fn decode_backslash_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'x' | b'X' if i + 3 < bytes.len() => {
                    let hi = unhex(bytes[i + 2]);
                    let lo = unhex(bytes[i + 3]);
                    if hi >= 0 && lo >= 0 {
                        out.push((hi << 4 | lo) as u8);
                        i += 4;
                        continue;
                    }
                }
                b'u' | b'U' if i + 5 < bytes.len() => {
                    let mut val = 0i32;
                    let mut valid = true;
                    for j in 2..6 {
                        let h = unhex(bytes[i + j]);
                        if h < 0 {
                            valid = false;
                            break;
                        }
                        val = val * 16 + h;
                    }
                    if valid && val < 128 {
                        out.push(val as u8);
                        i += 6;
                        continue;
                    }
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'0' => {
                    if i + 3 < bytes.len()
                        && bytes[i + 2] >= b'0'
                        && bytes[i + 2] <= b'7'
                        && bytes[i + 3] >= b'0'
                        && bytes[i + 3] <= b'7'
                    {
                        let val = (bytes[i + 1] - b'0') as i32 * 64
                            + (bytes[i + 2] - b'0') as i32 * 8
                            + (bytes[i + 3] - b'0') as i32;
                        if val < 128 {
                            out.push(val as u8);
                            i += 4;
                            continue;
                        }
                    }
                    out.push(0);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn strip_inline_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Find closing */ — remove comment entirely (mirrors Go pipeline)
            if let Some(pos) = s[i + 2..].find("*/") {
                i += pos + 4;
                continue;
            }
            out.extend_from_slice(&bytes[i..]);
            break;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn normalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' | '\n' | '\r' | '\x0B' | '\x0C' | '\u{00A0}' | '\u{2000}' | '\u{2001}'
            | '\u{2002}' | '\u{2003}' | '\u{2004}' | '\u{2005}' | '\u{2006}' | '\u{2007}'
            | '\u{2008}' | '\u{2009}' | '\u{200A}' | '\u{200B}' | '\u{200C}' | '\u{200D}'
            | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' => {
                out.push(' ')
            }
            _ => out.push(c),
        }
    }
    out
}

fn normalize_homoglyphs(s: &str) -> String {
    lazy_static_homoglyphs()
        .iter()
        .fold(s.to_string(), |acc, (from, to)| acc.replace(from, to))
}

fn lazy_static_homoglyphs() -> &'static Vec<(&'static str, &'static str)> {
    use std::sync::OnceLock;
    static MAP: OnceLock<Vec<(&str, &str)>> = OnceLock::new();
    MAP.get_or_init(|| {
        vec![
            // Quotation marks
            ("\u{2018}", "'"),
            ("\u{2019}", "'"),
            ("\u{201C}", "\""),
            ("\u{201D}", "\""),
            ("\u{0060}", "'"),
            ("\u{00B4}", "'"),
            // Fullwidth punctuation
            ("\u{FF08}", "("),
            ("\u{FF09}", ")"),
            ("\u{FF3B}", "["),
            ("\u{FF3D}", "]"),
            ("\u{FF5B}", "{"),
            ("\u{FF5D}", "}"),
            ("\u{FF1C}", "<"),
            ("\u{FF1E}", ">"),
            ("\u{FF0F}", "/"),
            ("\u{FF3C}", "\\"),
            ("\u{2024}", "."),
            ("\u{FF0E}", "."),
            ("\u{FF1A}", ":"),
            ("\u{FF1B}", ";"),
            ("\u{FF0C}", ","),
            ("\u{FF01}", "!"),
            ("\u{FF1D}", "="),
            ("\u{FF0B}", "+"),
            ("\u{FF05}", "%"),
            ("\u{FF03}", "#"),
            ("\u{FF20}", "@"),
            ("\u{FF06}", "&"),
            ("\u{FF5C}", "|"),
            ("\u{FF3E}", "^"),
            ("\u{FF5E}", "~"),
            ("\u{FF0D}", "-"),
            ("\u{FF3F}", "_"),
            ("\u{FF04}", "$"),
            ("\u{FF07}", "'"),
            ("\u{FF02}", "\""),
            // Cyrillic lookalikes
            ("\u{0410}", "A"),
            ("\u{0430}", "a"),
            ("\u{0412}", "B"),
            ("\u{0432}", "b"),
            ("\u{0421}", "C"),
            ("\u{0441}", "c"),
            ("\u{0415}", "E"),
            ("\u{0435}", "e"),
            ("\u{041D}", "H"),
            ("\u{043D}", "h"),
            ("\u{041A}", "K"),
            ("\u{043A}", "k"),
            ("\u{041C}", "M"),
            ("\u{043C}", "m"),
            ("\u{041E}", "O"),
            ("\u{043E}", "o"),
            ("\u{0420}", "P"),
            ("\u{0440}", "p"),
            ("\u{0422}", "T"),
            ("\u{0442}", "t"),
            ("\u{0425}", "X"),
            ("\u{0445}", "x"),
            ("\u{0423}", "Y"),
            ("\u{0443}", "y"),
        ]
    })
}

/// Fold Unicode fullwidth, halfwidth, and mathematical alphanumeric symbols
/// to their ASCII equivalents. Prevents NFKC normalization bypasses (CVE-2026-25673).
fn fold_unicode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let code = c as u32;
        match code {
            // Fullwidth ASCII: U+FF01 ('!') .. U+FF5E ('~') → 0x21..0x7E
            0xFF01..=0xFF5E => out.push((code - 0xFF01 + 0x21) as u8 as char),
            // Mathematical Bold A-Z
            0x1D400..=0x1D419 => out.push((b'A' + (code - 0x1D400) as u8) as char),
            // Mathematical Bold a-z
            0x1D41A..=0x1D433 => out.push((b'a' + (code - 0x1D41A) as u8) as char),
            // Mathematical Italic A-Z
            0x1D434..=0x1D44D => out.push((b'A' + (code - 0x1D434) as u8) as char),
            // Mathematical Italic a-z
            0x1D44E..=0x1D467 => out.push((b'a' + (code - 0x1D44E) as u8) as char),
            // Mathematical Bold digits 0-9
            0x1D7CE..=0x1D7D7 => out.push((b'0' + (code - 0x1D7CE) as u8) as char),
            _ => out.push(c),
        }
    }
    out
}

fn collapse_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_normalization_preserves_boundaries_and_large_tails() {
        for (input, expected) in [
            ("&#0000060;", "<"),
            ("&#00000060;", "&#00000060;"),
            ("&#x00003C;", "<"),
            ("&#bad &#60;", "&#bad <"),
            ("&#👁👁👁&#60;", "&#👁👁👁<"),
            ("&#;", "\0"),
        ] {
            assert_eq!(decode_html_entities(input), expected, "{input}");
        }
        for (input, expected) in [
            ("SEL/**/ECT", "SELECT"),
            ("a/*done*/b/*unterminated", "ab/*unterminated"),
            ("/*a/*b", "/*a/*b"),
            ("正常/*x*/尾部", "正常尾部"),
        ] {
            assert_eq!(strip_inline_comments(input), expected, "{input}");
        }
        let entities = "&#".repeat(32768);
        assert_eq!(decode_html_entities(&entities), entities);
        let comments = "/*a".repeat(21845);
        assert_eq!(strip_inline_comments(&comments), comments);
    }

    #[test]
    fn test_url_percent_decode() {
        assert_eq!(normalize("%27%20OR%201%3D1"), "' OR 1=1");
    }

    #[test]
    fn test_double_encoding() {
        assert_eq!(normalize("%2527%2520OR"), "' OR");
    }

    #[test]
    fn test_html_entities() {
        assert_eq!(normalize("&lt;script&gt;"), "<script>");
    }

    #[test]
    fn test_numeric_entities() {
        assert_eq!(normalize("&#60;script&#62;"), "<script>");
    }

    #[test]
    fn test_hex_entities() {
        assert_eq!(normalize("&#x3C;script&#x3E;"), "<script>");
    }

    #[test]
    fn test_backslash_hex() {
        assert_eq!(normalize("\\x3Cscript\\x3E"), "<script>");
    }

    #[test]
    fn test_backslash_unicode() {
        assert_eq!(normalize("\\u003Cscript\\u003E"), "<script>");
    }

    #[test]
    fn test_null_byte_strip() {
        assert_eq!(normalize("SEL\0ECT"), "SELECT");
    }

    #[test]
    fn test_sql_comment_strip() {
        assert_eq!(normalize("SEL/**/ECT"), "SELECT");
    }

    #[test]
    fn test_whitespace_normalize() {
        assert_eq!(normalize("SELECT\t\nFROM"), "SELECT FROM");
    }

    #[test]
    fn test_fullwidth_homoglyphs() {
        assert_eq!(normalize("\u{FF1C}script\u{FF1E}"), "<script>");
    }

    #[test]
    fn test_cyrillic_homoglyphs() {
        // Cyrillic 'С' (Es) + 'е' (Ie) in "Select"
        assert_eq!(normalize("\u{0421}ele\u{0441}t"), "Celect");
    }

    #[test]
    fn test_collapse_spaces() {
        assert_eq!(normalize("SELECT   *   FROM"), "SELECT * FROM");
    }

    #[test]
    fn test_combined_evasion() {
        // URL-encoded + comment-split + whitespace
        assert_eq!(normalize("UN%49ON/**/SEL%45CT"), "UNIONSELECT");
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(normalize(""), "");
    }
}
