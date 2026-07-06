//! Filename sanitization for received files.
//!
//! Threat model: `fileName` comes from an untrusted peer. It must never
//! escape the destination directory, break the local filesystem, or spoof
//! the user in terminal output. Mirrors the spirit of the official app
//! (which saves under a user-chosen folder) but is stricter, since a CLI
//! may run unattended as a daemon.

const MAX_NAME_BYTES: usize = 255; // common fs limit (ext4, APFS, NTFS)

/// Windows-reserved device names, sanitized everywhere for portability
/// (a file received on Linux may later sync to a Windows machine).
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Sanitize an untrusted file name into a safe, single path component.
/// Never returns an empty string, `.`/`..`, path separators, control
/// characters, or an over-long name.
pub fn sanitize_file_name(raw: &str) -> String {
    // 1. Take only the last path component, accepting / and \ as separators
    //    (a Windows sender may use backslashes).
    let last = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("");

    // 2. Drop control chars (incl. NUL), and BiDi override chars used for
    //    extension spoofing (U+202A..U+202E, U+2066..U+2069).
    let mut name: String = last
        .chars()
        .filter(|c| !c.is_control())
        .filter(|c| !matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
        .collect();

    // 3. Strip characters that are invalid on Windows filesystems.
    name = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();

    // 4. Trim leading/trailing whitespace and trailing dots (Windows).
    let name = name.trim().trim_end_matches(['.', ' ']).to_string();

    // 5. Reject empty / dot-only names.
    if name.is_empty() || name == "." || name == ".." {
        return "unnamed".to_string();
    }

    // 6. Neutralize Windows reserved names (case-insensitive, with or
    //    without extension: "CON", "con.txt").
    let stem = name.split('.').next().unwrap_or("");
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return format!("_{name}");
    }

    // 7. Enforce byte-length limit, preserving the extension where possible.
    if name.len() > MAX_NAME_BYTES {
        return truncate_preserving_ext(&name, MAX_NAME_BYTES);
    }
    name
}

fn truncate_preserving_ext(name: &str, max: usize) -> String {
    let ext = match name.rfind('.') {
        // Keep extensions up to 16 bytes; anything longer is not a real ext.
        Some(i) if name.len() - i <= 16 && i > 0 => &name[i..],
        _ => "",
    };
    let budget = max - ext.len();
    let mut cut = budget;
    // Walk back to a char boundary.
    let stem = &name[..name.len() - ext.len()];
    while cut > 0 && !stem.is_char_boundary(cut.min(stem.len())) {
        cut -= 1;
    }
    format!("{}{}", &stem[..cut.min(stem.len())], ext)
}

/// Pick a non-colliding path in `dir` for `name`, matching the official
/// app's pattern (file_path_helper.dart): "x.txt" -> "x (2).txt" -> "x (3).txt";
/// an existing " (N)" suffix on the stem is replaced, never nested.
pub fn dedup_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let base = strip_count_suffix(stem);
    for n in 2..10_000 {
        let c = dir.join(format!("{base} ({n}){ext}"));
        if !c.exists() {
            return c;
        }
    }
    // Pathological: fall back to a random suffix.
    dir.join(format!("{base}.{:08x}{ext}", rand::random::<u32>()))
}

/// "photo (3)" -> "photo"; "photo" -> "photo" (official withCount regex).
fn strip_count_suffix(stem: &str) -> &str {
    let Some(open) = stem.rfind(" (") else {
        return stem;
    };
    let inner = &stem[open + 2..];
    if inner.ends_with(')')
        && inner.len() > 1
        && inner[..inner.len() - 1].bytes().all(|b| b.is_ascii_digit())
    {
        &stem[..open]
    } else {
        stem
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_is_stripped() {
        assert_eq!(sanitize_file_name("../../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("/etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\..\\boot.ini"), "boot.ini");
        assert_eq!(sanitize_file_name("C:\\Windows\\evil.exe"), "evil.exe");
    }

    #[test]
    fn dot_and_empty_names_become_unnamed() {
        assert_eq!(sanitize_file_name(""), "unnamed");
        assert_eq!(sanitize_file_name("."), "unnamed");
        assert_eq!(sanitize_file_name(".."), "unnamed");
        assert_eq!(sanitize_file_name("   "), "unnamed");
        assert_eq!(sanitize_file_name("..."), "unnamed");
        assert_eq!(sanitize_file_name("a/"), "unnamed");
    }

    #[test]
    fn control_chars_removed() {
        assert_eq!(sanitize_file_name("evil\0.txt"), "evil.txt");
        assert_eq!(sanitize_file_name("a\r\nb.txt"), "ab.txt");
        assert_eq!(sanitize_file_name("tab\tname.txt"), "tabname.txt");
    }

    #[test]
    fn bidi_override_removed() {
        // "invoice_[U+202E]txt.exe" renders as "invoice_exe.txt" in terminals
        assert_eq!(sanitize_file_name("invoice_\u{202E}txt.exe"), "invoice_txt.exe");
    }

    #[test]
    fn windows_invalid_chars_replaced() {
        assert_eq!(sanitize_file_name("a:b?c*d.txt"), "a_b_c_d.txt");
        assert_eq!(sanitize_file_name("<video>|clip.mp4"), "_video__clip.mp4");
    }

    #[test]
    fn reserved_names_prefixed() {
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("con.txt"), "_con.txt");
        assert_eq!(sanitize_file_name("NUL.tar.gz"), "_NUL.tar.gz");
        assert_eq!(sanitize_file_name("console.txt"), "console.txt"); // not reserved
    }

    #[test]
    fn trailing_dots_and_spaces_trimmed() {
        assert_eq!(sanitize_file_name("report.pdf. "), "report.pdf");
        assert_eq!(sanitize_file_name(" report.pdf"), "report.pdf");
    }

    #[test]
    fn dotfiles_survive() {
        assert_eq!(sanitize_file_name(".bashrc"), ".bashrc");
        assert_eq!(sanitize_file_name("dir/.env"), ".env");
    }

    #[test]
    fn unicode_names_survive() {
        assert_eq!(sanitize_file_name("写真 🎉.png"), "写真 🎉.png");
        assert_eq!(sanitize_file_name("ملف.txt"), "ملف.txt");
    }

    #[test]
    fn long_names_truncated_with_ext() {
        let long = format!("{}.tar.gz", "x".repeat(300));
        let out = sanitize_file_name(&long);
        assert!(out.len() <= MAX_NAME_BYTES);
        assert!(out.ends_with(".gz"));
        let long_utf8 = format!("{}.png", "é".repeat(200)); // 2-byte chars
        let out = sanitize_file_name(&long_utf8);
        assert!(out.len() <= MAX_NAME_BYTES);
        assert!(out.ends_with(".png"));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn dedup_matches_official_pattern() {
        // Official app: first collision becomes " (2)", not " (1)".
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        assert_eq!(
            dedup_path(dir.path(), "a.txt").file_name().unwrap(),
            "a (2).txt"
        );
        std::fs::write(dir.path().join("a (2).txt"), b"x").unwrap();
        assert_eq!(
            dedup_path(dir.path(), "a.txt").file_name().unwrap(),
            "a (3).txt"
        );
        // existing " (N)" suffix is replaced, not nested
        std::fs::write(dir.path().join("b (7).txt"), b"x").unwrap();
        assert_eq!(
            dedup_path(dir.path(), "b (7).txt").file_name().unwrap(),
            "b (2).txt"
        );
        // no extension
        std::fs::write(dir.path().join("README"), b"x").unwrap();
        assert_eq!(
            dedup_path(dir.path(), "README").file_name().unwrap(),
            "README (2)"
        );
        // " (x)" is not a counter suffix
        std::fs::write(dir.path().join("c (x).txt"), b"x").unwrap();
        assert_eq!(
            dedup_path(dir.path(), "c (x).txt").file_name().unwrap(),
            "c (x) (2).txt"
        );
    }
}
