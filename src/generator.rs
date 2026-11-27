use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::hardening::fill_random;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// Ambiguous characters excluded when `exclude_ambiguous` is set.
const AMBIGUOUS: &[u8] = b"Il1O0|`'\"";

/// Common weak substrings penalized during offline password strength estimation.
const COMMON_WEAK_PATTERNS: &[&str] = &[
    "password", "passw0rd", "qwerty", "letmein", "admin", "welcome", "iloveyou", "monkey",
    "dragon", "baseball", "football", "shadow", "master", "trustno1", "abc123", "123456", "654321",
    "000000", "111111", "correct", "horse", "battery", "staple",
];

/// Curated 256-word high-clarity Diceware wordlist (8.0 bits of entropy per word).
const WORDLIST: &[&str] = &[
    "abacus",
    "acorn",
    "admiral",
    "agate",
    "albatross",
    "alchemy",
    "alder",
    "almond",
    "alpine",
    "amber",
    "anchor",
    "anemone",
    "antler",
    "anvil",
    "apricot",
    "archway",
    "arctic",
    "armada",
    "arrow",
    "aspen",
    "asteroid",
    "atlas",
    "aurora",
    "avalanche",
    "azimuth",
    "badger",
    "ballast",
    "bamboo",
    "banjo",
    "banyan",
    "barley",
    "basalt",
    "bastion",
    "beacon",
    "beaver",
    "beehive",
    "belfry",
    "beryl",
    "bison",
    "blizzard",
    "blossom",
    "boulder",
    "bramble",
    "breeze",
    "briar",
    "brigade",
    "bristle",
    "bronze",
    "buckler",
    "buffalo",
    "bulwark",
    "burrow",
    "cactus",
    "cairn",
    "caldera",
    "caliper",
    "camber",
    "canopy",
    "canyon",
    "capstan",
    "caravan",
    "carbon",
    "caribou",
    "cascade",
    "cashew",
    "castle",
    "catapult",
    "cavern",
    "cedar",
    "celadon",
    "chalice",
    "chamois",
    "chariot",
    "chestnut",
    "chimney",
    "chisel",
    "cinder",
    "citadel",
    "citrine",
    "clapper",
    "clarinet",
    "cliff",
    "clover",
    "cobalt",
    "cobble",
    "cockatoo",
    "compass",
    "condor",
    "conifer",
    "copper",
    "coral",
    "corbel",
    "cornet",
    "corsair",
    "cottage",
    "cougar",
    "courier",
    "cradle",
    "crane",
    "crater",
    "crevice",
    "crimson",
    "crocus",
    "crossbow",
    "crucible",
    "crystal",
    "culvert",
    "cupola",
    "current",
    "cutlass",
    "cyclone",
    "cypress",
    "dagger",
    "dahlia",
    "damask",
    "dandelion",
    "daybreak",
    "delta",
    "dervish",
    "desert",
    "diadem",
    "diamond",
    "dinghy",
    "dolphin",
    "domino",
    "donjon",
    "dormouse",
    "dragon",
    "drifter",
    "drizzle",
    "drumlin",
    "dune",
    "dynamo",
    "eagle",
    "eclipse",
    "eddy",
    "edelweiss",
    "egret",
    "elder",
    "ember",
    "emerald",
    "emperor",
    "enclave",
    "engine",
    "equinox",
    "ermine",
    "estuary",
    "evergreen",
    "falcon",
    "fathom",
    "feather",
    "feldspar",
    "fennel",
    "ferret",
    "fiddle",
    "figment",
    "filigree",
    "finch",
    "firefly",
    "fjord",
    "flagon",
    "flannel",
    "flint",
    "flotsam",
    "flurry",
    "foliage",
    "forager",
    "fortress",
    "fossil",
    "fountain",
    "foxhound",
    "frigate",
    "frost",
    "fulcrum",
    "furnace",
    "galleon",
    "garland",
    "garnet",
    "garrison",
    "gazelle",
    "geyser",
    "gibbon",
    "ginger",
    "glacier",
    "glider",
    "glimmer",
    "goblet",
    "gondola",
    "goshawk",
    "granite",
    "grapple",
    "gravel",
    "griffin",
    "grotto",
    "grouse",
    "gryphon",
    "halberd",
    "halcyon",
    "hammock",
    "harbor",
    "harrier",
    "harvest",
    "hawthorn",
    "hazelnut",
    "heather",
    "hedgehog",
    "helios",
    "hemlock",
    "herald",
    "heron",
    "hickory",
    "highland",
    "horizon",
    "hornet",
    "hummock",
    "hurricane",
    "hyacinth",
    "ibex",
    "iceberg",
    "iguana",
    "impala",
    "indigo",
    "ingot",
    "inlet",
    "isthmus",
    "ivory",
    "jacinth",
    "jackal",
    "jaguar",
    "jasper",
    "javelin",
    "juniper",
    "kestrel",
    "keystone",
    "kiln",
    "kingfisher",
    "knapsack",
    "kracken",
    "labyrinth",
    "lagoon",
    "lamprey",
    "lancet",
    "lantern",
    "lapwing",
    "larch",
    "lariat",
    "larkspur",
    "lattice",
    "laurel",
    "lavender",
    "leopard",
    "lichen",
    "lighthouse",
    "lilac",
    "limestone",
    "linden",
];

#[derive(Debug, Clone)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 12,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        }
    }
}

/// Draw a uniform random `usize` in `0..upper` using CSPRNG rejection sampling
/// (strictly zero modulo bias) with zeroized stack RNG buffer.
fn csprng_index(upper: usize) -> Result<usize> {
    if upper == 0 {
        return Err(VaultError::Crypto("empty alphabet for generator".into()));
    }
    if upper == 1 {
        return Ok(0);
    }
    let upper_u64 = upper as u64;
    let zone = u64::MAX - (u64::MAX % upper_u64);
    let mut buf = Zeroizing::new([0u8; 8]);
    loop {
        fill_random(&mut *buf)?;
        let candidate = u64::from_le_bytes(*buf);
        if candidate < zone {
            return Ok((candidate % upper_u64) as usize);
        }
    }
}

/// Generate a high-entropy random password using unbiased uniform rejection sampling over
/// the full enabled alphabet until every enabled character class is represented.
///
/// Unlike forced-first-char + shuffle, pure rejection sampling produces an exact uniform
/// distribution over all valid passwords with zero class-frequency bias.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    if opts.length < 8 || opts.length > 256 {
        return Err(VaultError::InvalidFormat(
            "password length must be between 8 and 256".into(),
        ));
    }

    let filter = |class: &[u8]| -> Vec<u8> {
        class
            .iter()
            .copied()
            .filter(|c| !opts.exclude_ambiguous || !AMBIGUOUS.contains(c))
            .collect()
    };

    let mut classes: Vec<Vec<u8>> = Vec::new();
    if opts.lowercase {
        classes.push(filter(LOWER));
    }
    if opts.uppercase {
        classes.push(filter(UPPER));
    }
    if opts.digits {
        classes.push(filter(DIGITS));
    }
    if opts.symbols {
        classes.push(filter(SYMBOLS));
    }

    classes.retain(|c| !c.is_empty());
    if classes.is_empty() {
        return Err(VaultError::InvalidFormat(
            "at least one character class must be enabled".into(),
        ));
    }

    let mut full_alphabet: Vec<u8> = Vec::new();
    for class in &classes {
        full_alphabet.extend_from_slice(class);
    }

    let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(opts.length));
    loop {
        chars.clear();
        for _ in 0..opts.length {
            let idx = csprng_index(full_alphabet.len())?;
            chars.push(full_alphabet[idx]);
        }
        let all_present = classes
            .iter()
            .all(|class| chars.iter().any(|ch| class.contains(ch)));
        if all_present {
            break;
        }
    }

    let owned = std::mem::take(&mut *chars);
    let password = String::from_utf8(owned)
        .map_err(|_| VaultError::Crypto("non-UTF8 generated password".into()))?;
    Ok(Zeroizing::new(password))
}

/// Exact mathematical entropy (in bits) of a password generated with `opts`.
pub fn generated_password_entropy_bits(opts: &PasswordOptions) -> f64 {
    let count_class = |class: &[u8]| -> usize {
        class
            .iter()
            .filter(|c| !opts.exclude_ambiguous || !AMBIGUOUS.contains(c))
            .count()
    };
    let mut pool = 0usize;
    if opts.lowercase {
        pool += count_class(LOWER);
    }
    if opts.uppercase {
        pool += count_class(UPPER);
    }
    if opts.digits {
        pool += count_class(DIGITS);
    }
    if opts.symbols {
        pool += count_class(SYMBOLS);
    }
    if pool <= 1 {
        return 0.0;
    }
    (opts.length as f64) * (pool as f64).log2()
}

/// Generate a Diceware-style memorable passphrase using OS CSPRNG with zeroized intermediates.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if opts.words < 10 || opts.words > 24 {
        return Err(VaultError::InvalidFormat(
            "passphrase word count must be between 10 and 24 (256-word list = 8 bits/word; recommend >= 12)".into(),
        ));
    }

    let mut parts: Vec<Zeroizing<String>> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let idx = csprng_index(WORDLIST.len())?;
        let raw_word = WORDLIST[idx];
        // Pre-allocate +2 bytes so optional 2-digit suffix never reallocates/frees an unzeroized prefix.
        let mut word = Zeroizing::new(String::with_capacity(raw_word.len() + 2));
        word.push_str(raw_word);
        if opts.capitalize {
            if let Some(first) = word.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
        }
        parts.push(word);
    }

    if opts.include_number {
        let target = csprng_index(parts.len())?;
        let num = csprng_index(100)?;
        let suffix = Zeroizing::new(format!("{num:02}"));
        parts[target].push_str(&suffix);
    }

    let total_len: usize = parts.iter().map(|p| p.len()).sum::<usize>()
        + opts.separator.len() * opts.words.saturating_sub(1);
    let mut joined = Zeroizing::new(String::with_capacity(total_len));
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            joined.push_str(&opts.separator);
        }
        joined.push_str(part);
    }
    Ok(joined)
}

/// Exact mathematical Shannon entropy (in bits) of a Diceware passphrase generated
/// from `WORDLIST` (256 words = 8.0 bits/word) plus optional 2-digit number placement.
pub fn passphrase_entropy_bits(opts: &PassphraseOptions) -> f64 {
    let mut bits = (opts.words as f64) * (WORDLIST.len() as f64).log2();
    if opts.include_number {
        bits += 100.0_f64.log2() + (opts.words.max(1) as f64).log2();
    }
    bits
}

/// Estimate password entropy in bits with conservative penalties for common patterns,
/// sequential runs, years, and low character diversity (zeroizes temporary char buffers).
pub fn estimate_entropy_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_non_ascii = false;

    for ch in password.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch.is_ascii() {
            has_symbol = true;
        } else {
            has_non_ascii = true;
        }
    }

    let mut pool: f64 = 0.0;
    if has_lower {
        pool += 26.0;
    }
    if has_upper {
        pool += 26.0;
    }
    if has_digit {
        pool += 10.0;
    }
    if has_symbol {
        pool += SYMBOLS.len() as f64; // accurate 24-symbol pool
    }
    if has_non_ascii {
        pool += 64.0;
    }
    if pool <= 1.0 {
        return 0.0;
    }

    // Pre-allocate exact upper-bound capacity before filling so Vec/String never reallocs unzeroized prefixes.
    let mut chars = Zeroizing::new(Vec::with_capacity(password.len()));
    chars.extend(password.chars());
    let char_len = chars.len();

    // Count sequential/repeated transitions (e.g. "abcd", "1234", "aaaa").
    let mut non_sequential_transitions = 1usize;
    for win in chars.windows(2) {
        let a = win[0] as i32;
        let b = win[1] as i32;
        let diff = (b - a).abs();
        if diff > 1 {
            non_sequential_transitions += 1;
        }
    }

    chars.sort_unstable();
    chars.dedup();
    let unique_chars = chars.len();
    drop(chars);

    let effective_len = (char_len as f64)
        .min((unique_chars as f64) * 2.0)
        .min((non_sequential_transitions as f64) * 1.5);

    let mut bits = effective_len * pool.log2();

    // Penalize common dictionary/keyboard patterns (case-insensitive & basic leetspeak).
    let mut normalized = Zeroizing::new(String::with_capacity(password.len()));
    for c in password.chars() {
        normalized.push(match c.to_ascii_lowercase() {
            '@' => 'a',
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '$' | '5' => 's',
            '7' => 't',
            other => other,
        });
    }
    let mut lower = Zeroizing::new(String::with_capacity(password.len()));
    for c in password.chars() {
        lower.push(c.to_ascii_lowercase());
    }
    for pat in COMMON_WEAK_PATTERNS {
        if lower.contains(pat) || normalized.contains(pat) {
            bits *= 0.45;
            break;
        }
    }

    bits
}

pub fn strength_label(bits: f64) -> &'static str {
    if bits <= 0.0 {
        "EMPTY"
    } else if bits < 40.0 {
        "WEAK"
    } else if bits < 60.0 {
        "FAIR"
    } else if bits < 80.0 {
        "STRONG"
    } else if bits < 110.0 {
        "VERY STRONG"
    } else {
        "BULLETPROOF"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_strong_password_with_all_classes() {
        let opts = PasswordOptions::default();
        let pw = generate_password(&opts).expect("generate password");
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| SYMBOLS.contains(&(c as u8))));
        assert!(generated_password_entropy_bits(&opts) >= 140.0);
    }

    #[test]
    fn generates_diceware_passphrase_and_rejects_short() {
        assert_eq!(WORDLIST.len(), 256);
        let phrase = generate_passphrase(&PassphraseOptions::default()).expect("passphrase");
        assert_eq!(phrase.split('-').count(), 12);

        assert!(generate_passphrase(&PassphraseOptions {
            words: 8,
            ..PassphraseOptions::default()
        })
        .is_err());
    }

    #[test]
    fn penalizes_common_weak_passwords_accurately() {
        assert!(estimate_entropy_bits("Password123!") < 50.0);
        assert!(estimate_entropy_bits("P@ssw0rd2024!") < 50.0);
        assert!(estimate_entropy_bits("1234567890Ab!") < 50.0);
        assert_eq!(strength_label(estimate_entropy_bits("")), "EMPTY");
    }
}
