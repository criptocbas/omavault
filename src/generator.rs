use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::hardening::fill_random;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// Ambiguous characters excluded when `exclude_ambiguous` is set.
const AMBIGUOUS: &[u8] = b"Il1O0|`'\"";

/// Curated 256-word high-clarity Diceware wordlist (8 bits of entropy per word).
/// 6 words = 48 bits, 8 words = 64 bits, 10 words = 80 bits (+ separator/digits).
const WORDLIST: &[&str] = &[
    "abacus", "acorn", "admiral", "agate", "albatross", "alchemy", "alder", "almond",
    "alpine", "amber", "anchor", "anemone", "antler", "anvil", "apricot", "archway",
    "arctic", "armada", "arrow", "aspen", "asteroid", "atlas", "aurora", "avalanche",
    "azimuth", "badger", "ballast", "bamboo", "banjo", "banyan", "barley", "basalt",
    "bastion", "beacon", "beaver", "beehive", "belfry", "beryl", "bison", "blizzard",
    "blossom", "boulder", "bramble", "breeze", "briar", "brigade", "bristle", "bronze",
    "buckler", "buffalo", "bulwark", "burrow", "cactus", "cairn", "caldera", "caliper",
    "camber", "canopy", "canyon", "capstan", "caravan", "carbon", "caribou", "cascade",
    "cashew", "castle", "catapult", "cavern", "cedar", "celadon", "chalice", "chamois",
    "chariot", "chestnut", "chimney", "chisel", "cinder", "citadel", "citrine", "clapper",
    "clarinet", "cliff", "clover", "cobalt", "cobble", "cockatoo", "compass", "condor",
    "conifer", "copper", "coral", "corbel", "cornet", "corsair", "cottage", "cougar",
    "courier", "cradle", "crane", "crater", "crevice", "crimson", "crocus", "crossbow",
    "crucible", "crystal", "culvert", "cupola", "current", "cutlass", "cyclone", "cypress",
    "dagger", "dahlia", "damask", "dandelion", "daybreak", "delta", "dervish", "desert",
    "diadem", "diamond", "dinghy", "dolphin", "domino", "donjon", "dormouse", "dragon",
    "drifter", "drizzle", "drumlin", "dune", "dynamo", "eagle", "eclipse", "eddy",
    "edelweiss", "egret", "elder", "ember", "emerald", "emperor", "enclave", "engine",
    "equinox", "ermine", "estuary", "evergreen", "falcon", "fathom", "feather", "feldspar",
    "fennel", "ferret", "fiddle", "figment", "filigree", "finch", "firefly", "fjord",
    "flagon", "flannel", "flint", "flotsam", "flurry", "foliage", "forager", "fortress",
    "fossil", "fountain", "foxhound", "frigate", "frost", "fulcrum", "furnace", "galleon",
    "garland", "garnet", "garrison", "gazelle", "geyser", "gibbon", "ginger", "glacier",
    "glider", "glimmer", "goblet", "gondola", "goshawk", "granite", "grapple", "gravel",
    "griffin", "grotto", "grouse", "gryphon", "halberd", "halcyon", "hammock", "harbor",
    "harrier", "harvest", "hawthorn", "hazelnut", "heather", "hedgehog", "helios", "hemlock",
    "herald", "heron", "hickory", "highland", "horizon", "hornet", "hummock", "hurricane",
    "hyacinth", "ibex", "iceberg", "iguana", "impala", "indigo", "ingot", "inlet",
    "isthmus", "ivory", "jacinth", "jackal", "jaguar", "jasper", "javelin", "juniper",
    "kestrel", "keystone", "kiln", "kingfisher", "knapsack", "kracken", "labyrinth", "lagoon",
    "lamprey", "lancet", "lantern", "lapwing", "larch", "lariat", "larkspur", "lattice",
    "laurel", "lavender", "leopard", "lichen", "lighthouse", "lilac", "limestone", "linden",
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
            words: 8,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        }
    }
}

/// Draw a uniform random `usize` in `0..upper` using CSPRNG rejection sampling
/// (strictly zero modulo bias).
fn csprng_index(upper: usize) -> Result<usize> {
    if upper == 0 {
        return Err(VaultError::Crypto("empty alphabet for generator".into()));
    }
    if upper == 1 {
        return Ok(0);
    }
    let upper_u64 = upper as u64;
    let zone = u64::MAX - (u64::MAX % upper_u64);
    let mut buf = [0u8; 8];
    loop {
        fill_random(&mut buf)?;
        let candidate = u64::from_le_bytes(buf);
        if candidate < zone {
            return Ok((candidate % upper_u64) as usize);
        }
    }
}

/// Generate a high-entropy random password using OS CSPRNG + unbiased rejection sampling.
/// Guarantees at least one character from each enabled character class, then performs a
/// CSPRNG Fisher-Yates shuffle.
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

    // Guarantee at least one character from each enabled class.
    for class in &classes {
        if chars.len() < opts.length {
            let idx = csprng_index(class.len())?;
            chars.push(class[idx]);
        }
    }

    // Fill remainder uniformly from full alphabet.
    while chars.len() < opts.length {
        let idx = csprng_index(full_alphabet.len())?;
        chars.push(full_alphabet[idx]);
    }

    // CSPRNG Fisher-Yates shuffle so guaranteed class positions are unpredictable.
    for i in (1..chars.len()).rev() {
        let j = csprng_index(i + 1)?;
        chars.swap(i, j);
    }

    let password = String::from_utf8(chars.to_vec())
        .map_err(|_| VaultError::Crypto("non-UTF8 generated password".into()))?;
    Ok(Zeroizing::new(password))
}

/// Generate a Diceware-style memorable passphrase using OS CSPRNG.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if opts.words < 4 || opts.words > 24 {
        return Err(VaultError::InvalidFormat(
            "passphrase word count must be between 4 and 24".into(),
        ));
    }

    let mut parts: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let idx = csprng_index(WORDLIST.len())?;
        let mut word = WORDLIST[idx].to_string();
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
        parts[target].push_str(&format!("{num:02}"));
    }

    Ok(Zeroizing::new(parts.join(&opts.separator)))
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

/// Estimate password entropy in bits based on observed character pool size and length.
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
        pool += 32.0;
    }
    if has_non_ascii {
        pool += 64.0;
    }
    if pool <= 1.0 {
        return 0.0;
    }

    // Penalize obvious repetition (e.g., "aaaaaaaaaaaa").
    let unique_chars = {
        let mut chars: Vec<char> = password.chars().collect();
        chars.sort_unstable();
        chars.dedup();
        chars.len()
    };
    let effective_len = (password.chars().count() as f64)
        .min((unique_chars as f64) * 2.5);

    effective_len * pool.log2()
}

pub fn strength_label(bits: f64) -> &'static str {
    if bits < 40.0 {
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
        assert!(estimate_entropy_bits(&pw) >= 100.0);
    }

    #[test]
    fn generates_diceware_passphrase() {
        assert_eq!(WORDLIST.len(), 256);
        let phrase = generate_passphrase(&PassphraseOptions::default()).expect("passphrase");
        assert_eq!(phrase.split('-').count(), 8);
    }
}
