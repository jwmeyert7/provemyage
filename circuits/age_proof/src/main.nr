// ProveMyAge -- Age Proof Circuit
// Proves: person's birthdate satisfies a minimum age threshold (and optional maximum)
// without revealing the actual birthdate.
//
// Private inputs:  birth_year, birth_month, birth_day, nullifier_seed
// Public inputs:   threshold dates, face_hash, timestamp, optional upper bound
// Public output:   single-use nullifier = pedersen(nullifier_seed, timestamp, face_hash)

fn main(
    // Private
    birth_year:  u32,
    birth_month: u32,
    birth_day:   u32,
    nullifier_seed: Field,

    // Public: minimum age threshold ("you must be at least this old")
    threshold_year:  pub u32,
    threshold_month: pub u32,
    threshold_day:   pub u32,

    // Public: binding inputs committed to in the proof
    face_hash:         pub Field,
    current_timestamp: pub u64,

    // Public: optional upper bound ("you must be at most this old")
    has_upper_bound: pub bool,
    upper_year:  pub u32,
    upper_month: pub u32,
    upper_day:   pub u32,
) -> pub Field {

    // Basic sanity checks on birth date components
    assert(birth_month >= 1);
    assert(birth_month <= 12);
    assert(birth_day   >= 1);
    assert(birth_day   <= 31);

    // Encode dates as YYYYMMDD integers for magnitude comparison.
    // e.g. 19900315 < 20060315 means born in 1990 is older than born in 2006.
    let birth_encoded:     u32 = birth_year  * 10000 + birth_month  * 100 + birth_day;
    let threshold_encoded: u32 = threshold_year * 10000 + threshold_month * 100 + threshold_day;

    // Core age check: birth_date <= threshold_date.
    // The threshold date is "today minus minimum age", so if the person was
    // born on or before it, they are old enough.
    assert(birth_encoded <= threshold_encoded);

    // Optional upper-bound check.
    // When has_upper_bound is true, the person must also be young enough.
    // Upper bound date = "today minus maximum age".
    // Caller passes (0, 0, 0) when no upper bound is needed, which makes
    // upper_encoded = 0 and the constraint trivially satisfied.
    let upper_encoded: u32 = upper_year * 10000 + upper_month * 100 + upper_day;
    if has_upper_bound {
        assert(birth_encoded >= upper_encoded);
    }

    // Compute single-use nullifier.
    // Binding nullifier_seed (private) + timestamp + face_hash (both public)
    // prevents replay attacks while tying the credential to this exact selfie.
    std::hash::pedersen_hash([nullifier_seed, current_timestamp as Field, face_hash])
}
