// ProveMyAge -- Age Proof Circuit with Selective Disclosure
// Proves: person's birthdate satisfies a minimum age threshold (and optional maximum)
// without revealing the actual birthdate.
// Optionally discloses: birthdate, exact age, nationality, gender, name.
//
// Private inputs:  birth_year, birth_month, birth_day, nullifier_seed,
//                  nationality_code, gender_code, name_part1, name_part2
// Public inputs:   threshold dates, face_hash, timestamp, optional upper bound,
//                  reference date (for age calc), reveal flags
// Public output:   [nullifier, disclosed_birth_y, disclosed_birth_m, disclosed_birth_d,
//                   disclosed_age, disclosed_nationality, disclosed_gender,
//                   disclosed_name1, disclosed_name2]

fn main(
    // Private
    birth_year:  u32,
    birth_month: u32,
    birth_day:   u32,
    nullifier_seed: Field,
    nationality_code: u32,   // 3 ASCII chars packed: c1*65536 + c2*256 + c3 (e.g. USA = 85*65536+83*256+65)
    gender_code: u32,        // ASCII code: 77='M', 70='F', 0=unspecified
    name_part1: Field,       // First <=31 bytes of "SURNAME<<GIVENNAMES" packed big-endian
    name_part2: Field,       // Remaining bytes (<=31) packed big-endian

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

    // Public: reference date (today) for exact age calculation
    ref_year:  pub u32,
    ref_month: pub u32,
    ref_day:   pub u32,

    // Public: selective disclosure flags
    reveal_birthdate:    pub bool,
    reveal_age:          pub bool,
    reveal_nationality:  pub bool,
    reveal_gender:       pub bool,
    reveal_name:         pub bool,
) -> pub [Field; 9] {

    // Basic sanity checks on birth date components
    assert(birth_month >= 1);
    assert(birth_month <= 12);
    assert(birth_day   >= 1);
    assert(birth_day   <= 31);

    // Encode dates as YYYYMMDD integers for magnitude comparison.
    let birth_encoded:     u32 = birth_year  * 10000 + birth_month  * 100 + birth_day;
    let threshold_encoded: u32 = threshold_year * 10000 + threshold_month * 100 + threshold_day;

    // Core age check: birth_date <= threshold_date.
    assert(birth_encoded <= threshold_encoded);

    // Optional upper-bound check.
    let upper_encoded: u32 = upper_year * 10000 + upper_month * 100 + upper_day;
    if has_upper_bound {
        assert(birth_encoded >= upper_encoded);
    }

    // -- Compute exact age --------------------------------------------------
    // had_birthday_this_year: true if (ref_month, ref_day) >= (birth_month, birth_day)
    let past_month = ref_month > birth_month;
    let same_month = ref_month == birth_month;
    let past_day   = ref_day >= birth_day;
    let had_birthday: bool = past_month | (same_month & past_day);

    let age: u32 = if had_birthday { ref_year - birth_year } else { ref_year - birth_year - 1 };

    // -- Conditional disclosure ---------------------------------------------
    let d_birth_y: Field = if reveal_birthdate { birth_year as Field }  else { 0 };
    let d_birth_m: Field = if reveal_birthdate { birth_month as Field } else { 0 };
    let d_birth_d: Field = if reveal_birthdate { birth_day as Field }   else { 0 };
    let d_age: Field     = if reveal_age { age as Field } else { 0 };
    let d_nat: Field     = if reveal_nationality { nationality_code as Field } else { 0 };
    let d_gen: Field     = if reveal_gender { gender_code as Field } else { 0 };
    let d_name1: Field   = if reveal_name { name_part1 } else { 0 };
    let d_name2: Field   = if reveal_name { name_part2 } else { 0 };

    // -- Compute single-use nullifier ----------------------------------------
    let nullifier = std::hash::pedersen_hash([nullifier_seed, current_timestamp as Field, face_hash]);

    [nullifier, d_birth_y, d_birth_m, d_birth_d, d_age, d_nat, d_gen, d_name1, d_name2]
}
