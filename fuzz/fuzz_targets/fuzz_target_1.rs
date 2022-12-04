#![no_main]

use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};

extern crate grex;

use grex::RegExpBuilder;

#[derive(Arbitrary, Debug, Clone)]
struct ByteString<'a> {
    bytes: &'a [u8],
}

impl<'a> Into<String> for ByteString<'a> {
    fn into(self) -> String {
        String::from_utf8_lossy(self.bytes).to_string()
    }
}

#[derive(Arbitrary, Debug)]
struct TestInput<'a> {
    data: Vec<ByteString<'a>>,

    with_conversion_of_digits: bool,
    with_conversion_of_non_digits: bool,
    with_conversion_of_whitespace: bool,
    with_conversion_of_non_whitespace: bool,
    with_conversion_of_words: bool,
    with_conversion_of_non_words: bool,
    with_conversion_of_repetitions: bool,
    with_case_insensitive_matching: bool,
    with_capturing_groups: bool,
    with_verbose_mode: bool,
    without_start_anchor: bool,
    without_end_anchor: bool,
    without_anchors: bool,
    with_syntax_highlighting: bool,

    with_minimum_repetitions: Option<u32>,
    with_minimum_substring_length: Option<u32>,
    with_escaping_of_non_ascii_chars: Option<bool>,
}

fuzz_target!(|input: TestInput<'_>| {
    // fuzzed code goes here
    let mut builder = RegExpBuilder::from(&input.data);

    macro_rules! apply_bool {
        ($x:ident) => {{
            if input.$x {
                builder.$x();
            }
        }};
        ($x:ident, $($y:ident),+) => {{
            apply_bool!($x);
            apply_bool!($($y),+);
        }}
    }

    apply_bool!(
        with_conversion_of_digits,
        with_conversion_of_non_digits,
        with_conversion_of_whitespace,
        with_conversion_of_non_whitespace,
        with_conversion_of_words,
        with_conversion_of_non_words,
        with_conversion_of_repetitions,
        with_case_insensitive_matching,
        with_capturing_groups,
        with_verbose_mode,
        without_start_anchor,
        without_end_anchor,
        without_anchors,
        with_syntax_highlighting
    );

    macro_rules! apply_opt {
        ($x:ident) => {{
            if let Some(x) = input.$x {
                builder.$x(x);
            }
        }};
        ($x:ident, $($y:ident),+) => {{
            apply_opt!($x);
            apply_opt!($($y),+);
        }}
    }

    apply_opt!(
        with_minimum_repetitions,
        with_minimum_substring_length,
        with_escaping_of_non_ascii_chars
    );

    let _ = builder.build();
});
