#![no_main]

use libfuzzer_sys::{arbitrary::Arbitrary, arbitrary::Unstructured, arbitrary::Result, fuzz_target};

extern crate grex;

use grex::{RegExpBuilder, RegExpConfig};

const MAX_STRING_LENGTH: usize = 12;
const MAX_VEC_LENGTH: usize = 5;

#[derive(Debug, Clone)]
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
    minimum_repetitions: u32,
    minimum_substring_length: u32,
    is_digit_converted: bool,
    is_non_digit_converted: bool,
    is_space_converted: bool,
    is_non_space_converted: bool,
    is_word_converted: bool,
    is_non_word_converted: bool,
    is_repetition_converted: bool,
    is_capturing_group_enabled: bool,
    is_non_ascii_char_escaped: bool,
    is_astral_code_point_converted_to_surrogate: bool,
    is_start_anchor_disabled: bool,
    is_end_anchor_disabled: bool,
    is_output_colorized: bool,

    #[arbitrary(with = arbitrary_input_data)]
    data: Vec<ByteString<'a>>
}

fn arbitrary_input_data<'a>(u: &mut Unstructured<'a>) -> Result<Vec<ByteString<'a>>> {
    let mut vec = Vec::with_capacity(MAX_VEC_LENGTH);
    while !u.is_empty() && vec.len() < MAX_VEC_LENGTH {
        let bytes_remaining = u.len();
        let max_length = MAX_STRING_LENGTH.min(bytes_remaining);

        let string_size = if vec.len() < MAX_VEC_LENGTH - 1 {
            u.int_in_range(0..=max_length)?
        } else {
            max_length
        };

        let bytes = u.bytes(string_size)?;

        vec.push(ByteString { bytes });
    }

    Ok(vec)
}

fuzz_target!(|input: TestInput<'_>| {
    let mut input = input;

    // fuzzed code goes here
    let input_data = if input.data.is_empty() {
        // we cannot give an empty list of test cases, so instead we create a vector with an empty
        // string
        vec![ByteString { bytes: &[] }]
    } else {
        input.data
    };

    // these are not allowed to be 0
    input.minimum_substring_length = input.minimum_substring_length.max(1);
    input.minimum_repetitions = input.minimum_repetitions.max(1);

    let config = RegExpConfig {
        minimum_repetitions: input.minimum_repetitions,
        minimum_substring_length: input.minimum_substring_length,
        is_digit_converted: input.is_digit_converted,
        is_non_digit_converted: input.is_non_digit_converted,
        is_space_converted: input.is_space_converted,
        is_non_space_converted: input.is_non_space_converted,
        is_word_converted: input.is_word_converted,
        is_non_word_converted: input.is_non_word_converted,
        is_repetition_converted: input.is_repetition_converted,

        // disable for efficiency
        is_case_insensitive_matching: false,

        is_capturing_group_enabled: input.is_capturing_group_enabled,
        is_non_ascii_char_escaped: input.is_non_ascii_char_escaped,
        is_astral_code_point_converted_to_surrogate: input.is_astral_code_point_converted_to_surrogate,

        // disable verbose mode since it's slow
        is_verbose_mode_enabled: false,

        is_start_anchor_disabled: input.is_start_anchor_disabled,
        is_end_anchor_disabled: input.is_end_anchor_disabled,
        is_output_colorized: input.is_output_colorized,
    };

    let mut builder = RegExpBuilder::from(&input_data);
    builder.config = config;

    let _ = builder.build();
});
