/*
 * Copyright 2021 Aon Cyber Solutions
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// Via https://github.com/omerbenamram/mft
#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&format!("{:?}", &self))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_flags_from_bits {
    ($bitflag_type: ident, $var_type: ident) => {
        impl $bitflag_type {
            #[allow(dead_code)]
            pub(crate) fn from_bits_checked(
                flags: $var_type,
                logs: &mut $crate::log::Logs,
            ) -> Self {
                let flags_mapped = $bitflag_type::from_bits_truncate(flags);
                if flags != flags_mapped.bits() {
                    fn f() {}
                    fn type_name_of<T>(_: T) -> &'static str {
                        std::any::type_name::<T>()
                    }
                    let name = type_name_of(f);
                    const FOOTER_LEN: usize = "::f".len();
                    let fn_name = &name[..name.len() - FOOTER_LEN];
                    logs.add(
                        $crate::log::LogCode::WarningUnrecognizedBitflag,
                        &format!("{}: {:#X}", fn_name, flags),
                    );
                }
                return flags_mapped;
            }
        }
    };
}

#[macro_export]
macro_rules! impl_enum_from_value {
    ($enum_type: ident) => {
        impl $enum_type {
            pub(crate) fn from_value(value: u32, logs: &mut Logs) -> Self {
                $enum_type::from_u32(value).unwrap_or_else(|| {
                    logs.add(
                        LogCode::WarningConversion,
                        &format!("Unrecognized {} value", stringify!($enum_type)),
                    );
                    $enum_type::Unknown
                })
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::log::{Log, LogCode, Logs};
    use bitflags::bitflags;

    #[test]
    fn test_from_bits_checked() {
        bitflags! {
            #[derive(Debug, PartialEq)]
            pub struct TestFlags: u16 {
                const TEST_1 = 0x0001;
                const TEST_2 = 0x0002;
                const TEST_3 = 0x0003;
            }
        }
        impl_flags_from_bits! { TestFlags, u16 }

        let flag_bits = 0x0001 | 0x0003;
        let mut logs = Logs::default();
        let flags = TestFlags::from_bits_checked(flag_bits, &mut logs);
        assert_eq!(
            TestFlags::TEST_1 | TestFlags::TEST_3,
            flags,
            "Valid from_bits_checked conversion"
        );
        assert_eq!(
            None,
            logs.get(),
            "Valid from_bits_checked conversion - logs should be empty"
        );

        let flag_bits = 0xffff;
        let flags = TestFlags::from_bits_checked(flag_bits, &mut logs);
        assert_eq!(
            TestFlags::TEST_1 | TestFlags::TEST_2 | TestFlags::TEST_3,
            flags,
            "Unmapped bits from_bits_checked conversion"
        );
        assert_eq!(Some(&vec![
            Log {
                code: LogCode::WarningUnrecognizedBitflag,
                text: "notatin::macros::tests::test_from_bits_checked::TestFlags::from_bits_checked: 0xFFFF".to_string()
            }
        ]), logs.get(), "Unmapped bits from_bits_checked conversion - logs should contain a warning");
    }
}
