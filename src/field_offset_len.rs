/*
 * Copyright 2023 Aon Cyber Solutions
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

 use serde::Serialize;

pub(crate) trait FieldTrait<T: Default + 'static> {
    fn value(&self) -> T;
    fn set(&mut self, val: T);
    fn offset(&self) -> usize;
    fn len(&self) -> u32;

    // This trait exists only to support FieldLight and FieldFull, so rather than
    // using a more generic Any/downcast approach to get the specific typed value
    // we instead have these functions
    fn get_field_light(&self) -> Option<&FieldLight<T>>;
    fn get_field_full(&self) -> Option<&FieldFull<T>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FieldFull<T: Default> {
    pub value: T,
    pub offset: usize,
    pub len: u32,
}

impl<T: Default + Clone + 'static> FieldTrait<T> for FieldFull<T> {
    fn value(&self) -> T {
        self.value.clone()
    }
    fn set(&mut self, val: T) {
        self.value = val
    }
    fn offset(&self) -> usize {
        self.offset
    }
    fn len(&self) -> u32 {
        self.len
    }
    fn get_field_light(&self) -> Option<&FieldLight<T>> {
        None
    }
    fn get_field_full(&self) -> Option<&FieldFull<T>> {
        Some(self)
    }
}

impl<T: Default> FieldFull<T> {
    /// This is the standard constructor; it will set len based upon the size of type `T`
    pub fn new(value: T, offset: usize) -> Self {
        Self::new_with_len(value, offset, std::mem::size_of::<T>() as u32)
    }

    /// Allows an explicit size to be set (for example, if T is a Vec)
    pub fn new_with_len(value: T, offset: usize, len: u32) -> Self {
        Self { value, offset, len }
    }
}

impl<T: Default> Default for FieldFull<T> {
    fn default() -> Self {
        Self {
            value: T::default(),
            offset: 0,
            len: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FieldLight<T: Default> {
    pub value: T,
}

impl<T: Default> FieldLight<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Default + Clone + 'static> FieldTrait<T> for FieldLight<T> {
    fn value(&self) -> T {
        self.value.clone()
    }
    fn set(&mut self, val: T) {
        self.value = val
    }
    fn offset(&self) -> usize {
        0
    }
    fn len(&self) -> u32 {
        0
    }
    fn get_field_light(&self) -> Option<&FieldLight<T>> {
        Some(self)
    }
    fn get_field_full(&self) -> Option<&FieldFull<T>> {
        None
    }
}

mod macros {
    #[macro_export]
    macro_rules! make_field_struct {
        ( @$field_type:ident, $name:ident { } -> ($($result:tt)*) ) => (
            #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
            pub struct $name {
                $($result)*
            }
        );

        ( @$field_type:ident, $name:ident { $field:ident : $type:ty, $($tail:tt)* } -> ($($result:tt)*) ) => (
            make_field_struct!(@$field_type, $name { $($tail)* } -> (
                $($result)*
                pub $field : $field_type<$type>,
            ));
        );

        ( @$field_type:ident, $name:ident { $field:ident : $type:ty ; $attribute_macro:meta, $($tail:tt)* } -> ($($result:tt)*) ) => (
            make_field_struct!(@$field_type, $name { $($tail)* } -> (
                $($result)*
                #[$attribute_macro]
                pub $field : $field_type<$type>,
            ));
        );

        /*( @$field_type:ident, $name:ident { $field:ident : $type:ty } -> ($($result:tt)*) ) => (
            make_field_struct!(@$field_type, $name {  } -> (
                $($result)*
                pub $field : $field_type<$type>,
            ));
        );*/

        ( $field_type:ident, $name:ident { $($tail:tt)* } ) => (
            make_field_struct!(@$field_type, $name { $($tail)* } -> ());
        );
    }

    #[macro_export]
    macro_rules! impl_enum {
        ( @$name:ident { } -> ($($result:tt)*) ) => (
            impl $name {
                $($result)*
            }
        );

        ( @$name:ident { $field:ident : $type:ty, $($tail:tt)* } -> ($($result:tt)*) ) => (
            impl_enum!(@$name { $($tail)* } -> (
                $($result)*
                pub fn $field(&self) -> $type {
                    match self {
                        Self::Light(detail) => detail.$field.value.clone(),
                        Self::Full(detail) => detail.$field.value.clone(),
                    }
                }

                paste::item! {
                    // Would love if there was some way to tell if $type was a primitive or not, and therefore whether we should generate
                    // set_field vs. set_field_full.
                    #[allow(dead_code)]
                    #[allow(clippy::ptr_arg)]
                    pub fn [< set_ $field >] (&mut self, val: &$type, offset: usize) {
                        match self {
                            Self::Light(detail) => detail.$field = FieldLight::<$type>::new(val.to_owned()),
                            Self::Full(detail) => detail.$field = FieldFull::<$type>::new(val.to_owned(), offset)
                        }
                    }

                    #[allow(dead_code)]
                    #[allow(clippy::ptr_arg)]
                    pub fn [< set_ $field _full >] (&mut self, val: &$type, offset: usize, len: u32) {
                        match self {
                            Self::Light(detail) => detail.$field = FieldLight::<$type>::new(val.to_owned()),
                            Self::Full(detail) => detail.$field = FieldFull::<$type>::new_with_len(val.to_owned(), offset, len)
                        }
                    }
                }
            ));
        );

        ( @$name:ident { $field:ident : $type:ty; $attribute_macro:meta, $($tail:tt)* } -> ($($result:tt)*) ) => (
            impl_enum!(@$name { $field : $type, $($tail)* } -> ($($result)*));
        );

        ( $name:ident { $($tail:tt)* } ) => (
            impl_enum!(@$name { $($tail)* } -> ());
        );
    }

    /// This macro generates three objects:
    ///     {class_name_prefix}Light: A struct which contains FieldLight objects for each field (value only)
    ///     {class_name_prefix}Full: A struct which contains FieldFull objects for each field (value, offset, and length)
    ///     {class_name_prefix}Enum: An enum with variants for the above two structs
    /// Accessor and setter functions are created on {class_name_prefix}Enum for each field.
    /// A `default()` function is created for {class_name_prefix}Enum which creates a default {class_name_prefix}Light variant
    #[macro_export]
    macro_rules! make_file_offset_structs {
        (
            $class_name_prefix:ident {
            $($tail:tt)*
            }
        ) => {
            paste::item!{
                make_field_struct! ( FieldLight, [<$class_name_prefix Light>] { $($tail)* } );
                make_field_struct! ( FieldFull, [<$class_name_prefix Full>] { $($tail)* } );

                #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
                pub enum [<$class_name_prefix Enum>]  {
                    Light(Box<[<$class_name_prefix Light>]>),
                    Full(Box<[<$class_name_prefix Full>]>),
                }

                impl Default for [<$class_name_prefix Enum>] {
                    fn default() -> Self {
                        Self::Light(Box::default())
                    }
                }

                impl_enum! ( [<$class_name_prefix Enum>] { $($tail)* } );
            }
        }
    }

    /// This macro generates code which uses nom to read the specified data at the current $input.
    /// If $get_full_field_info is true, it will also determine the offset into the current buffer and
    /// the length of the data and generate the appropriate FieldTrait (FieldFull or FieldLight) object.
    /// Finally it will set the field in $struct_enum.
    /// Note that the value is made available outside of the macro in $var to ensure that the
    /// calling code has access to it for additional processing.
    /// Ex: read_value_offset_length! { input, start_pos_ptr, get_full_field_info, detail_enum, key_node_flag_bits, u16, le_u16 }
    #[macro_export]
    macro_rules! read_value_offset_length {
        (
            $input: ident,
            $start_pos: ident,
            $get_full_field_info: ident,
            $struct_enum: ident,
            $var: ident,
            $var_type: ident,
            $nom_fn: ident
        ) => {
            let $var: $var_type;
            let cur_offset;
            if $get_full_field_info {
                cur_offset = $input.as_ptr() as usize - $start_pos;
            } else {
                cur_offset = 0; // cur_offset isn't used if !$get_full_field_info
            }

            let ($input, val) = $nom_fn($input)?;
            $var = val;

            paste::item! {
                // ex: detail_enum.set_key_node_flag_bits(&key_node_flag_bits, cur_offset)
                $struct_enum.[< set_ $var >](&$var, cur_offset);
            }
        };
    }

    /// This macro creates $enum_var of type {$class_name_prefix}Enum
    /// and initializes the appropriate variant depending on the value of $get_full_field_info
    #[macro_export]
    macro_rules! init_value_enum {
        (
            $class_name_prefix:ident,
            $enum_var:ident,
            $get_full_field_info:ident
        ) => {
            paste::item! {
                let mut $enum_var: [<$class_name_prefix Enum>] = if $get_full_field_info {
                    [<$class_name_prefix Enum>]::Full(Box::default())
                } else {
                    [<$class_name_prefix Enum>]::Light(Box::default())
                };
            }
        };
    }
}
