use serde::Serialize;
use std::any::Any;

pub(crate) trait DetailValue<T: Default + 'static> {
    fn value(&self) -> T;
    fn set(&mut self, val: T);
    fn offset(&self) -> usize;
    fn len(&self) -> u32;
    fn as_any(&self) -> &dyn Any;
    fn get_value_light(&self) -> Option<&ValueLight<T>>;
    fn get_value_full(&self) -> Option<&ValueFull<T>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ValueFull<T: Default> {
    pub value: T,
    pub offset: usize,
    pub len: u32,
}

impl<T: Default + Clone + 'static> DetailValue<T> for ValueFull<T> {
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
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn get_value_light(&self) -> Option<&ValueLight<T>> {
        None
    }
    fn get_value_full(&self) -> Option<&ValueFull<T>> {
        Some(self)
    }
}

impl<T: Default> ValueFull<T> {
    pub fn new(value: T, offset: usize) -> Self {
        Self::new_with_len(value, offset, std::mem::size_of::<T>() as u32)
    }

    pub fn new_with_len(value: T, offset: usize, len: u32) -> Self {
        Self { value, offset, len }
    }
}

impl<T: Default> Default for ValueFull<T> {
    fn default() -> Self {
        Self {
            value: T::default(),
            offset: 0,
            len: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct ValueLight<T: Default> {
    pub value: T,
}

impl<T: Default> ValueLight<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Default + Clone + 'static> DetailValue<T> for ValueLight<T> {
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
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn get_value_light(&self) -> Option<&ValueLight<T>> {
        Some(self)
    }
    fn get_value_full(&self) -> Option<&ValueFull<T>> {
        None
    }
}

#[macro_export]
macro_rules! make_file_offset_structs {
    (
        $class_name_preamble:ident,
        $($element: ident: $type: ty),*
    ) => {
        paste::item!{
            #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
            pub struct [<$class_name_preamble Light>] { $($element: ValueLight<$type>),* }

            #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
            pub struct [<$class_name_preamble Full>]  { $($element: ValueFull<$type>),* }

            #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
            pub enum [<$class_name_preamble Enum>]  {
                Light(Box<[<$class_name_preamble Light>]>),
                Full(Box<[<$class_name_preamble Full>]>),
            }

            impl [<$class_name_preamble Enum>] {
                $(
                    pub fn $element(&self) -> $type {
                        match self {
                            Self::Light(detail) => detail.$element.value.clone(),
                            Self::Full(detail) => detail.$element.value.clone(),
                        }
                    }

                    paste::item! {
                        pub(crate) fn [< set_ $element >] (&mut self, val: &dyn DetailValue<$type>) {
                            match self {
                                Self::Light(detail) => detail.$element = val.get_value_light().expect("explicitly calling this on a light object").clone(),
                                Self::Full(detail) => detail.$element = val.get_value_full().expect("explicitly calling this on a full object").clone(),
                            }
                        }
                    }
                )*
            }

            impl Default for [<$class_name_preamble Enum>] {
                fn default() -> Self {
                    Self::Light(Box::new([<$class_name_preamble Light>]::default()))
                }
            }
        }
    }
}

// ex: impl_read_value_offset_length! { input, start_pos_ptr, get_offset_info, detail_enum, flags, u16, le_u16 }
#[macro_export]
macro_rules! impl_read_value_offset_length {
    (
        $input: ident,
        $start_pos: ident,
        $get_offset_info: ident,
        $detail_enum: ident,
        $var: ident,
        $var_type: ident,
        $nom_fn: ident
    ) => {
        let $var: Box<dyn DetailValue<$var_type>>;
        let cur_offset;
        if $get_offset_info {
            cur_offset = $input.as_ptr() as usize;
        } else {
            cur_offset = 0; // cur_offset isn't used if !$get_offset_info
        }

        let ($input, val) = $nom_fn($input)?;
        if $get_offset_info {
            $var = Box::new(ValueFull::<$var_type>::new(val, cur_offset - $start_pos));
        } else {
            $var = Box::new(ValueLight::new(val));
        }

        // ex: detail_enum.set_flags(&*flags)
        paste::item! {
            $detail_enum.[< set_ $var >](&*$var);
        }
    };
}

#[macro_export]
macro_rules! init_value_enum {
    (
        $class_name_preamble:ident,
        $enum_var:ident,
        $get_offset_info:ident
    ) => {
        paste::item!{
            let mut $enum_var: [<$class_name_preamble Enum>];
            if $get_offset_info {
                $enum_var = [<$class_name_preamble Enum>]::Full(Box::new([<$class_name_preamble Full>]::default()));
            } else {
                $enum_var = [<$class_name_preamble Enum>]::Light(Box::new([<$class_name_preamble Light>]::default()));
            }
        }
    };
}
