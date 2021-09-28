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
use crate::cell_key_node::{AccessFlags, KeyNodeFlags};
use crate::field_offset_len::FieldTrait;
use crate::log::Logs;
use crate::util;
use serde::ser::{Serialize, SerializeStruct, Serializer};

pub(crate) fn field_data_as_hex<S: Serializer>(
    x: &[u8],
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&util::to_hex_string(x))
}

pub(crate) fn field_last_key_written_date_and_time_interpreted<S: Serializer>(
    x: &dyn FieldTrait<u64>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut ser = s.serialize_struct("last_key_written_date_and_time", get_field_count(x))?;
    serialize_base_field(x, &mut ser)?;
    ser.serialize_field(
        "interpreted",
        &util::format_date_time(util::get_date_time_from_filetime(x.value())),
    )?;
    ser.end()
}

pub(crate) fn field_key_node_flag_bits_interpreted<S: Serializer>(
    x: &dyn FieldTrait<u16>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut logs = Logs::default();
    let flags = KeyNodeFlags::from_bits_checked(x.value(), &mut logs);
    let mut ser = s.serialize_struct("key_node_flag_bits", get_field_count_with_logs(x, &logs))?;
    serialize_base_field(x, &mut ser)?;
    ser.serialize_field("interpreted", &format!("{:?}", flags))?;
    if logs.has_logs() {
        ser.serialize_field("logs", &logs.get_string())?;
    }
    ser.end()
}

pub(crate) fn field_acccess_flag_bits_interpreted<S: Serializer>(
    x: &dyn FieldTrait<u32>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut logs = Logs::default();
    let flags = AccessFlags::from_bits_checked(x.value(), &mut logs);
    let mut ser = s.serialize_struct("access_flag_bits", get_field_count_with_logs(x, &logs))?;
    serialize_base_field(x, &mut ser)?;
    ser.serialize_field("interpreted", &format!("{:?}", flags))?;
    if logs.has_logs() {
        ser.serialize_field("logs", &logs.get_string())?;
    }
    ser.end()
}

pub(crate) fn field_value_name_interpreted<S: Serializer>(
    x: &dyn FieldTrait<String>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut ser = s.serialize_struct("value_name", get_field_count(x))?;
    serialize_base_field(x, &mut ser)?;
    ser.serialize_field("interpreted", &util::get_pretty_name(&x.value()))?;
    ser.end()
}

fn get_field_count<T: Default + Clone + Serialize + 'static>(x: &dyn FieldTrait<T>) -> usize {
    if x.get_field_full().is_some() {
        4
    } else {
        2
    }
}

fn get_field_count_with_logs<T: Default + Clone + Serialize + 'static>(
    x: &dyn FieldTrait<T>,
    logs: &Logs,
) -> usize {
    get_field_count(x) + logs.has_logs() as usize // if we have logs then we need an additional field to display them
}

fn serialize_base_field<S: SerializeStruct, T: Default + Clone + Serialize + 'static>(
    x: &dyn FieldTrait<T>,
    ser: &mut S,
) -> Result<(), S::Error> {
    if let Some(full) = x.get_field_full() {
        ser.serialize_field("value", &full.value())?;
        ser.serialize_field("offset", &full.offset())?;
        ser.serialize_field("len", &full.len())
    } else {
        ser.serialize_field("value", &x.value())
    }
}
