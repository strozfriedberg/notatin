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
 *
 */

use log::{Level, Log, Metadata, Record, SetLoggerError};
use std::{cmp::Ordering, fs::File, io::BufReader};

use chrono::{DateTime, Datelike, Timelike, TimeZone, NaiveDateTime, Utc};
use notatin::file_info::ReadSeek;
use pyo3::types::{IntoPyDict, PyDateAccess, PyDateTime, PyString, PyTimeAccess, PyTzInfo};
use pyo3::ToPyObject;
use pyo3::{PyObject, PyResult, Python};
use pyo3_file::PyFileLikeObject;

#[derive(Debug)]
pub enum Output {
    Python,
}

#[derive(Debug)]
pub enum FileOrFileLike {
    File(String),
    FileLike(PyFileLikeObject),
}

impl FileOrFileLike {
    pub fn from_pyobject(path_or_file_like: PyObject) -> PyResult<FileOrFileLike> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        // is a path
        if let Ok(string_ref) = path_or_file_like.cast_as::<PyString>(py) {
            return Ok(FileOrFileLike::File(
                string_ref.to_string_lossy().to_string(),
            ));
        }

        // We only need read + seek
        match PyFileLikeObject::with_requirements(path_or_file_like, true, false, true) {
            Ok(f) => Ok(FileOrFileLike::FileLike(f)),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn to_read_seek(path_or_file_like: &PyObject) -> PyResult<Box<dyn ReadSeek + Send>> {
        match FileOrFileLike::from_pyobject(path_or_file_like.clone())? {
            FileOrFileLike::File(s) => {
                let file = File::open(s)?;
                let reader = BufReader::with_capacity(4096, file);
                Ok(Box::new(reader) as Box<dyn ReadSeek + Send>)
            }
            FileOrFileLike::FileLike(f) => Ok(Box::new(f) as Box<dyn ReadSeek + Send>),
        }
    }
}

fn nanos_to_micros_round_half_even(nanos: u32) -> u32 {
    let nanos_e7 = (nanos % 1_000) / 100;
    let nanos_e6 = (nanos % 10_000) / 1000;
    let mut micros = (nanos / 10_000) * 10;
    match nanos_e7.cmp(&5) {
        Ordering::Greater => micros += nanos_e6 + 1,
        Ordering::Less => micros += nanos_e6,
        Ordering::Equal => micros += nanos_e6 + (nanos_e6 % 2),
    }
    micros
}

fn date_splitter(date: &DateTime<Utc>) -> PyResult<(i64, u32)> {
    let mut unix_time = date.timestamp();
    let mut micros = nanos_to_micros_round_half_even(date.timestamp_subsec_nanos());

    let inc_sec = micros / 1_000_000;
    micros %= 1_000_000;
    unix_time += inc_sec as i64;

    Ok((unix_time, micros))
}

pub fn date_to_pyobject(date: &DateTime<Utc>) -> PyResult<PyObject> {
    let (unix_time, micros) = date_splitter(date)?;

    let gil = Python::acquire_gil();
    let py = gil.python();

    let rounded_date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(unix_time, micros * 1_000), Utc);

    PyDateTime::new(
        py,
        rounded_date.year(),
        rounded_date.month() as u8,
        rounded_date.day() as u8,
        rounded_date.hour() as u8,
        rounded_date.minute() as u8,
        rounded_date.second() as u8,
        rounded_date.timestamp_subsec_micros(),
        None,
    )
    .map(|dt| dt.to_object(py))
}

// Logging implementation from https://github.com/omerbenamram/pymft-rs
/// A logger that prints all messages with a readable output format.
struct PyLogger {
    level: Level,
    warnings_module: PyObject,
}

impl Log for PyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Level::Warn = self.level {
                let level_string = record.level().to_string();
                let gil = Python::acquire_gil();
                let py = gil.python();

                let message = format!(
                    "{:<5} [{}] {}",
                    level_string,
                    record.module_path().unwrap_or_default(),
                    record.args()
                );

                self.warnings_module
                    .call_method(py, "warn", (message,), None)
                    .ok();
            }
        }
    }

    fn flush(&self) {}
}

pub fn init_logging(py: Python) -> Result<(), SetLoggerError> {
    let warnings = py
        .import("warnings")
        .expect("python to have warning module")
        .to_object(py);

    let logger = PyLogger {
        level: Level::Warn,
        warnings_module: warnings,
    };

    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(Level::Warn.to_level_filter());

    Ok(())
}

#[cfg(test)]
mod tests {
    use pyo3::types::{PyDateAccess, PyTimeAccess};

    use super::*;

    #[test]
    fn test_nanos_to_micros_round_half_even() {
        assert_eq!(nanos_to_micros_round_half_even(764_026_300), 764_026);
        assert_eq!(nanos_to_micros_round_half_even(764_026_600), 764_027);
        assert_eq!(nanos_to_micros_round_half_even(764_026_500), 764_026);
        assert_eq!(nanos_to_micros_round_half_even(764_027_500), 764_028);
        assert_eq!(nanos_to_micros_round_half_even(999_999_500), 1_000_000);
    }

    #[test]
    fn test_date_splitter(){
        let tests = [
            ("2020-09-29T17:38:04.9999995Z", (1601401085, 0u32)),
            ("2020-09-29T17:38:04.0000004Z", (1601401084, 0u32)),
            ("2020-09-29T17:38:04.1234567Z", (1601401084, 123457u32)),
            ("2020-12-31T23:59:59.9999995Z", (1609459200, 0u32)),
        ];

        for (test, expected) in tests {
            let dt = DateTime::parse_from_rfc3339(test).unwrap().with_timezone(&Utc);
            let res = date_splitter(&dt).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_date_to_pyobject() {
        let tests = [
            ("2020-09-29T17:38:04.9999995Z", (2020, 9, 29, 17, 38, 5, 0)),
            ("2020-09-29T17:38:04.0000004Z", (2020, 9, 29, 17, 38, 4, 0)),
            ("2020-09-29T17:38:04.1234567Z", (2020, 9, 29, 17, 38, 4, 123457)),
            ("2020-12-31T23:59:59.9999995Z", (2021, 1, 1, 0, 0, 0, 0)),
        ];
        let gil = Python::acquire_gil();
        let py = gil.python();
        for (test, (y, mo, d, h, min, s, us)) in tests {
            let dt = DateTime::parse_from_rfc3339(test).unwrap().with_timezone(&Utc);

            let po = date_to_pyobject(&dt).unwrap();
            let pdt = po.as_ref(py).extract::<&PyDateTime>().unwrap();

            assert_eq!(pdt.get_year(), y);
            assert_eq!(pdt.get_month(), mo);
            assert_eq!(pdt.get_day(), d);
            assert_eq!(pdt.get_hour(), h);
            assert_eq!(pdt.get_minute(), min);
            assert_eq!(pdt.get_second(), s);
            assert_eq!(pdt.get_microsecond(), us);
        }
    }
}