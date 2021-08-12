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
use std::cmp::Ordering;

use chrono::{DateTime, Datelike, Timelike, Utc};
use pyo3::types::{PyDateTime, PyString};
use pyo3::ToPyObject;
use pyo3::{PyObject, PyResult, Python};
use pyo3_file::PyFileLikeObject;

#[derive(Debug)]
pub enum FileOrFileLike {
    File(String),
    FileLike(PyFileLikeObject),
}

#[derive(Debug)]
pub enum Output {
    Python,
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
}

// below from pymft - add attribution
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

fn nanos_to_micros_round_half_even(nanos: u32) -> u32 {
    let nanos_e7 = (nanos % 1000) / 100;
    let nanos_e6 = (nanos % 10000) / 1000;
    let mut micros = (nanos / 10000) * 10;
    match nanos_e7.cmp(&5) {
        Ordering::Greater => micros += nanos_e6 + 1,
        Ordering::Less => micros += nanos_e6,
        Ordering::Equal => micros += nanos_e6 + (nanos_e6 % 2),
    }
    micros
}

pub fn date_to_pyobject(date: &DateTime<Utc>) -> PyResult<PyObject> {
    let gil = Python::acquire_gil();
    let py = gil.python();
    PyDateTime::new(
        py,
        date.year(),
        date.month() as u8,
        date.day() as u8,
        date.hour() as u8,
        date.minute() as u8,
        date.second() as u8,
        nanos_to_micros_round_half_even(date.timestamp_subsec_nanos()),
        None,
    )
    .map(|dt| dt.to_object(py))
}

pub fn get_utc() -> PyResult<PyObject> {
    let gil = Python::acquire_gil();
    let py = gil.python();

    let datetime = py.import("datetime")?;
    let tz: PyObject = datetime.get("timezone")?.into();
    let utc = tz.getattr(py, "utc")?;

    Ok(utc)
}

/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nanos_to_micros_round_half_even() {
        assert_eq!(nanos_to_micros_round_half_even(764026300), 764026);
        assert_eq!(nanos_to_micros_round_half_even(764026600), 764027);
        assert_eq!(nanos_to_micros_round_half_even(764026500), 764026);
        assert_eq!(nanos_to_micros_round_half_even(764027500), 764028);
    }
}*/
