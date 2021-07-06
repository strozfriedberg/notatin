use pyo3::prelude::*;

use crate::err::PyRegError;
use crate::util::date_to_pyobject;
use chrono::{Datelike, DateTime, Timelike, Utc};
use notatin::{
    parser::Parser,
    filter::Filter,
    cell_key_value::{CellKeyValue, CellKeyValueDetail, CellKeyValueFlags, CellKeyValueDataTypes},
    cell_value::CellValue,
    log::Logs,
    util
};
use pyo3::{Py, PyIterProtocol, PyObject, PyResult, Python};

#[pyclass(subclass)]
pub struct PyRegValue {
    inner: CellKeyValue
}

#[pymethods]
impl PyRegValue {
    pub fn value(
        &self,
        py: Python
    ) -> PyObject {
        pyo3::types::PyBytes::new(py, &self.inner.detail.value_bytes.clone().unwrap_or_default()).to_object(py)
    }

    pub fn pretty_name(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.get_pretty_name().to_object(py)
    }

    pub fn name(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.value_name.to_object(py)
    }

    pub fn raw_data_type(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.detail.data_type_raw.to_object(py)
    }

    pub fn data_type(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.detail.data_type_raw.to_object(py)
    }

    pub fn get_content(
        &self,
        py: Python
    ) -> Option<PyObject> {
        let (content, _) = self.inner.get_content();
        match content {
            CellValue::ValueString(content) => Some(content.to_object(py)),
            CellValue::ValueI32(content) => Some(content.to_object(py)),
            CellValue::ValueU32(content) => {
                if self.inner.data_type == CellKeyValueDataTypes::REG_DEVPROP_TYPE_BOOLEAN || self.inner.data_type == CellKeyValueDataTypes::REG_COMPOSITE_BOOLEAN {
                    return Some((content != 0).to_object(py));
                }
                return Some(content.to_object(py));
            },
            CellValue::ValueU64(content) => {
                if self.inner.data_type == CellKeyValueDataTypes::REG_DEVPROP_TYPE_FILETIME {
                    let datetime = util::get_date_time_from_filetime(content);
                    if let Ok(py_datetime) = pyo3::types::PyDateTime::new(
                        py,
                        datetime.year(),
                        datetime.month() as u8,
                        datetime.day() as u8,
                        datetime.hour() as u8,
                        datetime.minute() as u8,
                        datetime.second() as u8,
                        datetime.timestamp_subsec_micros(),
                        None
                    ) {
                        return Some(py_datetime.to_object(py));
                    }
                }
                return Some(content.to_object(py));
            },
            CellValue::ValueI64(content) => Some(content.to_object(py)),
            CellValue::ValueMultiString(content) => Some(content.join(", ").to_object(py)),
            CellValue::ValueBinary(content) => Some(pyo3::types::PyBytes::new(py, &self.inner.detail.value_bytes.clone().unwrap_or_default()).to_object(py)),
            _ => None
        }
    }
}

impl PyRegValue {
    pub fn from_cell_key_value(
        py: Python,
        cell_key_value: CellKeyValue
    ) -> PyResult<Py<PyRegValue>> {
        Py::new(
            py,
            PyRegValue {
                inner: cell_key_value.clone()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_content() {
        let mut py_reg_value = PyRegValue {
            inner: CellKeyValue {
                detail: CellKeyValueDetail {
                    file_offset_absolute: 0,
                    size: 48,
                    value_name_size: 18,
                    data_size_raw: 8,
                    data_offset_relative: 3864,
                    data_type_raw: 1,
                    flags_raw: 1,
                    padding: 0,
                    value_bytes: None,
                    slack: vec![0, 0, 1, 0, 0, 0]
                },
                data_type: CellKeyValueDataTypes::REG_SZ,
                flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
                value_name: "IE5_UA_Backup_Flag".to_string(),
                data_offsets_absolute: Vec::new(),
                logs: Logs::default(),
                versions: Vec::new(),
                hash: None,
                sequence_num: None,
                updated_by_sequence_num: None
            },
        };
        py_reg_value.inner.detail.value_bytes = Some(vec![53, 0, 46, 0, 48, 0, 0, 0]);
        let gil = Python::acquire_gil();
        let py = gil.python();

        let content: std::result::Result<String, pyo3::PyErr> = py_reg_value.get_content(py).extract(py);
        assert_eq!(content.unwrap(), "5.0".to_string());

    }
}