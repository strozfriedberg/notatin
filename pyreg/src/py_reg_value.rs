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

use pyo3::prelude::*;

use notatin::{cell_key_value::CellKeyValue, cell_value::CellValue};
use pyo3::{Py, PyResult, Python};

#[pyclass(subclass)]
pub struct PyRegValue {
    inner: CellKeyValue,
}

#[pymethods]
impl PyRegValue {
    #[getter]
    pub fn value(&self, py: Python) -> PyObject {
        pyo3::types::PyBytes::new(
            py,
            &self.inner.detail.value_bytes.clone().unwrap_or_default(),
        )
        .to_object(py)
    }

    #[getter]
    pub fn pretty_name(&self, py: Python) -> PyObject {
        self.inner.get_pretty_name().to_object(py)
    }

    #[getter]
    pub fn name(&self, py: Python) -> PyObject {
        self.inner.value_name.to_object(py)
    }

    #[getter]
    pub fn raw_data_type(&self, py: Python) -> PyObject {
        self.inner.detail.data_type_raw.to_object(py)
    }

    #[getter]
    pub fn data_type(&self, py: Python) -> PyObject {
        self.inner.detail.data_type_raw.to_object(py)
    }

    #[getter]
    pub fn content(&self, py: Python) -> Option<PyObject> {
        let (content, _) = self.inner.get_content();
        match content {
            CellValue::ValueString(content) => Some(content.to_object(py)),
            CellValue::ValueI32(content) => Some(content.to_object(py)),
            CellValue::ValueU32(content) => Some(content.to_object(py)),
            CellValue::ValueU64(content) => Some(content.to_object(py)),
            CellValue::ValueI64(content) => Some(content.to_object(py)),
            CellValue::ValueMultiString(content) => Some(content.to_object(py)),
            CellValue::ValueBinary(content) => {
                Some(pyo3::types::PyBytes::new(py, &content).to_object(py))
            }
            _ => None,
        }
    }
}

impl PyRegValue {
    pub fn from_cell_key_value(
        py: Python,
        cell_key_value: CellKeyValue,
    ) -> PyResult<Py<PyRegValue>> {
        Py::new(
            py,
            PyRegValue {
                inner: cell_key_value,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notatin::{
        cell_key_value::{CellKeyValueDataTypes, CellKeyValueDetail, CellKeyValueFlags},
        cell_value::CellState,
        log::Logs,
    };

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
                    slack: vec![0, 0, 1, 0, 0, 0],
                },
                data_type: CellKeyValueDataTypes::REG_SZ,
                flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
                value_name: "IE5_UA_Backup_Flag".to_string(),
                state: CellState::Allocated,
                data_offsets_absolute: Vec::new(),
                logs: Logs::default(),
                versions: Vec::new(),
                hash: None,
                sequence_num: None,
                updated_by_sequence_num: None,
            },
        };
        py_reg_value.inner.detail.value_bytes = Some(vec![53, 0, 46, 0, 48, 0, 0, 0]);
        let gil = Python::acquire_gil();
        let py = gil.python();

        let content: std::result::Result<String, pyo3::PyErr> =
            py_reg_value.content(py).unwrap().extract(py);
        assert_eq!(content.unwrap(), "5.0".to_string());
    }
}
