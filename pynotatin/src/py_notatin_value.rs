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

use crate::py_notatin_content::PyNotatinContent;
use crate::py_notatin_key::PyNotatinValuesIterator;
use pyo3::prelude::*;

use notatin::{
    cell_key_value::CellKeyValue,
    cell_value::{CellValue, DecodableValue, DecodeFormat},
};
use pyo3::{Py, PyIterProtocol, PyResult, Python};

#[pyclass(subclass)]
/// Returns an instance of a cell value.
pub struct PyNotatinValue {
    inner: CellKeyValue,
}

#[pymethods]
impl PyNotatinValue {
    #[getter]
    /// Returns the value as bytes
    pub fn value(&self, py: Python) -> PyObject {
        pyo3::types::PyBytes::new(py, &self.inner.detail.value_bytes().unwrap_or_default())
            .to_object(py)
    }

    #[getter]
    pub fn pretty_name(&self, py: Python) -> PyObject {
        self.inner.get_pretty_name().to_object(py)
    }

    #[getter]
    pub fn name(&self, py: Python) -> PyObject {
        self.inner.detail.value_name().to_object(py)
    }

    #[getter]
    /// Returns the data type as an integer
    pub fn raw_data_type(&self, py: Python) -> PyObject {
        self.inner.detail.data_type_raw().to_object(py)
    }

    #[getter]
    /// Returns the value as typed data
    pub fn content(&self, py: Python) -> Option<PyObject> {
        let (content, _) = self.inner.get_content();
        Self::prepare_content(py, &content)
    }

    /// Decodes the content using one of the supported decoders (see `PyNotatinDecodeFormat`)
    pub fn decode(
        &self,
        py: Python,
        format: &PyNotatinDecodeFormat,
        offset: usize,
    ) -> PyResult<Py<PyNotatinContent>> {
        let (decoded_content, _) = self.inner.decode_content(&format.inner, offset); // in both of these functions I am ignoring any logs that are returned. Best way to handle these in python?
        Py::new(
            py,
            PyNotatinContent {
                inner: decoded_content,
            },
        )
    }

    fn versions(&mut self) -> PyResult<Py<PyNotatinValueVersionsIterator>> {
        self.versions_iterator()
    }
}

impl PyNotatinValue {
    /// Returns a PyNotatinValue representing the `cell_key_value` parameter
    pub fn from_cell_key_value(
        py: Python,
        cell_key_value: CellKeyValue,
    ) -> PyResult<Py<PyNotatinValue>> {
        Py::new(
            py,
            PyNotatinValue {
                inner: cell_key_value,
            },
        )
    }

    /// Returns typed data based upon the values's data_type
    pub(crate) fn prepare_content(py: Python, content: &CellValue) -> Option<PyObject> {
        match content {
            CellValue::String(content) => Some(content.to_object(py)),
            CellValue::I32(content) => Some(content.to_object(py)),
            CellValue::U32(content) => Some(content.to_object(py)),
            CellValue::U64(content) => Some(content.to_object(py)),
            CellValue::I64(content) => Some(content.to_object(py)),
            CellValue::MultiString(content) => Some(content.to_object(py)),
            CellValue::Binary(content) => {
                Some(pyo3::types::PyBytes::new(py, content).to_object(py))
            }
            _ => None,
        }
    }

    fn versions_iterator(&mut self) -> PyResult<Py<PyNotatinValueVersionsIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        Py::new(
            py,
            PyNotatinValueVersionsIterator {
                index: 0,
                versions: self.inner.versions.clone(),
            },
        )
    }
}

#[pyclass]
pub struct PyNotatinValueVersionsIterator {
    index: usize,
    versions: Vec<CellKeyValue>,
}

impl PyNotatinValueVersionsIterator {
    fn next(&mut self) -> Option<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        match self.versions.get(self.index) {
            Some(value) => {
                self.index += 1;
                Some(PyNotatinValuesIterator::reg_value_to_pyobject(
                    value.clone(),
                    py,
                ))
            }
            None => None,
        }
    }
}

#[pyproto]
impl PyIterProtocol for PyNotatinValueVersionsIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinValueVersionsIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}

#[pyclass]
/// Exposes the available decode formats (lznt1, rot13, utf16, utf16_multiple) to Python
pub struct PyNotatinDecodeFormat {
    pub inner: DecodeFormat,
}

#[pymethods]
impl PyNotatinDecodeFormat {
    #[classattr]
    fn lznt1() -> Self {
        PyNotatinDecodeFormat {
            inner: DecodeFormat::Lznt1,
        }
    }

    #[classattr]
    fn rot13() -> Self {
        PyNotatinDecodeFormat {
            inner: DecodeFormat::Rot13,
        }
    }

    #[classattr]
    fn utf16() -> Self {
        PyNotatinDecodeFormat {
            inner: DecodeFormat::Utf16,
        }
    }

    #[classattr]
    fn utf16_multiple() -> Self {
        PyNotatinDecodeFormat {
            inner: DecodeFormat::Utf16Multiple,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notatin::{
        cell::CellState,
        cell_key_value::{
            CellKeyValue, CellKeyValueDataTypes, CellKeyValueDetailEnum, CellKeyValueDetailLight,
            CellKeyValueFlags,
        },
        field_offset_len::FieldLight,
        log::Logs,
    };
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_get_content() {
        let mut py_reg_value = PyNotatinValue {
            inner: CellKeyValue {
                file_offset_absolute: 0,
                detail: CellKeyValueDetailEnum::Light(Box::new(CellKeyValueDetailLight {
                    size: FieldLight { value: -48 },
                    signature: FieldLight {
                        value: "vk".to_string(),
                    },
                    value_name_size: FieldLight { value: 18 },
                    data_size_raw: FieldLight { value: 8 },
                    data_offset_relative: FieldLight { value: 3864 },
                    data_type_raw: FieldLight { value: 1 },
                    flags_raw: FieldLight { value: 1 },
                    padding: FieldLight { value: 0 },
                    value_bytes: FieldLight { value: None },
                    value_name: FieldLight {
                        value: "IE5_UA_Backup_Flag".to_string(),
                    },
                    slack: FieldLight {
                        value: vec![0, 0, 1, 0, 0, 0],
                    },
                })),
                data_type: CellKeyValueDataTypes::REG_SZ,
                flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
                cell_state: CellState::Allocated,
                data_offsets_absolute: Vec::new(),
                logs: Logs::default(),
                versions: Vec::new(),
                hash: None,
                sequence_num: None,
                updated_by_sequence_num: None,
            },
        };
        py_reg_value
            .inner
            .detail
            .set_value_bytes(&Some(vec![53, 0, 46, 0, 48, 0, 0, 0]), 0);
        let gil = Python::acquire_gil();
        let py = gil.python();

        let content: std::result::Result<String, pyo3::PyErr> =
            py_reg_value.content(py).unwrap().extract(py);
        assert_eq!(content.unwrap(), "5.0".to_string());
    }

    #[test]
    fn test_decode_content() -> Result<(), PyErr> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        let mut lznt1_file = File::open("../test_data/lznt1_buffer").unwrap();
        let mut lznt1_buffer = Vec::new();
        lznt1_file.read_to_end(&mut lznt1_buffer).unwrap();
        let py_notatin_value = PyNotatinValue {
            inner: CellKeyValue {
                detail: CellKeyValueDetailEnum::Light(Box::new(CellKeyValueDetailLight {
                    size: FieldLight { value: 48 },
                    signature: FieldLight {
                        value: "vk".to_string(),
                    },
                    value_name_size: FieldLight { value: 4 },
                    data_size_raw: FieldLight {
                        value: lznt1_buffer.len() as u32,
                    },
                    data_offset_relative: FieldLight { value: 3864 },
                    data_type_raw: FieldLight { value: 1 },
                    flags_raw: FieldLight { value: 1 },
                    padding: FieldLight { value: 0 },
                    value_name: FieldLight {
                        value: "test".to_string(),
                    },
                    value_bytes: FieldLight {
                        value: Some(lznt1_buffer.clone()),
                    },
                    slack: FieldLight { value: vec![] },
                })),
                file_offset_absolute: 0,
                data_type: CellKeyValueDataTypes::REG_BIN,
                flags: CellKeyValueFlags::VALUE_COMP_NAME_ASCII,
                cell_state: CellState::Allocated,
                data_offsets_absolute: Vec::new(),
                logs: Logs::default(),
                versions: Vec::new(),
                hash: None,
                sequence_num: None,
                updated_by_sequence_num: None,
            },
        };

        let decoded_value = py_notatin_value
            .decode(py, &PyNotatinDecodeFormat::lznt1(), 8)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<Vec<u8>>(py)?;

        let mut lznt1_decoded_file = File::open("../test_data/lznt1_decoded_buffer").unwrap();
        let mut lznt1_decoded_buffer = Vec::new();
        lznt1_decoded_file
            .read_to_end(&mut lznt1_decoded_buffer)
            .unwrap();
        assert_eq!(lznt1_decoded_buffer, decoded_value);

        let py_notatin_content = PyNotatinContent {
            inner: CellValue::Binary(lznt1_buffer),
        };
        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::lznt1(), 8)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<Vec<u8>>(py)?;
        assert_eq!(lznt1_decoded_buffer, decoded_value);

        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::lznt1(), 8)?
            .extract::<PyNotatinContent>(py)?
            .decode(py, &PyNotatinDecodeFormat::utf16_multiple(), 1860)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<Vec<String>>(py)?;
        let expected_output = vec![
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CSRSS.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\LOGONUI.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\EXPLORER.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\WUAUCLT.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\TASKHOST.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\EXPLORER.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NOTEPAD.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\PROGRAM FILES\WINDOWS NT\ACCESSORIES\WORDPAD.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CONSENT.EXE".to_string(),
            r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CONHOST.EXE".to_string(),
        ];
        assert_eq!(expected_output, decoded_value);

        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::lznt1(), 8)?
            .extract::<PyNotatinContent>(py)?
            .decode(py, &PyNotatinDecodeFormat::utf16(), 1860)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<String>(py)?;
        let expected_output = r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CSRSS.EXE".to_string();
        assert_eq!(expected_output, decoded_value);

        let mut utf16_multiple_file = File::open("../test_data/utf16_multiple_buffer").unwrap();
        let mut utf16_multiple_buffer = Vec::new();
        utf16_multiple_file
            .read_to_end(&mut utf16_multiple_buffer)
            .unwrap();
        let py_notatin_content = PyNotatinContent {
            inner: CellValue::Binary(utf16_multiple_buffer),
        };
        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::utf16_multiple(), 0)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<Vec<String>>(py)?;
        let expected_output = vec![
            "NAS_requested_data.7z".to_string(),
            "BlackHarrier_D7_i686_FDE_20141219.dd.7z".to_string(),
            "BlackHarrier_D7_amd64_20141217.7z".to_string(),
            "BlackHarrier_D7_amd64_FDE_20141217.7z".to_string(),
            r"C:\Users\jmroberts\Desktop\USB_Research\IEF.zip".to_string(),
            "Company_Report_10222013.vir.zip".to_string(),
            "LYNC.7z".to_string(),
            "viruses.zip".to_string(),
            "ALLDATA.txt.bz2".to_string(),
        ];
        assert_eq!(expected_output, decoded_value);

        let utf16 = vec![
            0x4E, 0x00, 0x41, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x72, 0x00, 0x65, 0x00, 0x71, 0x00,
            0x75, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x64, 0x00, 0x5F, 0x00,
            0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x2E, 0x00, 0x37, 0x00, 0x7A, 0x00,
        ];
        let py_notatin_content = PyNotatinContent {
            inner: CellValue::Binary(utf16),
        };
        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::utf16(), 0)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<String>(py)?;
        let expected_output = "NAS_requested_data.7z".to_string();
        assert_eq!(expected_output, decoded_value);

        let py_notatin_content = PyNotatinContent {
            inner: CellValue::String("Abgngva havg grfg.".to_string()),
        };
        let decoded_value = py_notatin_content
            .decode(py, &PyNotatinDecodeFormat::rot13(), 0)?
            .extract::<PyNotatinContent>(py)?
            .content(py)
            .unwrap()
            .extract::<String>(py)?;
        let expected_output = "Notatin unit test.".to_string();
        assert_eq!(expected_output, decoded_value);

        Ok(())
    }
}
