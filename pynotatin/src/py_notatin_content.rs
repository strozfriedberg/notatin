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

use crate::py_notatin_value::{PyNotatinDecodeFormat, PyNotatinValue};
use pyo3::prelude::*;

use notatin::cell_value::{CellValue, DecodableValue};
use pyo3::{Py, PyResult, Python};

#[pyclass]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PyNotatinContent {
    pub inner: CellValue,
}

#[pymethods]
impl PyNotatinContent {
    #[getter]
    pub fn content(&self, py: Python) -> Option<PyObject> {
        PyNotatinValue::prepare_content(py, &self.inner)
    }

    pub fn decode(
        &self,
        py: Python,
        format: &PyNotatinDecodeFormat,
        offset: usize,
    ) -> PyResult<Py<PyNotatinContent>> {
        let (decoded_content, _) = self.inner.decode_content(&format.inner, offset);
        Py::new(
            py,
            PyNotatinContent {
                inner: decoded_content,
            },
        )
    }
}
