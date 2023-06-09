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

use crate::py_notatin_parser::{PyNotatinKeysIterator, PyNotatinParser};
use crate::py_notatin_value::PyNotatinValue;
use crate::util::date_to_pyobject;
use notatin::{cell_key_node::CellKeyNode, cell_key_value::CellKeyValue};
use pyo3::exceptions::PyNotImplementedError;
use pyo3::{Py, PyResult, Python};

#[pyclass(subclass)]
pub struct PyNotatinKey {
    pub(crate) inner: CellKeyNode,
    #[pyo3(get)]
    pub last_key_written_date_and_time: PyObject,
}

#[pymethods]
impl PyNotatinKey {
    /// values(self, /)
    /// --
    ///
    /// Returns an iterator that yields registry values as python objects.
    fn values(&mut self) -> PyResult<Py<PyNotatinValuesIterator>> {
        self.reg_values_iterator()
    }

    /// value(self, name)
    /// --
    ///
    /// Returns an option with the requested value, or None.
    fn value(&mut self, name: &str) -> Option<Py<PyNotatinValue>> {
        match self.inner.get_value(name) {
            Some(value) => {
                let gil = Python::acquire_gil();
                let py = gil.python();
                let ret = PyNotatinValue::from_cell_key_value(py, value);
                if let Ok(py_reg_value) = ret {
                    return Some(py_reg_value);
                }
            }
            _ => return None,
        }
        None
    }

    /// sub_keys(self, parser, /)
    /// --
    ///
    /// Returns an iterator that yields sub keys as python objects.
    fn subkeys(&mut self, parser: &mut PyNotatinParser) -> PyResult<Py<PyNotatinSubKeysIterator>> {
        self.sub_keys_iterator(parser)
    }

    fn find_key(&mut self, parser: &mut PyNotatinParser, path: &str) -> Option<Py<PyNotatinKey>> {
        match &mut parser.inner {
            Some(parser) => match self.inner.get_sub_key_by_path(parser, path) {
                Some(key) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let ret = PyNotatinKey::from_cell_key_node(py, key);
                    if let Ok(py_reg_key) = ret {
                        return Some(py_reg_key);
                    }
                }
                _ => return None,
            },
            _ => return None,
        }
        None
    }

    /// name(self, /)
    /// --
    ///
    /// Returns the name of the key
    #[getter]
    pub fn name(&self, py: Python) -> PyObject {
        self.inner.key_name.to_object(py)
    }

    /// path(self, /)
    /// --
    ///
    /// Returns the path of the key
    #[getter]
    pub fn path(&self, py: Python) -> PyObject {
        self.inner.path.to_object(py)
    }

    /// pretty_path(self, /)
    /// --
    ///
    /// Returns the pretty path (no root object) of the key
    #[getter]
    pub fn pretty_path(&self, py: Python) -> PyObject {
        self.inner.get_pretty_path().to_object(py)
    }

    /// number_of_sub_keys(self, /)
    /// --
    ///
    /// Returns the number of sub keys
    #[getter]
    pub fn number_of_sub_keys(&self, py: Python) -> PyObject {
        self.inner.detail.number_of_sub_keys().to_object(py)
    }

    /// number_of_key_values(self, /)
    /// --
    ///
    /// Returns the number of key values
    #[getter]
    pub fn number_of_key_values(&self, py: Python) -> PyObject {
        self.inner.detail.number_of_key_values().to_object(py)
    }

    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinValuesIterator>> {
        slf.values()
    }

    fn __next__(_slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Err(PyErr::new::<PyNotImplementedError, _>("Using `next()` over `PyNotatinKey` is not supported. Try iterating over `PyNotatinKey(...).values() or PyNotatinKey(...).sub_keys()`"))
    }
}

impl PyNotatinKey {
    pub fn from_cell_key_node(
        py: Python,
        cell_key_node: CellKeyNode,
    ) -> PyResult<Py<PyNotatinKey>> {
        Py::new(
            py,
            PyNotatinKey {
                last_key_written_date_and_time: date_to_pyobject(
                    &cell_key_node.last_key_written_date_and_time(),
                )?,
                inner: cell_key_node,
            },
        )
    }

    fn reg_values_iterator(&mut self) -> PyResult<Py<PyNotatinValuesIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        Py::new(
            py,
            PyNotatinValuesIterator {
                inner: self.inner.clone(),
                sub_values_iter_index: 0,
            },
        )
    }

    fn sub_keys_iterator(
        &mut self,
        parser: &mut PyNotatinParser,
    ) -> PyResult<Py<PyNotatinSubKeysIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        self.inner.init_sub_key_iter();
        match &mut parser.inner {
            Some(parser) => {
                let sub_keys = self.inner.read_sub_keys(parser);

                Py::new(py, PyNotatinSubKeysIterator { index: 0, sub_keys })
            }
            _ => Py::new(
                py,
                PyNotatinSubKeysIterator {
                    index: 0,
                    sub_keys: Vec::new(),
                },
            ),
        }
    }
}

#[pyclass]
pub struct PyNotatinValuesIterator {
    inner: CellKeyNode,
    sub_values_iter_index: usize,
}

impl PyNotatinValuesIterator {
    pub(crate) fn reg_value_to_pyobject(reg_value: CellKeyValue, py: Python) -> PyObject {
        match PyNotatinValue::from_cell_key_value(py, reg_value).map(|entry| entry.to_object(py)) {
            Ok(py_reg_value) => py_reg_value,
            Err(e) => e.to_object(py),
        }
    }

    fn next(&mut self) -> Option<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        match self.inner.next_value(self.sub_values_iter_index) {
            Some((value, sub_values_iter_index)) => {
                self.sub_values_iter_index = sub_values_iter_index;
                Some(Self::reg_value_to_pyobject(value, py))
            }
            None => None,
        }
    }
}

#[pyclass]
pub struct PyNotatinSubKeysIterator {
    index: usize,
    sub_keys: Vec<CellKeyNode>,
}

impl PyNotatinSubKeysIterator {
    fn next(&mut self) -> Option<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        match self.sub_keys.get(self.index) {
            Some(key) => {
                self.index += 1;
                Some(PyNotatinKeysIterator::reg_key_to_pyobject(key.clone(), py))
            }
            None => None,
        }
    }
}

#[pymethods]
impl PyNotatinValuesIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinValuesIterator>> {
        Ok(slf.into())
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}

#[pymethods]
impl PyNotatinSubKeysIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinSubKeysIterator>> {
        Ok(slf.into())
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}
