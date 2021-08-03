use pyo3::prelude::*;

use crate::err::PyRegError;
use crate::util::date_to_pyobject;
use crate::py_reg_value::PyRegValue;
use crate::py_reg_parser::{PyRegKeysIterator, PyRegParser};
use notatin::{
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
};
use pyo3::{Py, PyIterProtocol, PyResult, Python};
use pyo3::exceptions::PyNotImplementedError;

#[pyclass(subclass)]
pub struct PyRegKey {
    pub(crate) inner: CellKeyNode,
    #[pyo3(get)]
    pub last_key_written_date_and_time: PyObject,
}

#[pymethods]
impl PyRegKey {
    /// values(self, /)
    /// --
    ///
    /// Returns an iterator that yields registry values as python objects.
    fn values(&mut self) -> PyResult<Py<PyRegValuesIterator>> {
        self.reg_values_iterator()
    }

    /// value(self, name)
    /// --
    ///
    /// Returns an option with the requested value, or None.
    fn value(&mut self, name: &str) -> Option<Py<PyRegValue>> {
        match self.inner.get_value(name) {
            Some(value) => {
                let gil = Python::acquire_gil();
                let py = gil.python();
                let ret = PyRegValue::from_cell_key_value(py, value);
                if let Ok(py_reg_value) = ret {
                    return Some(py_reg_value);
                }
            },
            _ => return None
        }
        None
    }

    /// sub_keys(self, parser, /)
    /// --
    ///
    /// Returns an iterator that yields sub keys as python objects.
    fn subkeys(
        &mut self,
        parser: &mut PyRegParser
    ) -> PyResult<Py<PyRegSubKeysIterator>> {
        self.sub_keys_iterator(parser)
    }

    fn find_key(
        &mut self,
        parser: &mut PyRegParser,
        path: &str
    ) -> Option<Py<PyRegKey>> {
        match &mut parser.inner {
            Some(parser) => {
                match self.inner.get_sub_key_by_path(parser, &path) {
                    Some(key) => {
                        let gil = Python::acquire_gil();
                        let py = gil.python();
                        let ret = PyRegKey::from_cell_key_node(py, key);
                        if let Ok(py_reg_key) = ret {
                            return Some(py_reg_key);
                        }
                    },
                    _ => return None
                }
            },
            _ => return None
        }
        None
    }

    /// name(self, /)
    /// --
    ///
    /// Returns the name of the key
    #[getter]
    pub fn name(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.key_name.to_object(py)
    }

    /// path(self, /)
    /// --
    ///
    /// Returns the path of the key
    #[getter]
    pub fn path(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.path.to_object(py)
    }

    /// number_of_sub_keys(self, /)
    /// --
    ///
    /// Returns the number of sub keys
    #[getter]
    pub fn number_of_sub_keys(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.number_of_sub_keys.to_object(py)
    }

    /// number_of_key_values(self, /)
    /// --
    ///
    /// Returns the number of key values
    #[getter]
    pub fn number_of_key_values(
        &self,
        py: Python
    ) -> PyObject {
        self.inner.number_of_key_values.to_object(py)
    }
}

impl PyRegKey {
    pub fn from_cell_key_node(
        py: Python,
        cell_key_node: CellKeyNode
    ) -> PyResult<Py<PyRegKey>> {
        Py::new(
            py,
            PyRegKey {
                last_key_written_date_and_time: date_to_pyobject(&cell_key_node.last_key_written_date_and_time)?,
                inner: cell_key_node,
            },
        )
    }

    fn reg_values_iterator(&mut self) -> PyResult<Py<PyRegValuesIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        self.inner.init_value_iter();

        Py::new(
            py,
            PyRegValuesIterator {
                inner: self.inner.clone()
            },
        )
    }

    fn sub_keys_iterator(
        &mut self,
        parser: &mut PyRegParser
    ) -> PyResult<Py<PyRegSubKeysIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        self.inner.init_sub_key_iter();
        match &mut parser.inner {
            Some(parser) => {
                let sub_keys = self.inner.read_sub_keys(parser);

                Py::new(
                    py,
                    PyRegSubKeysIterator {
                        index: 0,
                        sub_keys
                    },
                )
            },
            _ => Py::new(
                    py,
                    PyRegSubKeysIterator {
                        index: 0,
                        sub_keys: Vec::new()
                    }
                )
        }
    }
}

#[pyclass]
pub struct PyRegValuesIterator {
    inner: CellKeyNode
}

impl PyRegValuesIterator {
    fn reg_value_to_pyobject(
        &mut self,
        reg_value_result: Result<CellKeyValue, PyRegError>,
        py: Python,
    ) -> PyObject {
        match reg_value_result {
            Ok(reg_value) => {
                match PyRegValue::from_cell_key_value(py, reg_value)
                    .map(|entry| entry.to_object(py))
                {
                    Ok(py_reg_value) => py_reg_value,
                    Err(e) => e.to_object(py),
                }
            }
            Err(e) => {
                let err = PyErr::from(e);
                err.to_object(py)
            }
        }
    }

    fn next(&mut self) -> Option<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        match self.inner.next_value() {
            Some(value) => {
                Some(self.reg_value_to_pyobject(Ok(value), py))
            }
            None => None
        }
    }
}

#[pyclass]
pub struct PyRegSubKeysIterator {
    index: usize,
    sub_keys: Vec<CellKeyNode>
}

impl PyRegSubKeysIterator {
    fn next(&mut self) -> Option<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        match self.sub_keys.get(self.index) {
            Some(key) => {
                self.index += 1;
                Some(PyRegKeysIterator::reg_key_to_pyobject(Ok(key.clone()), py))
            }
            None => None
        }
    }
}

#[pyproto]
impl PyIterProtocol for PyRegKey {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<Py<PyRegValuesIterator>> {
        slf.values()
    }
    fn __next__(_slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Err(PyErr::new::<PyNotImplementedError, _>("Using `next()` over `PyRegKey` is not supported. Try iterating over `PyRegKey(...).values() or PyRegKey(...).sub_keys()`"))
    }
}

#[pyproto]
impl PyIterProtocol for PyRegValuesIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyRegValuesIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}

#[pyproto]
impl PyIterProtocol for PyRegSubKeysIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyRegSubKeysIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}