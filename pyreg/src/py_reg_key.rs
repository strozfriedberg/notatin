use pyo3::prelude::*;

use crate::err::PyRegError;
use crate::util::{Output, date_to_pyobject};
use crate::py_reg_value::PyRegValue;
use notatin::{
    parser::Parser,
    filter::Filter,
    cell_key_node::CellKeyNode,
    cell_key_value::CellKeyValue,
};
use pyo3::{Py, PyIterProtocol, PyResult, Python};
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};

#[pyclass]
pub struct PyRegKey {
    inner: CellKeyNode,
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub number_of_sub_keys: u32,
    #[pyo3(get)]
    pub number_of_key_values: u32,
    #[pyo3(get)]
    pub last_key_written_date_and_time: PyObject,
}

#[pymethods]
impl PyRegKey {
    /// reg_values(self, /)
    /// --
    ///
    /// Returns an iterator that yields reg values as python objects.
    fn values(&mut self) -> PyResult<Py<PyRegValuesIterator>> {
        self.reg_values_iterator(Output::Python)
    }
}

impl PyRegKey {
    pub fn from_cell_key_node(
        py: Python,
        cell_key_node: CellKeyNode,
        parser: &mut Parser,
    ) -> PyResult<Py<PyRegKey>> {
        Py::new(
            py,
            PyRegKey {
                path: cell_key_node.path.clone(),
                number_of_sub_keys: cell_key_node.number_of_sub_keys,
                number_of_key_values: cell_key_node.number_of_key_values,
                last_key_written_date_and_time: date_to_pyobject(&cell_key_node.last_key_written_date_and_time)?,
                inner: cell_key_node,
            },
        )
    }

    fn reg_values_iterator(&mut self, output_format: Output) -> PyResult<Py<PyRegValuesIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        Py::new(
            py,
            PyRegValuesIterator {
                inner: self.inner.clone(),
                output_format,
            },
        )
    }
}

#[pyclass]
pub struct PyRegValuesIterator {
    inner: CellKeyNode,
    output_format: Output,
}

impl PyRegValuesIterator {
    fn reg_value_to_pyobject(
        &mut self,
        reg_key_result: Result<CellKeyValue, PyRegError>,
        py: Python,
    ) -> PyObject {
        match reg_key_result {
            Ok(reg_key) => {
                match PyRegValue::from_cell_key_value(py, reg_key)
                    .map(|entry| entry.to_object(py))
                {
                    Ok(py_reg_key) => py_reg_key,
                    Err(e) => e.to_object(py),
                }
            }
            Err(e) => {
                let err = PyErr::from(e);
                err.to_object(py)
            }
        }
    }

   /* fn reg_key_to_json(
        &mut self,
        entry_result: Result<CellKeyNode, PyRegError>,
        py: Python,
    ) -> PyObject {
        match entry_result {
            Ok(entry) => match serde_json::to_string(&entry) {
                Ok(s) => PyString::new(py, &s).to_object(py),
                Err(_e) => PyErr::new::<RuntimeError, _>("JSON Serialization failed").to_object(py),
            },
            Err(e) => PyErr::from(e).to_object(py),
        }
    }*/

    fn next(&mut self) -> PyResult<Option<PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        let obj = match self.inner.next() {
            Some(key) => {
                let ret = match self.output_format {
                    Output::Python => self.reg_value_to_pyobject(Ok(key), py),
                   // Output::JSONL => { return PyErr{ state: std::cell::UnsafeCell::new(Some(PyErrState::"not supported yet")) }; }//self.entry_to_json(Ok(entry), py),
                   /* Output::CSV => self.entry_to_csv(Ok(entry), py),*/
                };

                Ok(Some(ret))
            }
            None => Ok(None)
        };
        return obj;
    }
}

#[pyproto]
impl PyIterProtocol for PyRegKey {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<Py<PyRegValuesIterator>> {
        slf.values()
    }
    fn __next__(_slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Err(PyErr::new::<PyNotImplementedError, _>("Using `next()` over `PyRegKey` is not supported. Try iterating over `PyRegKey(...).reg_values()`"))
    }
}

#[pyproto]
impl PyIterProtocol for PyRegValuesIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyRegValuesIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        slf.next()
    }
}