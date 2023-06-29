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

use crate::err::PyNotatinError;
use crate::py_notatin_content::PyNotatinContent;
use crate::py_notatin_key::PyNotatinKey;
use crate::py_notatin_value::{PyNotatinDecodeFormat, PyNotatinValue};
use crate::util::{init_logging, FileOrFileLike};
use notatin::{
    cell_key_node::CellKeyNode,
    parser::{Parser, ParserIteratorContext},
    parser_builder::ParserBuilder,
};
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;

#[pyclass(subclass)]
/// Returns an instance of the parser.
/// Works on both a path (string), or a file-like object.
pub struct PyNotatinParser {
    pub inner: Option<Parser>,
}

#[pymethods]
impl PyNotatinParser {
    #[new]
    fn new(path_or_file_like: PyObject) -> PyResult<Self> {
        let parser = ParserBuilder::from_file(FileOrFileLike::to_read_seek(&path_or_file_like)?)
            .build()
            .map_err(PyNotatinError)?;
        Ok(PyNotatinParser {
            inner: Some(parser),
        })
    }

    /// Returns an iterator that yields reg keys as Python objects.
    fn reg_keys(&mut self) -> PyResult<Py<PyNotatinKeysIterator>> {
        self.reg_keys_iterator()
    }

    /// Returns the key for the `path` parameter.
    fn open(&mut self, path: &str) -> PyResult<Option<Py<PyNotatinKey>>> {
        match &mut self.inner {
            Some(parser) => match parser.get_key(path, false) {
                Ok(key) => {
                    if let Some(key) = key {
                        let gil = Python::acquire_gil();
                        let py = gil.python();
                        return Ok(PyNotatinKey::from_cell_key_node(py, key).ok());
                    }
                },
                Err(e) => return Err(PyErr::new::<PyRuntimeError, _>(e.to_string()))
            },
            _ => return Ok(None)
        }
        Ok(None)
    }

    /// Returns the root key.
    fn root(&mut self) -> PyResult<Option<Py<PyNotatinKey>>> {
        match &mut self.inner {
            Some(parser) => match parser.get_root_key() {
                Ok(key) => {
                    if let Some(key) = key {
                        let gil = Python::acquire_gil();
                        let py = gil.python();
                        Ok(PyNotatinKey::from_cell_key_node(py, key).ok())
                    }
                    else {
                        Ok(None)
                    }
                },
                Err(e) => Err(PyErr::new::<PyRuntimeError, _>(e.to_string()))
            },
            _ => Ok(None)
        }
    }

    /// Returns the parent key for the `key` parameter.
    fn get_parent(&mut self, key: &mut PyNotatinKey) -> PyResult<Option<Py<PyNotatinKey>>> {
        match &mut self.inner {
            Some(parser) => match parser.get_parent_key(&mut key.inner) {
                Ok(key) => {
                    if let Some(key) = key {
                        let gil = Python::acquire_gil();
                        let py = gil.python();
                        return Ok(PyNotatinKey::from_cell_key_node(py, key).ok());
                    }
                },
                Err(e) => return Err(PyErr::new::<PyRuntimeError, _>(e.to_string()))
            },
            _ => return Ok(None)
        }
        Ok(None)
    }

    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinKeysIterator>> {
        slf.reg_keys()
    }

fn __next__(_slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Err(PyErr::new::<PyNotImplementedError, _>("Using `next()` over `PyNotatinParser` is not supported. Try iterating over `PyNotatinParser(...).reg_keys()`"))
    }
}

impl PyNotatinParser {
    /// Returns an iterator that yields reg keys as Python objects
    fn reg_keys_iterator(&mut self) -> PyResult<Py<PyNotatinKeysIterator>> {
        Python::with_gil(|py| {
            let inner = match self.inner.take() {
                Some(inner) => inner,
                None => {
                    return Err(PyErr::new::<PyRuntimeError, _>(
                        "PyNotatinParser can only be used once",
                    ));
                }
            };
            let iterator_context = ParserIteratorContext::from_parser(&inner, true, None);
            Py::new(
                py,
                PyNotatinKeysIterator {
                    inner,
                    iterator_context,
                },
            )
        })
    }
}

#[pyclass]
pub struct PyNotatinParserBuilder {
    pub primary_file: PyObject,
    pub recover_deleted: bool,
    pub transaction_logs: Vec<PyObject>,
}

#[pymethods]
impl PyNotatinParserBuilder {
    #[new]
    fn new(path_or_file_like: PyObject) -> PyResult<Self> {
        Ok(PyNotatinParserBuilder {
            primary_file: path_or_file_like,
            recover_deleted: false,
            transaction_logs: vec![],
        })
    }

    pub fn recover_deleted(&mut self, recover: bool) -> PyResult<()> {
        self.recover_deleted = recover;
        Ok(())
    }

    pub fn with_transaction_log(&mut self, log: PyObject) -> PyResult<()> {
        self.transaction_logs.push(log);
        Ok(())
    }

    pub fn build(&self) -> PyResult<PyNotatinParser> {
        let mut builder =
            ParserBuilder::from_file(FileOrFileLike::to_read_seek(&self.primary_file)?);
        builder.recover_deleted(self.recover_deleted);
        for transaction_log in &self.transaction_logs {
            builder.with_transaction_log(FileOrFileLike::to_read_seek(transaction_log)?);
        }
        Ok(PyNotatinParser {
            inner: Some(builder.build().map_err(PyNotatinError)?),
        })
    }
}

#[pyclass]
pub struct PyNotatinKeysIterator {
    inner: Parser,
    iterator_context: ParserIteratorContext,
}

impl PyNotatinKeysIterator {
    pub(crate) fn reg_key_to_pyobject(reg_key: CellKeyNode, py: Python) -> PyObject {
        match PyNotatinKey::from_cell_key_node(py, reg_key).map(|entry| entry.to_object(py)) {
            Ok(py_reg_key) => py_reg_key,
            Err(e) => e.to_object(py),
        }
    }

    fn next(&mut self) -> Option<PyObject> {
        Python::with_gil(|py| {
            self.inner
                .next_key_preorder(&mut self.iterator_context)
                .map(|key| Self::reg_key_to_pyobject(key, py))
        })
    }
}

#[pymethods]
impl PyNotatinKeysIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyNotatinKeysIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Ok(slf.next())
    }
}

/// Parses a windows registry file.
#[pymodule]
fn notatin(py: Python, m: &PyModule) -> PyResult<()> {
    init_logging(py).ok();

    m.add_class::<PyNotatinParserBuilder>()?;
    m.add_class::<PyNotatinParser>()?;
    m.add_class::<PyNotatinKey>()?;
    m.add_class::<PyNotatinValue>()?;
    m.add_class::<PyNotatinContent>()?;
    m.add_class::<PyNotatinDecodeFormat>()?;

    Ok(())
}
