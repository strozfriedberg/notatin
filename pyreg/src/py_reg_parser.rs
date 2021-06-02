use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::fs::File;
use notatin::{
    parser::Parser,
    filter::Filter,
    cell_key_node::CellKeyNode
};
use pyo3::prelude::*;
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};
use pyo3::{PyIterProtocol};
use crate::util::{FileOrFileLike, Output, init_logging};
use crate::err::PyRegError;
use crate::py_reg_key::PyRegKey;
//pub use reg_key::PyRegKey;

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}

#[pyclass]
/// PyRegParser(self, path_or_file_like, /)
/// --
///
/// Returns an instance of the parser.
/// Works on both a path (string), or a file-like object.
pub struct PyRegParser {
    //inner: Option<Registry>
    inner: Option<Parser>
}

#[pymethods]
impl PyRegParser {
    #[new]
    fn new(path_or_file_like: PyObject) -> PyResult<Self> {
        let file_or_file_like = FileOrFileLike::from_pyobject(path_or_file_like)?;
        let boxed_read_seek = match file_or_file_like {
            FileOrFileLike::File(s) => {
                let file = File::open(s)?;

                let reader = BufReader::with_capacity(4096, file);

                Box::new(reader) as Box<dyn ReadSeek + Send>
            }
            FileOrFileLike::FileLike(f) => Box::new(f) as Box<dyn ReadSeek + Send>,
        };

        let parser = Parser::from_read_seek(boxed_read_seek, None, false).map_err(PyRegError)?;
        Ok(PyRegParser {
            inner: Some(parser),
        })
    }

    /// reg_keys(self, /)
    /// --
    ///
    /// Returns an iterator that yields reg keys as python objects.
    fn reg_keys(&mut self) -> PyResult<Py<PyRegKeysIterator>> {
        self.reg_keys_iterator(Output::Python)
    }

    /// reg_keys_jsonl(self, /)
    /// --
    ///
    /// Returns an iterator that yields reg keys as JSON.
    fn reg_keys_jsonl(&mut self) -> PyResult<Py<PyRegKeysIterator>> {
        //self.reg_keys_iterator(Output::JSONL)
        self.reg_keys_iterator(Output::Python)
    }
}

impl PyRegParser {
    fn reg_keys_iterator(&mut self, output_format: Output) -> PyResult<Py<PyRegKeysIterator>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let inner = match self.inner.take() {
            Some(inner) => inner,
            None => {
                return Err(PyErr::new::<PyRuntimeError, _>(
                    "PyRegParser can only be used once",
                ));
            }
        };

        Py::new(
            py,
            PyRegKeysIterator {
                inner: inner,
                output_format,
            },
        )
    }
}

#[pyclass]
pub struct PyRegKeysIterator {
    inner: Parser,
    output_format: Output,
}

impl PyRegKeysIterator {
    fn reg_key_to_pyobject(
        &mut self,
        reg_key_result: Result<CellKeyNode, PyRegError>,
        py: Python,
    ) -> PyObject {
        match reg_key_result {
            Ok(reg_key) => {
                match PyRegKey::from_cell_key_node(py, reg_key, &mut self.inner)
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
                    Output::Python => self.reg_key_to_pyobject(Ok(key), py),
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
impl PyIterProtocol for PyRegParser {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<Py<PyRegKeysIterator>> {
        slf.reg_keys()
    }
    fn __next__(_slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        Err(PyErr::new::<PyNotImplementedError, _>("Using `next()` over `PyRegParser` is not supported. Try iterating over `PyRegParser(...).reg_keys()`"))
    }
}

#[pyproto]
impl PyIterProtocol for PyRegKeysIterator {
    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PyRegKeysIterator>> {
        Ok(slf.into())
    }
    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        slf.next()
    }
}

// Don't use double quotes ("") inside this docstring, this will crash pyo3.
/// Parses an mft file.
#[pymodule]
fn pyreg(py: Python, m: &PyModule) -> PyResult<()> {
    init_logging(py).ok();

    m.add_class::<PyRegParser>()?;
    m.add_class::<PyRegKey>()?;

   /* // Entry
    m.add_class::<PyMftEntriesIterator>()?;
    m.add_class::<PyMftEntry>()?;

    // Attributes
    m.add_class::<PyMftAttribute>()?;
    m.add_class::<PyMftAttributesIter>()?;
    m.add_class::<PyMftAttributeX10>()?;
    m.add_class::<PyMftAttributeX20>()?;
    m.add_class::<PyMftAttributeX30>()?;
    m.add_class::<PyMftAttributeX40>()?;
    m.add_class::<PyMftAttributeX80>()?;
    m.add_class::<PyMftAttributeX90>()?;
    m.add_class::<PyMftAttributeNonResident>()?;
    m.add_class::<PyMftAttributeOther>()?;*/

    Ok(())
}