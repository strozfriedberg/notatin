use pyo3::exceptions::PyRuntimeError;
use pyo3::PyErr;

pub struct PyRegError(pub notatin::err::Error);

impl From<PyRegError> for PyErr {
    fn from(err: PyRegError) -> Self {
        match err.0 {
            //notatin::err::Error::Io (detail) => detail.into(),
            _ => PyErr::new::<PyRuntimeError, _>(format!("{}", err.0)),
        }
    }
}
