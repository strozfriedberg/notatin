use pyo3::prelude::*;

use crate::err::PyRegError;
use crate::util::date_to_pyobject;
use notatin::{
    registry::Parser,
    filter::Filter,
    cell_key_node::CellKeyNode
};
use pyo3::{Py, PyIterProtocol, PyResult, Python};

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
}