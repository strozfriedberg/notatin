use pyo3::prelude::*;

use crate::err::PyRegError;
use crate::util::date_to_pyobject;
use notatin::{
    parser::Parser,
    filter::Filter,
    cell_key_value::CellKeyValue,
    cell_value::CellValue
};
use pyo3::{Py, PyIterProtocol, PyResult, Python};

#[pyclass]
pub struct PyRegValue {
    //inner: CellKeyValue,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub value_type: u32,
    //#[pyo3(get)]
    //pub value: u32,
    #[pyo3(get)]
    pub raw_data: Vec<u8>
}

impl PyRegValue {
    pub fn from_cell_key_value(
        py: Python,
        cell_key_value: CellKeyValue
    ) -> PyResult<Py<PyRegValue>> {
        //let (cell_value, logs) = cell_key_value.get_content();
        Py::new(
            py,
            PyRegValue {
                name: cell_key_value.value_name.clone(),
                value_type: cell_key_value.detail.data_type_raw,
                raw_data: cell_key_value.detail.value_bytes.unwrap_or_default()
            },
        )
    }
}