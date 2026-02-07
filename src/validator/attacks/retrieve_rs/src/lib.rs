use pyo3::prelude::*;

#[pyfunction]
pub fn retrieve(values: Vec<i64>) -> PyResult<i64> {
    Ok(values.iter().sum())
}

#[pymodule]
fn retrieve_rs(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(retrieve, m)?)?;
    Ok(())
}