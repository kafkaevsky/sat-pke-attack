use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

#[pyfunction]
pub fn retrieve(
    ciphertext: Vec<Vec<u128>>,
    public_key: Vec<Vec<Vec<u64>>>,
    n: u128,
) -> PyResult<HashMap<u64, Vec<Vec<u64>>>> {
    // ================================
    //      Step 1
    // ================================
    if n > 128 {
        panic!("`N` was {}, must be <= 128", n);
    }
    let mut var_to_bit = HashMap::new();
    let mut bit_to_var = HashMap::new();
    for i in 0..n {
        let v: u128 = 1 << i;
        var_to_bit.insert(i + 2, v);
        bit_to_var.insert(v, i + 2);
    }
    println!("v2b {:?}", var_to_bit);

    let mut unique_masks: HashSet<u128> = HashSet::new();
    for m in ciphertext {
        let mut mask: u128 = 0b0;
        for v in m {
            mask |= var_to_bit[&v];
        }
        unique_masks.insert(mask);
    }

    let unique_masks_vec: Vec<u128> = unique_masks.into_iter().collect();

    let mut combination_masks: HashSet<u128> = HashSet::new();
    for (i, mask_a) in unique_masks_vec.iter().enumerate() {
        for mask_b in &unique_masks_vec[i + 1..] {
            combination_masks.insert(mask_a | mask_b);
        }
    }
    // ================================
    //      Step 2
    // ================================

    let mut public_key_vars_only: Vec<Vec<u64>> = Vec::new();
    for c in public_key {
        let mut clause_vars: Vec<u64> = Vec::new();
        for v in c {
            clause_vars.push(v[0].clone());
        }
        public_key_vars_only.push(clause_vars);
    }

    let mut clauses_sharing_variable: HashMap<u64, Vec<Vec<u64>>> = HashMap::new();
    for i in 2..(n as u64) + 2 {
        clauses_sharing_variable.insert(
            i,
            public_key_vars_only
                .iter()
                .filter(|c| c.contains(&i))
                .cloned()
                .collect(),
        );
    }

    // ================================
    //      Step 3
    // ================================

    // ================================
    //      Step 4
    // ================================
    Ok(clauses_sharing_variable)
}

#[pymodule]
fn retrieve_rs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(retrieve, m)?)?;
    Ok(())
}
