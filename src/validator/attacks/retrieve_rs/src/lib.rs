use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

#[pyclass]
#[derive(Clone)]
pub struct FormattedElement {
    #[pyo3(get)]
    clause: Vec<(u64, u8)>,
    #[pyo3(get)]
    vars: u128,
}

#[pyfunction]
pub fn retrieve(
    ciphertext: Vec<Vec<u64>>,
    public_key: Vec<Vec<(u64, u8)>>,
    n: u128,
    // ) -> PyResult<HashMap<u64, Vec<Vec<u64>>>> {
) -> PyResult<Vec<FormattedElement>> {
    // ================================
    //      Step 1
    // ================================
    if n > 128 {
        panic!("`N` was {}, must be <= 128", n);
    }
    let mut var_to_bit: HashMap<u64, u128> = HashMap::new();
    let mut bit_to_var: HashMap<u128, u64> = HashMap::new();
    for i in 0..n as u64 {
        let v: u128 = 1 << i;
        var_to_bit.insert(i + 2, v);
        bit_to_var.insert(v, i + 2);
    }
    // println!("v2b {:?}", var_to_bit);

    let mut unique_masks: HashSet<u128> = HashSet::new();
    for m in ciphertext {
        let mut mask: u128 = 0b0;
        for v in m {
            mask |= var_to_bit[&v];
        }
        unique_masks.insert(mask);
    }

    let unique_masks_vec: Vec<u128> = unique_masks.into_iter().collect();

    let mut s_combination_masks: HashSet<u128> = HashSet::new();
    for (i, mask_a) in unique_masks_vec.iter().enumerate() {
        for mask_b in &unique_masks_vec[i + 1..] {
            s_combination_masks.insert(mask_a | mask_b);
        }
    }

    // ================================
    //      Step 2
    // ================================

    let mut public_key_formatted: Vec<FormattedElement> = Vec::new();
    for c in public_key {
        let mut vars_extracted: u128 = 0;
        for v in &c {
            vars_extracted |= var_to_bit[&v.0];
        }
        let e = FormattedElement {
            clause: c.clone(),
            vars: vars_extracted,
        };
        public_key_formatted.push(e);
    }

    let mut clauses_sharing_variable: HashMap<u64, (Vec<FormattedElement>, u128)> = HashMap::new();
    for i in 2..(n as u64) + 2 {
        let clauses_vec: Vec<FormattedElement> = public_key_formatted
                .iter()
                .filter(|c| c.vars & (var_to_bit[&i]) > 0)
                .cloned()
                .collect();
        clauses_sharing_variable.insert(
            i,
            (clauses_vec.clone(), clauses_vec.into_iter().fold(0, |var_set, x| var_set | x.vars))
        );
    }

    let mut s_prime_expanded_from_s: HashSet<u128> = HashSet::new();
    for s_i in s_combination_masks {
        // println!("HEY {:b}", s_i);
        let mut b = s_i.clone();
        while b != 0 {
            let var: u64 = b.trailing_zeros().into();
            b &= b - 1;
            s_prime_expanded_from_s.insert(s_i | clauses_sharing_variable[&var].1);
            }
        }
    
    for x in s_prime_expanded_from_s {
        println!("s_prime_i {}", x);
    }
    

    // ================================
    //      Step 3
    // ================================

    // ================================
    //      Step 4
    // ================================

    Ok(public_key_formatted)

}

#[pymodule]
fn retrieve_rs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FormattedElement>()?;
    m.add_function(wrap_pyfunction!(retrieve, m)?)?;
    Ok(())
}
