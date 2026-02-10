use itertools::Itertools;
use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

#[pyclass]
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FormattedElement {
    #[pyo3(get)]
    clause: Vec<(u64, u64)>,
    #[pyo3(get)]
    vars: u128,
}

#[pyfunction]
pub fn retrieve(
    ciphertext: Vec<Vec<u64>>,
    public_key: Vec<Vec<(u64, u64)>>,
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
            (
                clauses_vec.clone(),
                clauses_vec
                    .into_iter()
                    .fold(0, |var_set, x| var_set | x.vars),
            ),
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

    // ================================
    //      Step 3
    // ================================

    let mut t_contained_by_clauses: Vec<Vec<Vec<(u64, u64)>>> = Vec::new();
    for s_prime_i in s_prime_expanded_from_s {
        let mut t_i_hashset = HashSet::new();
        let mut b = s_prime_i.clone();
        while b != 0 {
            let var: u64 = b.trailing_zeros().into();
            b &= b - 1;
            for candidate_clause in &clauses_sharing_variable[&var].0 {
                if (candidate_clause.vars & !s_prime_i) == 0 {
                    // vars in candidate_clause are contained by vars in s_prime_i
                    t_i_hashset.insert(candidate_clause.clause.clone());
                }
            }
        }

        let t_i: Vec<Vec<(u64, u64)>> = Vec::from_iter(t_i_hashset);
        if t_i.len() > 0 {
            t_contained_by_clauses.push(t_i.clone());
        }
    }

    fn cnf_to_neg_anf(clause: &Vec<(u64, u64)>) -> Vec<Vec<u64>> {
        println!("========");
        let mut clause_iterable_negated: Vec<Vec<u64>> = vec![vec![1]];
        for m in clause {
            clause_iterable_negated.push(vec![m.0, m.1]);
        }

        let mut neg_anf_simplified: Vec<Vec<u64>> = Vec::new();
        for m in clause_iterable_negated
            .iter()
            .map(|v| v.iter().copied())
            .multi_cartesian_product()
        {
            if !m.contains(&0) {
                neg_anf_simplified.push(m.into_iter().filter(|v| *v != 1 as u64).collect());
            }
        }
        neg_anf_simplified
    }

    for t_i in t_contained_by_clauses {
        let c_1 = &t_i[0];
        let mut anf_c_1: Vec<Vec<u64>> = cnf_to_neg_anf(&c_1);
    }

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
