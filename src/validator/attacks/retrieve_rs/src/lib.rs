use pyo3::prelude::*;
use rand::RngExt;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

#[pyclass]
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FormattedElement {
    #[pyo3(get)]
    clause: Vec<(u64, u64)>,
    #[pyo3(get)]
    vars: u128,
}

const INDEX_0_OFFSET: u64 = 2;
const DEFAULT_MAX_SAMPLES: usize = 100;
const DEFAULT_SAMPLE_THRESHOLD: usize = 30;

#[inline(always)]
fn encode_bit_vector(var: u64) -> u128 {
    1u128 << (var - INDEX_0_OFFSET)
}

fn decode_bit_vector(v: u128) -> Vec<u64> {
    let mut m: Vec<u64> = Vec::with_capacity(v.count_ones() as usize);
    let mut bits = v;
    while bits != 0 {
        let i = bits.trailing_zeros() as u64;
        m.push(i + INDEX_0_OFFSET);
        bits &= bits - 1;
    }
    m
}

fn cnf_to_neg_anf(clause: &Vec<(u64, u64)>) -> Vec<u128> {
    let mut result: HashSet<u128> = HashSet::new();
    result.insert(0);
    for &(var, sign) in clause {
        let encoded_var = encode_bit_vector(var);
        let mut updated_result: HashSet<u128> = HashSet::new();

        for &m in &result {
            // Sign bit is 1 (so we have x)
            if sign != 0 {
                // add m
                if !updated_result.remove(&m) {
                    updated_result.insert(m);
                }
                // add m | x
                let m_with_var = m | encoded_var;
                if !updated_result.remove(&m_with_var) {
                    updated_result.insert(m_with_var);
                }
            }
            // Sign bit is 0 (so we have ~x)
            else {
                let m_with_var = m | encoded_var;
                if !updated_result.remove(&m_with_var) {
                    updated_result.insert(m_with_var);
                }
            }
        }
        result = updated_result;
    }
    result.into_iter().collect()
}

#[pyfunction]
pub fn retrieve(
    ciphertext: Vec<Vec<u64>>,
    public_key: Vec<Vec<(u64, u64)>>,
    n: u128,
    max_samples: usize,
    sample_threshold: usize,
) -> PyResult<Vec<Vec<FormattedElement>>> {
    // ================================
    //      Step 1
    // ================================
    if n > 128 {
        panic!("`N` was {}, must be <= 128", n);
    }

    let mut unique_masks: HashSet<u128> = HashSet::with_capacity(ciphertext.len());
    for m in ciphertext {
        let mut mask: u128 = 0b0;
        for v in m {
            mask |= encode_bit_vector(v);
        }
        unique_masks.insert(mask);
    }

    eprintln!("unique_masks: {}", unique_masks.len());

    let unique_masks_vec: Vec<u128> = unique_masks.iter().copied().collect();

    let s_combination_masks: HashSet<u128> = (0..unique_masks_vec.len())
        .into_par_iter()
        .flat_map(|i| {
            unique_masks_vec[i + 1..]
                .iter()
                .map({
                    let value = unique_masks_vec.clone();
                    move |mask_b| value[i] | mask_b
                })
                .collect::<Vec<_>>()
        })
        .collect();

    eprintln!("s_combination_masks: {}", s_combination_masks.len());

    // ================================
    //      Step 2
    // ================================

    let mut public_key_formatted: Vec<FormattedElement> = Vec::with_capacity(public_key.len());
    for c in &public_key {
        let mut vars_extracted: u128 = 0;
        for v in c {
            vars_extracted |= encode_bit_vector(v.0);
        }
        public_key_formatted.push(FormattedElement {
            clause: c.clone(),
            vars: vars_extracted,
        });
    }

    let mut clauses_sharing_variable: HashMap<u64, (Vec<FormattedElement>, u128)> = HashMap::new();
    for i in INDEX_0_OFFSET..(n as u64) + INDEX_0_OFFSET {
        let encoded_var = encode_bit_vector(i);
        let mut union_vars: u128 = 0;
        let mut clauses_vec: Vec<FormattedElement> = Vec::new();
        for c in &public_key_formatted {
            if c.vars & encoded_var != 0 {
                union_vars |= c.vars;
                clauses_vec.push(c.clone());
            }
        }
        clauses_sharing_variable.insert(i, (clauses_vec, union_vars));
    }

    eprintln!(
        "clauses_sharing_variable: {}",
        clauses_sharing_variable.len()
    );

    let s_prime_expanded_from_s: HashSet<u128> = s_combination_masks
        .par_iter()
        .flat_map(|&s_i| {
            let mut results = Vec::new();
            let mut b = s_i;
            while b != 0 {
                let var = (b.trailing_zeros() as u64) + INDEX_0_OFFSET;
                b &= b - 1;
                results.push(s_i | clauses_sharing_variable[&var].1);
            }
            results
        })
        .collect();

    eprintln!("s_prime_expanded_from_s: {}", s_prime_expanded_from_s.len());

    // ================================
    //      Step 3
    // ================================

    let s_prime_vec: Vec<u128> = s_prime_expanded_from_s.into_iter().collect();

    let t_contained_by_clauses: Vec<Vec<FormattedElement>> = s_prime_vec
        .par_iter()
        .filter_map(|&s_prime_i| {
            let mut t_i_hashset: HashSet<*const FormattedElement> = HashSet::new();
            let mut t_i: Vec<FormattedElement> = Vec::new();
            let mut b = s_prime_i;
            while b != 0 {
                let var = (b.trailing_zeros() as u64) + INDEX_0_OFFSET;
                b &= b - 1;
                if let Some((clauses, _)) = clauses_sharing_variable.get(&var) {
                    for candidate_clause in clauses {
                        if (candidate_clause.vars & !s_prime_i) == 0 {
                            let ptr = candidate_clause as *const FormattedElement;
                            if t_i_hashset.insert(ptr) {
                                t_i.push(candidate_clause.clone());
                            }
                        }
                    }
                }
            }
            if t_i.is_empty() {
                None
            } else {
                Some(t_i)
            }
        })
        .collect();

    eprintln!("t_contained_by_clauses: {}", t_contained_by_clauses.len());

    // ================================
    //      Step 4
    // ================================

    let t_prime_subset_of_t: Vec<Vec<FormattedElement>> = t_contained_by_clauses
        .into_par_iter()
        .filter(|t_i| {
            let c_1 = &t_i[0];
            // 4.i. Pick any monomial from ANF(negation of c_1)
            let anf_c_1: Vec<u128> = cnf_to_neg_anf(&c_1.clause);
            let m_prime: u128 = anf_c_1[0].clone();

            // 4.ii. S = union of vars in c_2...c_k, excluding vars in c_1
            let mut s_union_of_other_vars: u128 = 0b0;
            for c_i in &t_i[1..] {
                s_union_of_other_vars |= c_i.vars;
            }
            s_union_of_other_vars = s_union_of_other_vars & !c_1.vars;

            // 4.iii. Sample random monomials supported on S
            let other_vars: Vec<u64> = decode_bit_vector(s_union_of_other_vars);
            let max_samples = if max_samples == 0 {
                DEFAULT_MAX_SAMPLES
            } else {
                max_samples
            };
            let sample_threshold = if sample_threshold == 0 {
                DEFAULT_SAMPLE_THRESHOLD
            } else {
                sample_threshold
            };

            let num_samples = max_samples.min(1usize << other_vars.len().min(63));
            let mut rng = rand::rng();

            let mut appearances = 0;
            for _ in 0..num_samples {
                let mut m_i_bit_vector: u128 = 0;
                for &v in &other_vars {
                    if rng.random_bool(0.5) {
                        m_i_bit_vector |= 1u128 << (v - INDEX_0_OFFSET);
                    }
                }
                // 4.iv. Check if m_prime*m_i appears in the ciphertext
                let product = m_prime | m_i_bit_vector;
                if unique_masks.contains(&product) {
                    appearances += 1;
                }
                if appearances >= sample_threshold {
                    return true;
                }
            }
            false
        })
        .collect();

    Ok(t_prime_subset_of_t)
}

#[pymodule]
fn retrieve_rs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FormattedElement>()?;
    m.add_function(wrap_pyfunction!(retrieve, m)?)?;
    Ok(())
}
