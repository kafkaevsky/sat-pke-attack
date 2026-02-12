use itertools::Itertools;
use pyo3::prelude::*;
use rand::seq::SliceRandom;
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
const MAX_SAMPLES: usize = 100;
const SAMPLE_THRESHOLD: usize = 30;

fn encode_bit_vector(m: Vec<u64>) -> u128 {
    let mut b: u128 = 0b0;
    for v in m {
        b |= 1u128 << (v - INDEX_0_OFFSET);
    }
    b
}

fn decode_bit_vector(v: u128) -> Vec<u64> {
    let mut m: Vec<u64> = Vec::new();
    for i in 0..128 {
        if 1 << i & v != 0 {
            m.push(i + INDEX_0_OFFSET);
        }
    }
    m
}

fn set_union(a: u128, b: u128) -> u128 {
    return a | b;
}

fn set_intersection(a: u128, b: u128) -> u128 {
    return a & b;
}

fn set_issubset(a: u128, b: u128) -> bool {
    return a & !b == 0;
}

#[pyfunction]
pub fn retrieve(
    ciphertext: Vec<Vec<u64>>,
    public_key: Vec<Vec<(u64, u64)>>,
    n: u128,
) -> PyResult<Vec<FormattedElement>> {
    // ================================
    //      Step 1
    // ================================
    if n > 128 {
        panic!("`N` was {}, must be <= 128", n);
    }

    let mut var_to_bit: HashMap<u64, u128> = HashMap::with_capacity(n as usize);
    let mut bit_to_var: HashMap<u128, u64> = HashMap::with_capacity(n as usize);
    for i in 2..(n as u64) + 2 {
        let encoding: u128 = encode_bit_vector(vec![i]);
        var_to_bit.insert(i, encoding);
        bit_to_var.insert(encoding, i);
    }

    let mut unique_masks: HashSet<u128> = HashSet::with_capacity(ciphertext.len());
    for m in ciphertext {
        let mut mask: u128 = 0b0;
        for v in m {
            mask |= var_to_bit[&v];
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
                .map(|mask_b| unique_masks_vec[i] | mask_b)
                .collect::<Vec<_>>()
        })
        .collect();

    eprintln!("s_combination_masks: {}", s_combination_masks.len());

    // ================================
    //      Step 2
    // ================================

    let mut public_key_formatted: Vec<FormattedElement> = Vec::with_capacity(public_key.len());
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
        let mut union_vars: u128 = 0;
        let mut clauses_vec: Vec<FormattedElement> = Vec::new();
        for c in &public_key_formatted {
            if c.vars & var_to_bit[&i] != 0 {
                union_vars |= c.vars;
                clauses_vec.push(c.clone());
            }
        }
        clauses_sharing_variable.insert(i, (clauses_vec, union_vars));
    }

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

    let mut t_contained_by_clauses: Vec<Vec<FormattedElement>> = Vec::new();
    for s_prime_i in s_prime_expanded_from_s {
        let mut t_i_hashset = HashSet::new();
        let mut b = s_prime_i.clone();
        while b != 0 {
            let var: u64 = (b.trailing_zeros() as u64) + INDEX_0_OFFSET;
            b &= b - 1;
            for candidate_clause in &clauses_sharing_variable[&var].0 {
                if (candidate_clause.vars & !s_prime_i) == 0 {
                    // vars in candidate_clause are contained by vars in s_prime_i
                    t_i_hashset.insert(candidate_clause.clone());
                }
            }
        }

        let t_i: Vec<FormattedElement> = Vec::from_iter(t_i_hashset);
        if t_i.len() > 0 {
            t_contained_by_clauses.push(t_i.clone());
        }
    }

    eprintln!("t_contained_by_clauses: {}", t_contained_by_clauses.len());

    // ================================
    //      Step 4
    // ================================

    fn cnf_to_neg_anf(clause: &Vec<(u64, u64)>) -> Vec<Vec<u64>> {
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

    // ========
    // 4.i.
    // ========
    let mut t_prime_subset_of_t: Vec<Vec<FormattedElement>> = Vec::new();

    for t_i in t_contained_by_clauses {
        let c_1 = &t_i[0];
        let anf_c_1: Vec<Vec<u64>> = cnf_to_neg_anf(&c_1.clause);
        let chosen_monomial: Vec<u64> = anf_c_1[0].clone();
        let m_prime_encoded_monomial: u128 = encode_bit_vector(chosen_monomial);

        let mut s_union_of_other_vars: u128 = 0b0;
        for c_i in &t_i[1..] {
            s_union_of_other_vars |= c_i.vars;
        }
        s_union_of_other_vars = set_intersection(s_union_of_other_vars, !m_prime_encoded_monomial);

        let other_vars: Vec<u64> = decode_bit_vector(s_union_of_other_vars);
        let num_samples = MAX_SAMPLES.min(1usize << other_vars.len().min(63));
        let mut rng = rand::rng();

        let mut appearances = 0;
        for i in 0..num_samples {
            let mut m_i_bit_vector: u128 = 0;
            for &v in &other_vars {
                if rng.random_bool(0.5) {
                    m_i_bit_vector |= 1u128 << (v - INDEX_0_OFFSET);
                }
            }
            let product = m_prime_encoded_monomial | m_i_bit_vector;
            if unique_masks.contains(&product) {
                appearances += 30;
            }
            if appearances >= SAMPLE_THRESHOLD {
                t_prime_subset_of_t.push(t_i);
                break;
            }
        }

        for t_prime_i in &t_prime_subset_of_t {
            println!("===============");
            for m in t_prime_i {
                println!("{:b}", m.vars);
            }
        }
    }

    // ========
    // 4.ii.
    // ========

    Ok(public_key_formatted)
}

#[pymodule]
fn retrieve_rs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FormattedElement>()?;
    m.add_function(wrap_pyfunction!(retrieve, m)?)?;
    Ok(())
}
