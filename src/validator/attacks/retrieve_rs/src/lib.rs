use pyo3::prelude::*;
use rand::RngExt;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
struct LinearizationTask {
    c_i: Vec<u128>,
    r_var_bits: Vec<u128>,
    start_col: usize,
    n_subsets: usize,
}

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

fn toggle_column(row_words: &mut [u64], col: usize) {
    let word_i = col / 64;
    let bit_i = col % 64;
    row_words[word_i] ^= 1u64 << bit_i;
}

fn merge_mask_maps(
    mut left: HashMap<u128, Vec<u64>>,
    right: HashMap<u128, Vec<u64>>,
    words: usize,
) -> HashMap<u128, Vec<u64>> {
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    for (term, right_words) in right {
        let entry = left.entry(term).or_insert_with(|| vec![0u64; words]);
        for (x, y) in entry.iter_mut().zip(right_words.iter()) {
            *x ^= *y;
        }
    }
    left
}

#[pyfunction]
pub fn linearization_build(
    ciphertext: Vec<Vec<u64>>,
    t_prime: Vec<Vec<FormattedElement>>,
) -> PyResult<(Vec<Vec<u64>>, Vec<u8>, Option<usize>, usize, bool)> {
    let ciphertext_set: HashSet<u128> = ciphertext
        .into_iter()
        .map(|m| m.into_iter().fold(0u128, |acc, x| acc | encode_bit_vector(x)))
        .collect();

    let mut tasks: Vec<LinearizationTask> = Vec::new();
    let mut coefficient_count: usize = 0;

    for t_prime_i in &t_prime {
        let len_i = t_prime_i.len();
        if len_i == 0 {
            continue;
        }

        let clause_anfs: Vec<Vec<u128>> = t_prime_i
            .iter()
            .map(|element| cnf_to_neg_anf(&element.clause))
            .collect();

        for i in 0..len_i {
            let mut r_vars_mask: u128 = 0;
            for (j, element) in t_prime_i.iter().enumerate() {
                if i != j {
                    r_vars_mask |= element.vars;
                }
            }

            let mut r_var_bits: Vec<u128> = Vec::with_capacity(r_vars_mask.count_ones() as usize);
            let mut bits = r_vars_mask;
            while bits != 0 {
                let bit = bits.trailing_zeros();
                r_var_bits.push(1u128 << bit);
                bits &= bits - 1;
            }

            if r_var_bits.len() >= usize::BITS as usize {
                return Err(PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
                    "too many variables in R_vars for subset enumeration",
                ));
            }

            let n_subsets: usize = 1usize << r_var_bits.len();
            let start_col = coefficient_count;
            coefficient_count = coefficient_count
                .checked_add(n_subsets)
                .ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
                        "coefficient_count overflowed usize",
                    )
                })?;

            tasks.push(LinearizationTask {
                c_i: clause_anfs[i].clone(),
                r_var_bits,
                start_col,
                n_subsets,
            });
        }
    }

    let words: usize = coefficient_count.div_ceil(64);

    let term_to_mask_words: HashMap<u128, Vec<u64>> = tasks
        .par_iter()
        .map(|task| {
            let mut local_map: HashMap<u128, Vec<u64>> = HashMap::new();

            for subset_i in 0..task.n_subsets {
                let mut r_term: u128 = 0;
                for (bit_i, var_bit) in task.r_var_bits.iter().enumerate() {
                    if ((subset_i >> bit_i) & 1usize) != 0 {
                        r_term |= *var_bit;
                    }
                }

                let col = task.start_col + subset_i;

                for &c_term in &task.c_i {
                    let literals = r_term | c_term;
                    let row_words = local_map.entry(literals).or_insert_with(|| vec![0u64; words]);
                    toggle_column(row_words, col);
                }
            }

            local_map
        })
        .reduce(
            || HashMap::new(),
            |left, right| merge_mask_maps(left, right, words),
        );

    let mut term_and_rows: Vec<(u128, Vec<u64>)> = term_to_mask_words.into_iter().collect();
    term_and_rows.sort_by_key(|(term, _)| *term);

    let mut row_masks_words: Vec<Vec<u64>> = Vec::with_capacity(term_and_rows.len());
    let mut b: Vec<u8> = Vec::with_capacity(term_and_rows.len());
    let mut constant_row: Option<usize> = None;

    for (row_i, (term, row_words)) in term_and_rows.into_iter().enumerate() {
        if term == 0 {
            constant_row = Some(row_i);
        }
        b.push(if ciphertext_set.contains(&term) { 1 } else { 0 });
        row_masks_words.push(row_words);
    }

    let constant_in_ciphertext = ciphertext_set.contains(&0);
    Ok((
        row_masks_words,
        b,
        constant_row,
        coefficient_count,
        constant_in_ciphertext,
    ))
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
    m.add_function(wrap_pyfunction!(linearization_build, m)?)?;
    Ok(())
}
