try:
    import retrieve_rs
except Exception:
    retrieve_rs = None
import argparse
import h5py


def _linearization(ciphertext_file, public_key_file):

    if "ciphertext" not in ciphertext_file:
        raise KeyError()

    ciphertext_set = {tuple(m) for m in ciphertext_file["ciphertext"]}


def main():

    parser = argparse.ArgumentParser(prog="Attack")
    parser.add_argument("i", type=int)
    args = parser.parse_args()

    if retrieve_rs is None:
        raise RuntimeError(
            """`retrieve_rs` module not built. 
            Run `source venv/bin/activate && maturin develop --manifest-path src/validator/attacks/retrieve_rs/Cargo.toml`"""
        )
    
    print(retrieve_rs.retrieve([5, 5, 12351]))

    CIPHERTEXT_DIRPATH = f"tests/c_{args.i}"
    CIPHERTEXT_FILEPATH = f"{CIPHERTEXT_DIRPATH}/ciphertext_{args.i}.hdf5"
    CLAUSES_FILEPATH = f"{CIPHERTEXT_DIRPATH}/public_key_{args.i}.txt"

    with h5py.File(CIPHERTEXT_FILEPATH, "r") as CIPHERTEXT_FILE:
        with open(CLAUSES_FILEPATH, "r") as CLAUSES_FILE:
            y = _linearization(CIPHERTEXT_FILE, CLAUSES_FILE)
            print(y)


if __name__ == "__main__":
    main()
