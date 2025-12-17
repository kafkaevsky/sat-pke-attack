import h5py
import numpy as np
import argparse


def _g(args):

    PRIVATE_KEY_FILEPATH = f"tests/c_{args.n}/private_key_{args.n}.txt"
    CIPHERTEXT_FILEPATH = f"tests/c_{args.n}/ciphertext_{args.n}.hdf5"

    with open(PRIVATE_KEY_FILEPATH, "r") as file:
        priv = file.read()
        with h5py.File(CIPHERTEXT_FILEPATH, "r") as file:
            if "ciphertext" in file:

                def assign(x):
                    x = int(x)
                    return int(priv[x - 2])

                v__assign = np.vectorize(assign)
                v__assign_conditional = lambda term: (
                    v__assign(term) if len(term) > 0 else []
                )

                expression = np.array(file["ciphertext"][:])
                expression = [all(v__assign_conditional(term)) for term in expression]
                expression = filter(lambda term: term, expression)
                expression = list(expression)

                size = sum(1 for _ in expression)
                return size % 2


def main():
    parser = argparse.ArgumentParser(prog="Decrypt")
    parser.add_argument("n", type=int)
    args = parser.parse_args()
    y = _g(args)
    print(y)

if __name__ == "__main__":
    main()
