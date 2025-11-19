import h5py
import numpy as np
import argparse


def g(n):

    with open(f"tests/cipher_{n}_dir/private_key_{n}.txt", "r") as file:
        priv = file.read()
        with h5py.File(f"tests/cipher_{n}_dir/ciphertext_{n}.hdf5", "r") as file:
            if "expression" in file:

                def assign(x):
                    x = int(x)
                    if x == 1:
                        return x
                    return int(priv[x - 2])

                v__assign = np.vectorize(assign)
                v__assign_conditional = lambda term: (
                    v__assign(term) if len(term) > 0 else []
                )

                expression = file["expression"]
                expression = np.array(expression[:])
                expression = [all(v__assign_conditional(term)) for term in expression]
                expression = filter(lambda term: term, expression)
                expression = list(expression)

                size = sum(1 for _ in expression)
                g_res = size % 2
                return g_res


def decrypt(n, formatted_printout=False):
    g_decryption = g(n)

    if formatted_printout:
        with open(f"tests/cipher_{n}_dir/plaintext_{n}.txt", "r") as file:
            y = int(file.read())
            print(f"decryption for cipher {n} with plaintext y={y}:")
            print(f"g(priv)={g_decryption}      =>      y=1")
            if y ^ g_decryption:
                print("DECRYPTION FAILURE")
    return g_decryption

def main():
    parser = argparse.ArgumentParser(
        prog="Encrypt",
        description="Generates ciphertext file from plaintext based on Sebastian E. Schmittner's SAT-Based Public Key Encryption Scheme",
        epilog="https://eprint.iacr.org/2015/771.pdf",
    )

    parser.add_argument("n", type=int)
    args = parser.parse_args()

    g_decryption = decrypt(args.n)
    print(g_decryption)

if __name__ == "__main__":
    main()