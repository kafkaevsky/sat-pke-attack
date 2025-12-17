from ..parameters import *
from ..helpers import *
import os
import argparse
import random
from tqdm import tqdm

def _evaluate(args):
    os.makedirs("tests", exist_ok=True)
    if EVALUATE_CLEARS_DATA:
        if os.path.isdir("tests") and len(os.listdir("tests")) > 0:
            run_zsh("rm -rf $DATA_DIRECTORY/*")
            print(f"tests directory cleared")

    ciphers = []
    t = 0
    attack_results_counts = {"successes": 0, "failures": 0, "errors": 0}
    progress_bar = tqdm(
        range(args.n),
        postfix=attack_results_counts,
        bar_format="{l_bar}{bar}|[{n_fmt}/{total_fmt}{postfix}]",
    )
    for _ in progress_bar:

        plaintext = PLAINTEXT
        if PLAINTEXT == "r":
            plaintext = random.getrandbits(1)

        i = 1
        ciphertext_dirpath = f"{"tests"}/c_{i}"
        
        while os.path.isdir(ciphertext_dirpath):
            i += 1
            ciphertext_dirpath = f"{"tests"}/c_{i}"
        os.mkdir(ciphertext_dirpath)


        cmd = f'time python3 -m validator.primitives.encrypt -i "{i}" -y "{plaintext}"'
        res = run_zsh(cmd, capture=True)

        ciphers.append(str(i))
        t += float(res.stderr[:-2])

        PLAINTEXT_FILEPATH = f"{ciphertext_dirpath}/plaintext_{i}.txt"
        CIPHERTEXT_TXT_FILEPATH = f"{ciphertext_dirpath}/ciphertext_{i}.txt"
        CIPHERTEXT_HDF5_FILEPATH = f"{ciphertext_dirpath}/ciphertext_{i}.hdf5"

        with open(PLAINTEXT_FILEPATH, "w") as file:
            file.write(str(plaintext))

        if INCLUDE_READABLE_CIPHERTEXT:
            with open(CIPHERTEXT_TXT_FILEPATH, "w") as file:
                cmd = f"h5dump --width=1 '{CIPHERTEXT_HDF5_FILEPATH}'"
                cipher = run_zsh(cmd, capture=True)
                file.write(cipher.stdout)

        cmd = f"python3 -m validator.primitives.decrypt {i}"
        decryption = int(run_zsh(cmd, capture=True).stdout[:-1])

        cmd = f"python3 -m validator.attacks.attack {i}"
        attack = int(run_zsh(cmd, capture=True).stdout[:-1])

        code = attack
        if code >= 0:
            code = int(code == decryption)
        if code < 0:
            code = -1

        RESULT_STRINGS_PLURAL = {1: "successes", 0: "failures", -1: "errors"}
        RESULT_STRINGS_SINGULAR = {1: "success", 0: "failure", -1: "error"}

        attack_results_counts[RESULT_STRINGS_PLURAL.get(code)] += 1
        s = f"ciphertext {i}: {RESULT_STRINGS_SINGULAR[code]:<10} y={decryption} \u2227 attack(pub,c)={attack}"
        progress_bar.write(s)
        progress_bar.set_postfix(attack_results_counts, refresh=True)


def main():
    parser = argparse.ArgumentParser(prog="Evaluate")
    parser.add_argument("n", type=int)
    args = parser.parse_args()
    _evaluate(args)


if __name__ == "__main__":
    main()
