from ..parameters import *
from ..primitives.encrypt import _encrypt
from ..primitives.decrypt import _g
from ..attacks.attack import attack as run_attack
import os
import shutil
import argparse
import random
import time
import h5py
from types import SimpleNamespace
from tqdm import tqdm


def _format_hdf5(filepath):
    lines = []
    with h5py.File(filepath, "r") as f:
        def _visit(name, obj):
            if isinstance(obj, h5py.Dataset):
                lines.append(f'DATASET "{name}" {{')
                lines.append(f"   DATATYPE  {obj.dtype}")
                lines.append(f"   DATASPACE  SIMPLE {{ ( {obj.shape[0]} ) / ( {obj.shape[0]} ) }}")
                lines.append("   DATA {")
                for i, item in enumerate(obj):
                    lines.append(f"   ({i}): {list(item)}")
                lines.append("   }")
                lines.append("}")
        f.visititems(_visit)
    return "\n".join(lines)


def _evaluate(args):
    os.makedirs("tests", exist_ok=True)
    if EVALUATE_CLEARS_DATA:
        if os.path.isdir("tests") and len(os.listdir("tests")) > 0:
            for entry in os.listdir("tests"):
                entry_path = os.path.join("tests", entry)
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path)
                else:
                    os.remove(entry_path)
            print("tests directory cleared")

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
        ciphertext_dirpath = f"tests/c_{i}"
        
        while os.path.isdir(ciphertext_dirpath):
            i += 1
            ciphertext_dirpath = f"tests/c_{i}"
        os.mkdir(ciphertext_dirpath)

        encrypt_args = SimpleNamespace(i=i, plaintext=plaintext)
        start_time = time.time()
        _encrypt(encrypt_args)
        elapsed = time.time() - start_time

        ciphers.append(str(i))
        t += elapsed

        PLAINTEXT_FILEPATH = f"{ciphertext_dirpath}/plaintext_{i}.txt"
        CIPHERTEXT_TXT_FILEPATH = f"{ciphertext_dirpath}/ciphertext_{i}.txt"
        CIPHERTEXT_HDF5_FILEPATH = f"{ciphertext_dirpath}/ciphertext_{i}.hdf5"

        with open(PLAINTEXT_FILEPATH, "w") as file:
            file.write(str(plaintext))

        if INCLUDE_READABLE_CIPHERTEXT:
            with open(CIPHERTEXT_TXT_FILEPATH, "w") as file:
                file.write(_format_hdf5(CIPHERTEXT_HDF5_FILEPATH))

        if args.generate_only:
            s = f"ciphertext {i} created: y={plaintext}"
        else:
            decrypt_args = SimpleNamespace(n=i)
            decryption = _g(decrypt_args)

            attack_args = SimpleNamespace(i=i)
            try:
                attack = run_attack(attack_args)
            except Exception as e:
                print(e)
                return

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
    parser.add_argument('-g', '--generate-only', action='store_true')
    args = parser.parse_args()
    _evaluate(args)


if __name__ == "__main__":
    main()
