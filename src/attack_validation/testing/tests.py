from collections import defaultdict
from attack_validation.parameters import *
import subprocess
import os
import argparse
import random

my_env = os.environ.copy()


def run_zsh(cmd, capture=False):
    return subprocess.run(
        cmd,
        env=my_env,
        shell=True,
        text=True,
        executable="/bin/zsh",
        capture_output=capture,
    )


def generate(n):
    os.makedirs(my_env["DATA_DIRECTORY"], exist_ok=True)
    if GENERATE_CLEARS_DATA:
        if os.path.isdir(my_env["DATA_DIRECTORY"]) and len(os.listdir(my_env["DATA_DIRECTORY"])) > 0:
            run_zsh("rm -rf $DATA_DIRECTORY/*")
            print(f"tests directory cleared")

    ciphers = []
    t = 0
    codebreak_results = defaultdict(int)
    for _ in range(n):

        plaintext = PLAINTEXT
        if PLAINTEXT == "r":
            plaintext = random.getrandbits(1)

        #####

        next_n = 0
        next_dir = f"{my_env["DATA_DIRECTORY"]}/cipher_{next_n}_dir"
        while os.path.isdir(next_dir):
            next_n += 1
            next_dir = f"{my_env["DATA_DIRECTORY"]}/cipher_{next_n}_dir"
        os.mkdir(next_dir)

        #####

        encrypt_stdout_n__txt = "/dev/null"
        if INCLUDE_ENCRYPT_STDOUT_N__TXT:
            encrypt_stdout_n__txt = f"{next_dir}/encrypt_stdout_{next_n}.txt"

        #####

        cmd = f'time python3 -m attack_validation.primitives.encrypt -n "{next_n}" -y "{plaintext}" >{encrypt_stdout_n__txt}'
        res = run_zsh(cmd, capture=True)
        print(f"cipher {next_n} created in {res.stderr[:-1]}")

        ciphers.append(str(next_n))
        t += float(res.stderr[:-2])

        ### plaintext_n__txt
        path = f"{next_dir}/plaintext_{next_n}.txt"
        with open(path, "w") as file:
            file.write(str(plaintext))

        ### ciphertext_n__txt
        if INCLUDE_CIPHERTEXT_N__TXT:
            path = f"{next_dir}/ciphertext_{next_n}.txt"
            with open(path, "w") as file:
                cmd = f"h5dump --width=1 '{next_dir}/ciphertext_{next_n}.hdf5'"
                cipher = run_zsh(cmd, capture=True)
                file.write(cipher.stdout)

        ### codebreak_success_n__txt
        if AUTOMATICALLY_TEST_CODEBREAK:
            cmd = f"python3 -m attack_validation.primitives.decrypt {next_n}"
            decryption = int(run_zsh(cmd, capture=True).stdout[:-1])
            # print(decryption)

            cmd = f"python3 -m attack_validation.attacks.attack {next_n}"
            codebreak = int(run_zsh(cmd, capture=True).stdout[:-1])
            # print(codebreak)

            # decryption == codebreak: "success"
            # decryption != codebreak: "failure"
            # codebreak == -1: "problem running algorithm (error 1)"
            # codebreak == -2: "problem running algorithm (error 2)"
            results = "unknown"

            if decryption in [0,1] and decryption == codebreak:
                results = "success"
            if decryption in [0,1] and decryption != codebreak:
                results = "failure"
            if codebreak in [-1]:
                results = "problem running algorithm (error-1)"
            if codebreak in [-2]:
                results = "problem running algorithm (error-2)"

            codebreak_results[results] += 1
            
            print (f"y = {decryption} \u2227 attack(pub,c) = {codebreak}       =>      {results}")
            for r in codebreak_results.keys():
                key = r
                value = codebreak_results[r]
                print(f"{round(100*value/len(ciphers), 2)}% ({value}/{len(ciphers)}): {key}")
            print("\n\n")

    if n > 1:
        print(f"{n} ciphers ({", ".join(ciphers)}) created in {round(t,2)}s")

def main():
    parser = argparse.ArgumentParser(prog="Generate")
    parser.add_argument("n", type=int)
    args = parser.parse_args()

    generate(args.n)


if __name__ == "__main__":
    main()