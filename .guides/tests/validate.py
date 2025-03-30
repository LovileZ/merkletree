import eth_account
import hexbytes
from web3 import Web3
from pathlib import Path
import sys
import json
from web3.middleware import ExtraDataToPOAMiddleware  # Necessary for POA chains
import random
import string



class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def connectTo(chain):
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"  # AVAX C-chain testnet

    if chain == 'bsc':
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"  # BSC testnet

    if chain in ['avax', 'bsc']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        # inject the poa compatibility middleware to the innermost layer
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def hash_list(value_list):
    if isinstance(value_list[0], int):
        y = "".join(str(x) for x in value_list)
    else:
        y = "".join([x.hex() for x in value_list])
    hash = Web3.solidity_keccak(['string'], [y])
    return hash


def validate(code_path):
    try:
        import submitProof
    except Exception as e:
        print(f"Could not load submitProof.py")
        sys.exit(1)

    chain = 'bsc'
    score = 0
    primes, leaves, tree = [], [], []


    # Testing setup
    # Connect to Merkel contract (not a student test)
    try:
        test_dir = Path(__file__).parent.absolute()
        # Get contract Address and ABI
        with open(test_dir / "contract_info.json", "r") as f:
            d = json.load(f)
            d = d[chain]
        address = d['address']
        abi = d['abi']

        # Get proof.txt data
        with open(test_dir / "proofs.txt", "r") as f:
            proof_dict = json.load(f)
    except Exception as e:
        print(f"{e}\nTesting support files are missing!\nPlease contact your instructor")
        return score

    try:
        w3 = connectTo(chain)
    except Exception as e:
        print(f"{e}\nFailed to connect to chain. Please try again.\n"
              f"If this problem persists, please contact your instructor")
        return score

    try:
        contract = w3.eth.contract(abi=abi, address=address)
    except Exception as e:
        print(f"{e}\nFailed to create contract object. Please try again.\n"
              f"If this problem persists, please contact your instructor")
        return score

    try:
        onchain_root = contract.functions.merkleRoot().call()
    except Exception as e:
        print(f"{e}\nFailed to retrieve contract information. Please try again.\n"
              f"If this problem persists, please contact your instructor")
        return score

    # Test 1 "correct primes" 25% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: generate_primes(num_primes)")
    try:
        num_primes = 8192
        primes = submitProof.generate_primes(num_primes)
        assert num_primes == len(primes), f"your primes list does not contain {str(num_primes)} values"
        assert proof_dict['primes'] == hash_list(primes).hex(), "your primes list does not contain " \
                                                                "the correct values"
        score += 25
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: primes list is correct")
    except Exception as e:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: {e}")

    # Test 2 "Correct leaf format" 5% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: convert_leaves(primes_list)")
    try:
        leaves = submitProof.convert_leaves(primes)
        for leaf in leaves:
            assert isinstance(leaf, bytes), "your leaves aren't in bytes format"
            assert 32 == len(leaf), "your leaves aren't in bytes 32 format"

        score += 5
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: leaves are correctly formatted")
    except Exception as e:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: {e}")

    # Test 3 "Correct root" 10% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: build_merkle(leaves)")
    try:
        tree = submitProof.build_merkle(leaves)
        assert 14 == (len(tree)), "your Merkel tree has the incorrect number of levels"
        assert isinstance(tree[13][0], hexbytes.main.HexBytes), "your root is not in HexBytes format"
        assert onchain_root == tree[13][0], "your root value is incorrect"

        score += 10
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: root hash is correct")
    except Exception as e:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: {e}")

    # Test 4/5 tests setup
    proofs = []
    num_tests = 5
    for test in range(num_tests):
        i = random.randint(0, len(primes) - 1)  # Pick a random leaf to test student code
        proof = submitProof.prove_merkle(tree, i)
        proofs.append([i, proof[0], hash_list(proof)])

    bad_sibling, bad_proof = 0, 0
    for result in proofs:
        if proof_dict[str(result[0])]['sibling'] != str(result[1]):
            bad_sibling += 1
        if proof_dict[str(result[0])]['proof hash'] != str(result[2].hex()):
            bad_proof += 1

    # Test 4 "Correct sibling" 10% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: prove_merkel(merkel_tree, random_indx) test#1")
    if not bad_sibling:
        score += 10
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: sibling leaf was correct on {num_tests} tests")
    else:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: your sibling leaf was incorrect on {bad_sibling} of {num_tests}")
    # Test 5 "Correct proof" 25% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: prove_merkel(merkel_tree, random_indx) test#2")
    if not bad_proof:
        score += 25
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: proof was correct on {num_tests} tests")
    else:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: your proof was incorrect on {bad_proof} of {num_tests}")

    # Test 6 "valid signature" 10% of grade
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: sign_challenge(challenge)")
    challenge = ''.join(random.choice(string.ascii_letters) for _ in range(32))

    try:
        eth_addr, sig = submitProof.sign_challenge(challenge)
    except Exception as e:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: your sign_challenge failed\n{e}")
        return 0

    try:
        assert isinstance(eth_addr, str), f"Your address should be type <class 'str'> " \
                                          f"but was type {type(eth_addr)} instead."
        assert isinstance(sig, str), f"Your signature should be type <class 'str'> " \
                                     f"but was type {type(sig)} instead. Did you use '.hex()'?"
        # verify signed message
        eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
        recovered_addr = eth_account.Account.recover_message(eth_encoded_msg, signature=sig)
        assert recovered_addr == eth_addr, f"Signature failed to validate\n" \
                                           f"signature = {sig}\naddress = {eth_addr}"

        score += 10
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: signature validated")
    except AssertionError as e:
        # If signature doesn't validate, test 7 (verifying ownership)
        # will not be run on the student provided address
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: {e}")
        return score

    # Test 7 "Claimed prime" the last 15% of grade. 100% is automatically awarded
    # for passing this test (and the signature test #6) if the student used another
    # means (not this code) of claiming the prime
    print(f"{bcolors.OKBLUE}TESTING{bcolors.ENDC}: Checking that the provided account has claimed a prime")
    try:
        prime = contract.functions.getPrimeByOwner(eth_addr).call()
        if isinstance(prime, bytes):
            prime = int.from_bytes(prime, 'big')
    except Exception as e:
        print(f"{e}\nFailed to retrieve contract information. Please try again.\n"
              f"If this problem persists, please contact your instructor")
        return score

    # If student hasn't claimed a prime yet use their code to attempt to claim one
    if prime == 0:
        try:  # Catch exception in student's code (typically sign and send)
            submitProof.merkle_assignment()
            prime = contract.functions.getPrimeByOwner(eth_addr).call()
            if isinstance(prime, bytes):
                prime = int.from_bytes(prime, 'big')
        except Exception as e:
            print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: Your code did not run correctly\n{e}")

    if prime != 0:
        score = 100
        print(f"\t{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: You successfully registered {prime}")
    else:
        print(f"\t{bcolors.FAIL}ERROR{bcolors.ENDC}: You failed to register a prime\ngetPrimeByOwner({eth_addr}) returned 0")
    return score


if __name__ == "__main__":
    final_score = validate("./")
    print(f"Score = {final_score}%")
