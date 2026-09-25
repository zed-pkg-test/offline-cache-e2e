#!/usr/bin/env python3
from itertools import product

def usable(lock_present: bool, digest_match: bool, artifact_present: bool) -> bool:
    return lock_present and digest_match and artifact_present

def main() -> None:
    explored = 0
    for state in product((False,True), repeat=3):
        explored += 1
        assert usable(*state) == all(state)
    assert not usable(True, False, True)
    print(f'offline cache digest model: {explored} states')

if __name__ == '__main__': main()
