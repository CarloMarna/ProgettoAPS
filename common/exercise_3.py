import hashlib
from cryptography.fernet import Fernet
from typing import List

def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def build_merkle_tree(data_list):
    leaves = [sha256(data) for data in data_list]
    tree = [leaves]

    while len(tree[-1]) > 1:
        current_level = tree[-1]

        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])

        next_level = [
            sha256(current_level[i] + current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]
        tree.append(next_level)
    return tree[-1][0], tree

def verify_merkle_proof(h_i: str, proof: List[str], root: str, index: int) -> bool:
        """Verifica che h_i + π_i risalga alla Merkle Root"""
        current_hash = h_i
        for sibling in proof:
            if index % 2 == 0:
                current_hash = sha256(current_hash + sibling)
            else:
                current_hash = sha256(sibling + current_hash)
            index //= 2
        return current_hash == root

def compute_merkle_proofs(leaves, tree):
    """Costruisce la lista completa di Merkle proof π_i per ogni attributo"""
    proofs_with_index = []
    for i in range(len(leaves)):
        proof = []
        index = i
        idx_for_proof = i  
        for level in tree[:-1]:
            sibling = index + 1 if index % 2 == 0 else index - 1
            if 0 <= sibling < len(level):
                proof.append(level[sibling])
            index //= 2
        proofs_with_index.append({
            "index": idx_for_proof,
            "proof": proof
        })
    return proofs_with_index
