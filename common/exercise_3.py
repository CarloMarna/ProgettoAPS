import hashlib
from cryptography.fernet import Fernet


def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def build_merkle_tree(data_list):
    # the tree is represented by a list of lists;
    # the i-th list contains the (k-i+1)-th level of the tree (from leaves to root, where k is the height of the tree)

    # compute the hash for each leaf (corresponding to each data block), then create the tree
    leaves = [sha256(data) for data in data_list]
    tree = [leaves]

    #
    while len(tree[-1]) > 1:
        # we refer to the current level to build the next one
        current_level = tree[-1]

        # Merkle trees are always complete, therefore we duplicate the last leaf within the current level
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])

        # nodes in the next level will be built by hashing the concatenation of the children's hash
        next_level = [
            sha256(current_level[i] + current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]

        # the next level is now completed, we insert it into the tree
        tree.append(next_level)

    # we return the pair (root node, tree)
    return tree[-1][0], tree


def fernet_encrypt(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode('utf-8'))


def fernet_decrypt(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode('utf-8')


def verify_data(decrypted_data, leaf_index, merkle_root, leaves, tree):
    """Verify data against a leaf and a merkle tree.
    :param decrypted_data: Decrypted data.
    :param leaf_index: Leaf index.
    :param merkle_root: Merkle root to verify.
    :param leaves: Leaves to verify.
    :param tree: Tree to verify."""

    # we hash the data
    data_hash = sha256(decrypted_data)

    # this holds for this example only: if we already have the
    # data, we can just check if the hash matches
    if data_hash != leaves[leaf_index]:
        return False

    current_hash = data_hash
    # traverse the whole tree except for the root, starting from the leaves level
    for level in tree[:-1]:
        # we identify the sibling needed to verify the hash...
        if leaf_index % 2 == 0:
            sibling_index = leaf_index + 1
        else:
            sibling_index = leaf_index - 1

        # ... and we get it here
        sibling_hash = (
            level[sibling_index]
            if sibling_index < len(level)
            else level[-1]
        )

        # here we recompute the combined hash and we bring it to the upper levels
        if leaf_index % 2 == 0:
            current_hash = sha256(current_hash + sibling_hash)
        else:
            current_hash = sha256(sibling_hash + current_hash)

        # move up to parent index
        leaf_index //= 2

    # the verification holds iff the root matches with the computed hash
    return current_hash == merkle_root


if __name__ == "__main__":
    data_list = ["message_1", "message_2", "message_3", "message_4"]

    merkle_root, tree = build_merkle_tree(data_list)
    key = Fernet.generate_key()

    for i, level in enumerate(tree):
        print(f'Livello {len(tree) - i}, numero nodi: {len(level)}', ', '.join(level))

    encrypted_data = [fernet_encrypt(data, key) for data in data_list]
    leaf_index = 2
    decrypted_data = fernet_decrypt(encrypted_data[leaf_index], key)

    print(f"Decrypted data: {decrypted_data}")

    if verify_data(decrypted_data, leaf_index, merkle_root, tree[0], tree):
        print(f"Data '{decrypted_data}' is verified using the Merkle tree!")
    else:
        print(f"Data verification failed for '{decrypted_data}'!")
