import os
import hashlib
import time
import multiprocessing

class MerkleNode:
    def __init__(self, hash_value, left=None, right=None):
        self.hash = hash_value
        self.left = left
        self.right = right

class MerkleTree:
    def __init__(self, file_path, block_size=1024):
        self.file_path = file_path
        self.block_size = block_size
        self.n_proc = multiprocessing.cpu_count()
        self.root = self.build_tree()

    def build_tree(self):
        file_size = os.path.getsize(self.file_path)
        block_hashes = []

        with open(self.file_path, 'rb') as f:
            for _ in range(0, file_size, self.block_size):
                data = f.read(self.block_size)
                hashed_data = hashlib.sha256(data).digest()
                node = MerkleNode(hashed_data)
                block_hashes.append(node)

        return self.build_tree_from_leaves(block_hashes)

    def build_tree_from_leaves(self, leaves):
        if len(leaves) == 1:
            return leaves[0]
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        init = list(zip(leaves[::2],leaves[1::2]))
        parents = []
        def append_parents(response):
            parents.extend(response)
        with multiprocessing.Pool(self.n_proc * 2) as p:
            p.starmap_async(self.hash_pair,init,callback = append_parents)
            p.close()
            p.join()
        return self.build_tree_from_leaves(parents)

    def hash_pair(self, left, right):
        name = multiprocessing.current_process().name
        # print(f"[{name}] value 1: {left.hash.hex()}, value 2: {right.hash.hex()}")
        hasher = hashlib.sha256()
        hasher.update(left.hash)
        hasher.update(right.hash)
        node = MerkleNode(hasher.digest(), left, right)
        return node

    @property
    def root_hash(self):
        return self.root.hash if self.root else None
        # return 'lol'

    def update_block(self, block_index, new_data):
        with open(self.file_path, 'r+b') as f:
            f.seek(block_index * self.block_size)
            f.write(new_data)
        
        self.root = self.build_tree()


if __name__ == '__main__':
    start = time.time()
    # merkletree = MerkleTree('C:/9_ATV_11_RK3318_HK5230_HS2734_AP6330.img')
    merkletree = MerkleTree('C:/Users/vovan/Desktop/3D/Gloss_Garage_A_cap.stl')
    end = time.time()
    print(merkletree.root_hash.hex())
    # merkletree.root_hash()
    print('time: ' , end-start)