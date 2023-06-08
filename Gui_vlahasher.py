import customtkinter
import tkinter
import hashlib
import sys
import os
import time
from tkinter import filedialog
import matplotlib.pyplot as plt
import networkx as nx
import graphviz as gv

LIMIT_SIZE = 2000000


class MerkleNode:
    def __init__(self, hash_value, left=None, right=None):
        self.hash = hash_value
        self.left = left
        self.right = right

class MerkleTree:
    def __init__(self, file_path, hash_func='SHA-256', block_size=1024):
        self.file_path = file_path
        self.block_size = block_size
        self.time_read_file = 0
        self.hash_func = hash_func
        self.height=0
        self.root = self.build_tree()

    def build_tree(self):
        file_size = os.path.getsize(self.file_path)
        block_hashes = []
        start=time.time()
        with open(self.file_path, 'rb') as f:
            for _ in range(0, file_size, self.block_size):
                data = f.read(self.block_size)
                if (self.hash_func == 'SHA-256'):
                    hashed_data = hashlib.sha256(data).digest()
                elif (self.hash_func == 'MD-5'):
                    hashed_data = hashlib.md5(data).digest()
                node = MerkleNode(hashed_data)
                block_hashes.append(node)
                

        self.time_read_file = time.time()-start
        print('read time file: ', self.time_read_file)

        if len(block_hashes) % 2 == 1:
            block_hashes.append(block_hashes[-1])
        return self.build_tree_from_leaves(block_hashes)

    def build_tree_from_leaves(self, leaves):
        if len(leaves) == 1:
            return leaves[0]
        self.height=self.height+1
        parents = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            if i + 1 < len(leaves):
                right = leaves[i+1]
                parents.append(self.hash_pair(left, right))
            else:
                parents.append(left)
        return self.build_tree_from_leaves(parents)

    def hash_pair(self, left, right):
        if (self.hash_func == 'SHA-256'):
            hasher = hashlib.sha256()
        elif (self.hash_func == 'MD-5'):
            hasher = hashlib.md5()
        hasher.update(left.hash)
        hasher.update(right.hash)
        node = MerkleNode(hasher.digest(), left, right)
        return node
    def get_root(self):
        return self.root

    @property
    def root_hash(self):
        return self.root.hash if self.root else None
    
    def get_time_read_file(self):
        return self.time_read_file
    
def vizual_tree(root):
    g = gv.Graph(format='png')
    g.attr('node', shape='square')
    g.node(root.hash.hex(),root.hash.hex())
    build_viz_tree(g, root)
    g.render('binary_tree', view=True)

def build_viz_tree(g, node):
    print(node.hash.hex())


    if node.left is None and node.right is None:
        return
    
    if node.left is not None:
        g.node(node.left.hash.hex(),node.left.hash.hex())
        g.edge(node.hash.hex(),node.left.hash.hex())
        build_viz_tree(g,node.left)
    if node.right is not None:
        g.node(node.right.hash.hex(),node.right.hash.hex())
        g.edge(node.hash.hex(),node.right.hash.hex())
        build_viz_tree(g,node.right)

    return

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.filepath = tkinter.StringVar()

        def radiobutton_event():
            print("radiobutton toggled, current value:", self.radio_var.get())


        self.title("Merkle Tree")
        self.geometry("700x500")
        self.grid_columnconfigure((1,2), weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.radio_var = tkinter.IntVar(value=1)
        self.FLAG_VIZ=False

        my_font = customtkinter.CTkFont(family="Arial", size=18)

        self.tree_frame = customtkinter.CTkFrame(self)
        self.content_frame = customtkinter.CTkFrame(self)
        self.result_frame =  customtkinter.CTkFrame(self,height=150)

        self.label_tree_frame = customtkinter.CTkLabel(self.tree_frame, text="Hash function", fg_color="transparent", justify='center', font=my_font)
        self.label_tree_frame.grid(row=0,column=0, sticky='ew', pady=10)
        self.tree_frame.columnconfigure(0, weight=1)

        radiobutton_1 = customtkinter.CTkRadioButton(self.tree_frame, text="SHA-256",
                                             command=radiobutton_event, variable= self.radio_var, value=1)
        radiobutton_1.grid(row=1,column=0,pady=10)
        radiobutton_2 = customtkinter.CTkRadioButton(self.tree_frame, text="MD-5",
                                             command=radiobutton_event, variable= self.radio_var, value=2)
        radiobutton_2.grid(row=2,column=0,pady=10)

        self.label_content_frame = customtkinter.CTkLabel(self.content_frame, text="Decrypt", fg_color="transparent", justify='center', font=my_font)
        self.label_content_frame.grid(row=0, column=0, sticky='ew',  pady=10, columnspan=3)
        

        self.file_button =customtkinter.CTkButton(self.content_frame,text="Выбрать файл",command=self.choose_file)
        self.file_button.grid(row=1, column=0, sticky='we',  pady=10, padx=10)

        self.filepath_label = customtkinter.CTkLabel(self.content_frame, text = 'Файл не выбран', fg_color='#C7C7C7', padx=5, pady=5, corner_radius=5)
        self.filepath_label.grid(row=1, column=1, sticky='we', columnspan=2, padx=(0,10))
        self.content_frame.columnconfigure(1, weight=1)

        self.entry_hash = customtkinter.CTkEntry(self.content_frame, placeholder_text='Введите хэш-значение', fg_color='#C7C7C7')
        self.entry_hash.grid(row=2, column=0, columnspan=3,  sticky='we', padx=10, pady=(20,20))

        self.label_content_frame = customtkinter.CTkLabel(self.content_frame, text="Statistics", fg_color="transparent", justify='center', font=my_font)
        self.label_content_frame.grid(row=3, column=0, sticky='ew',  pady=10, columnspan=3)

        self.time_read_label = customtkinter.CTkLabel(self.content_frame, text='Время чтения файла: ')
        self.time_read_label.grid(row=4,column=0,sticky='w', padx=10, pady=10)

        self.time_read = customtkinter.CTkLabel(self.content_frame, text='', fg_color='#C7C7C7', padx=5, pady=5, corner_radius=5)
        self.time_read.grid(row=4, column=1, sticky='we', columnspan=2, padx=(0,10))

        self.general_time_label = customtkinter.CTkLabel(self.content_frame, text='Общее время работы алгоритма: ')
        self.general_time_label.grid(row=5,column=0,sticky='w', padx=10)

        self.general_time = customtkinter.CTkLabel(self.content_frame, text='', fg_color='#C7C7C7', padx=5, pady=5, corner_radius=5)
        self.general_time.grid(row=5, column=1, sticky='we', columnspan=2, padx=(0,10))


        self.result_frame.columnconfigure(1, weight=1)
        self.label_result_frame = customtkinter.CTkLabel(self.result_frame, text="Result: ", fg_color="transparent", justify='center', font=my_font)
        self.label_result_frame.grid(row=0, column=0, sticky='ew',  pady=10, padx=10)

        self.text_result = customtkinter.CTkLabel(self.result_frame, text='', fg_color='#C7C7C7', padx=5, pady=5, corner_radius=5)
        self.text_result.grid(row=0, column=1, sticky='we', columnspan=2, padx=(0,10))

        self.tree_frame.grid(row=0, column=0, padx=10, pady=(10, 0), ipadx=20, sticky="nsew", rowspan=2)
        self.content_frame.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew", columnspan=2)
        self.result_frame.grid(row=1, column=1, padx=10, pady=(10, 0), sticky="nsew", columnspan=2)

        self.button = customtkinter.CTkButton(self, text="Проверить файл", command=self.check_hash)
        self.button.grid(row=2, column=0, padx=10, pady=(10,5), sticky="ew",  columnspan=3)

        self.button = customtkinter.CTkButton(self, text="Визуализировать хэш-дерево", command=self.button_vizul)
        self.button.grid(row=3, column=0, padx=10, pady=(5,10), sticky="ew",  columnspan=3)


    def button_vizul(self):
        if not self.FLAG_VIZ:
            self.text_result.configure(text='Не построено дерево Меркла!', text_color='red')
            return
        if os.path.getsize(self.filepath.get()) > LIMIT_SIZE:
            self.text_result.configure(text='Слишком Большой файл! До 2 MB', text_color='red')
            return
        vizual_tree(self.merkle_tree.get_root())

    def choose_file(self):
        file = filedialog.askopenfilename()
        self.filepath.set(file)
        if file:
            self.filepath_label.configure(text=file)

    def validate_hash_input(self):
        hash_str = self.entry_hash.get()
        if not hash_str:
            return "empty"
        if (len(hash_str) != 64 and self.radio_var.get() == 1) or (len(hash_str) != 32 and self.radio_var.get() == 2):
            return "length"
        if not all(c in "0123456789abcdef" for c in hash_str.lower()):
            return "format"
        return "valid"

    def check_hash(self):
        print('radio_var: ', self.radio_var.get())
        valid_hash = self.validate_hash_input()
        if not self.filepath.get():
            self.text_result.configure(text='Файл не выбран!', text_color='red')
        if valid_hash != "valid":
            print(valid_hash)
            if valid_hash == "empty":
                self.text_result.configure(text='Введите хэш-значение!', text_color='red')
            elif valid_hash == 'length':
                self.text_result.configure(text='Хэш-значение неверной длины!', text_color='red')
            elif valid_hash == 'format':
                self.text_result.configure(text='Хэш-значение неверного формата!', text_color='red')
        else:
            print('file size: ', os.path.getsize(self.filepath.get()))
            start = time.time()
            self.merkle_tree = MerkleTree(self.filepath.get(),hash_func = 'SHA-256' if self.radio_var.get() == 1 else 'MD-5' )
            time_alg = time.time() - start
            calculated_hash = self.merkle_tree.root_hash.hex()

            self.time_read.configure(text=self.merkle_tree.get_time_read_file())
            self.general_time.configure(text=time_alg)

            print(calculated_hash)
            
            self.FLAG_VIZ = True    

            if calculated_hash == self.entry_hash.get():
                self.text_result.configure(text='Файл не был изменен!', text_color='green')
            else:
                self.text_result.configure(text='Возможно, файл был изменен! Хэши не совпадают', text_color='yellow')





app = App()
app.mainloop()