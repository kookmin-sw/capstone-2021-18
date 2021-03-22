from tqdm import tqdm
from collections import Counter
import math
import numpy as np
import secrets
import payload_parser
import os
import pandas as pd
LOOP = 10000
threshold = 6


class is_encrypt():
    def __init__(self, path):
        if "std_dict.pickle" not in os.listdir(r"."):
            self.std(LOOP)
        self.stat = pd.read_pickle("std_dict.pickle")

        dir_save_path = {"plain": rf"{path}\plain",
                         "encrypt": rf"{path}\encrypt"}

        for key in dir_save_path.keys():
            if not os.path.exists(dir_save_path[key]):
                os.makedirs(dir_save_path[key])

    def is_encrypt(self, ful_payload):
        exc = ("170303", "170302", "170301", "150301", "150302", "150303")
        wl = ("140301", "140302", "140303", "160301", "160302", "160303")

        payload = self.get_app(ful_payload)
        length = int(len(payload)/2)
        if length <= 3:
            return False
        elif payload[:6] in exc:
            return True
        elif payload[:6] in wl:
            return False
        elif (self.stat['MEAN'][length] -
              (threshold * self.stat['STD'][length]) < self.get_entropy(payload_parser.to_byte(payload))):
            return True
        else:
            return False

    def get_entropy(self, data):
        if not data:
            return 0.0
        occurrences = Counter(bytearray(data))
        entropy = 0
        for x in occurrences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def get_app(self, payload):
        if payload[46:48] == "06":
            return payload[107:]
        elif payload[46:48] == "11":
            return payload[83:]
        elif payload[46:48] == "01":
            return payload

    def std(self, LOOP):
        stat = {'MEAN': [], 'STD': []}
        for i in tqdm(range(1601)):
            entropy_list = []
            for n in range(LOOP):
                entropy_one = self.get_entropy(secrets.token_bytes(i))
                entropy_list.append(entropy_one)
            stat['MEAN'].append(sum(entropy_list) / LOOP)
            stat['STD'].append(np.std(entropy_list))
        pd.to_pickle(stat, "std_dict.pickle")
