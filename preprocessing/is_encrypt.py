from tqdm import tqdm
from collections import Counter

import numpy as np
import pandas as pd
import math
import secrets
import os

import payload_parser
# for making std
LOOP = 10000
# six sigma
threshold = 6

#declare class for seperate encrypted packet
class IsEncrypt():
    # when class declared, if std_dict is not exist, make std_dict
    def __init__(self, path):
        if f"std_dict{os.extsep}pickle" not in os.listdir(os.curdir):
            self.std(LOOP)
        self.stat = pd.read_pickle("std_dict.pickle")

        dir_save_path = {"plain": rf"{path}{os.sep}plain",
                         "encrypt": rf"{path}{os.sep}encrypt"}

        # make directory for saving pickle
        for key in dir_save_path.keys():
            if not os.path.exists(dir_save_path[key]):
                os.makedirs(dir_save_path[key])
    
    # Returns the entropy value according to the input(payload)
    def get_entropy(self, data):
        if not data:
            return 0.0
        occurrences = Counter(bytearray(data))
        entropy = 0
        for x in occurrences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    # Returns application payload about each protocols
    def get_app(self, payload):
        if payload[46:48] == "06":
            return payload[107:]
        elif payload[46:48] == "11":
            return payload[83:]
        elif payload[46:48] == "01":
            return payload

    # if std_dict is not exist, make std_dict
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

    # Returns wheter to be encrypted according to the input(payload)
    def encryption_determinate(self, ful_payload):
        # blacklist
        bl = ("170303", "170302", "170301", "150301", "150302", "150303")
        # whitelist
        wl = ("140301", "140302", "140303", "160301", "160302", "160303")

        payload = self.get_app(ful_payload)
        length = int(len(payload)/2)
        # less than 3 is treated as plain text.
        if length <= 3:
            return False
        elif payload[:6] in bl:
            return True
        elif payload[:6] in wl:
            return False
        # six sigma threshold
        elif (self.stat['MEAN'][length] -
              (threshold * self.stat['STD'][length]) < self.get_entropy(payload_parser.to_byte(payload))):
            return True
        else:
            return False
