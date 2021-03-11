from tqdm import tqdm
from collections import Counter
import math
import numpy as np
import csv
import secrets

high = [0] * 1600
low = [10] * 1600
mean = []
MAX_LEN = 1600
LOOP = 3000
diff = []


def get_entropy(data):
    if not data:
        return 0.0
    occurrences = Counter(bytearray(data))
    entropy = 0
    for x in occurrences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def to_byte(payload):
    out = []
    for ii in range(0, len(payload), 2):
        out.append(int(payload[ii: ii + 2], 16))
    return bytes(out)


def make_std():
    for i in tqdm(range(MAX_LEN)):
        tmp = []
        for n in range(LOOP):
            entropy = get_entropy(secrets.token_bytes(i))
            if entropy > high[i]:
                high[i] = entropy
            if entropy < low[i]:
                low[i] = entropy
            tmp.append(entropy)
        mean.append(np.mean(tmp))
    diff = [high[i] - mean[i] for i in range(MAX_LEN)]
    return diff


def read_payload(path):
    f = open(path, 'r', encoding='cp949')
    id_payload = {}
    for line in tqdm(f.readlines()[1:]):
        table = line.strip().split(",")
        id_payload[table[1]] = table[-1]
    return id_payload


def separation(payload):  # 지금 풀패킷으로 되어 있는데 함수는 TCP 패킷으로 되어 있음 이부분 수정
    exc = ["170303", "170302", "170301", "150301", "150302", "150303"]
    plain = []
    for eid, data in tqdm(payload.items()):
        len_data = int(len(data)/2)
        if (mean[len_data] - (diff[len_data]) < get_entropy(to_byte(data)) and len_data > 3) or data[:6] in exc:
            continue
        plain.append(eid)
    return plain


def write_plain(payload, plain, save_path):
    f = open(save_path, 'w', encoding='cp949', newline="")
    wr = csv.writer(f)
    wr.writerow(["_id", "payload"])
    for i in plain:
        wr.writerow([i, payload[i]])
    f.close()


if __name__ == "__main__":
    load_path = r"D:\KISTI\데이터\all_parameter_5to10.csv"
    save_path = r"D:\KISTI\데이터\plainList.csv"
    payload = read_payload(load_path)
    plain = separation(payload)
    write_plain(payload, plain, save_path)
