import os
import csv
import pickle

import pandas as pd

from tqdm import tqdm
from payload_parser import to_byte, get_app


def HttpParser(payload):
    content = {'20', '2F', '3A', '27', '2C','29', '28', '7D', '7B', '2E','5D','5B', '3B', '3E','3C', '2A', '22', '23', '3D'}
    # delimiter by special character
    ls = []
    header_body = payload.split('0D0A0D0A')
    ing = header_body[0].split('0D0A')
    if len(header_body) > 1 and len(header_body[1]) > 0:
        ing.append(header_body[1])
    for chunk in ing:
        word = ""
        for idx in range(0, len(chunk), 2):
            if chunk[idx:idx+2] in content and len(word) > 0:
                ls.append(word)
                word =""
            elif chunk[idx:idx+2] in content and len(word) == 0:
                pass
            else:
                word += chunk[idx:idx+2]
        if len(word) > 0:
            ls.append(word)
    return ls


def jac_sim(a, b):
    return len(a & b) / (len(a) + len(b) - len(a & b))


def make_result_csv(data, cluster_jac, vec_dict, title_vec, SAVE_PATH, obj):
    pd.to_pickle(title_vec, rf"{SAVE_PATH}\{obj}_title_vector.pickle")
    csv_tmp = open(rf"{SAVE_PATH}\{obj}_cluster.csv", 'w',
                   newline='', encoding='cp949')
    wrt_tmp = csv.writer(csv_tmp)
    wrt_tmp.writerow(
        ['Cluster', 'DetectName', 'Result', '_id', 'Payload', 'label_Purity', 'DetectName_Purity', 'diffrent'])
    etc = []
    for cls in tqdm(cluster_jac):
        if len(cluster_jac[cls]) <= 1:
            etc.append(cluster_jac[cls][0])
            continue
        else:
            p = 0
            for e_id in cluster_jac[cls]:
                if p == 0:
                    wrt_tmp.writerow(
                        [cls, data[e_id]['DetectName'], data[e_id]['Result'], e_id, str(to_byte(data[e_id]['Payload'])),
                         [data[i]['Result'] for i in cluster_jac[cls]].count(data[cluster_jac[cls][0]]['Result']) / len(
                             cluster_jac[cls]),
                         [data[i]['DetectName'] for i in cluster_jac[cls]].count(
                             data[cluster_jac[cls][0]]['DetectName']) / len(cluster_jac[cls]),
                         [str(to_byte(word)) for word in (vec_dict[e_id] - title_vec[cls])]])
                    p = 1
                else:
                    wrt_tmp.writerow(
                        [cls, data[e_id]['DetectName'], data[e_id]['Result'], e_id, str(to_byte(data[e_id]['Payload'])),
                         '', '', [str(to_byte(word)) for word in (vec_dict[e_id] - title_vec[cls])]])
        wrt_tmp.writerow([''])

    for d in tqdm(etc):
        wrt_tmp.writerow(['etc', data[d]['DetectName'], data[d]['Result'], d, str(to_byte(data[d]['Payload']))])
    csv_tmp.close()


def get_cluster(data, SAVE_PATH, sim_rate, obj):
    vec_dict = {}
    for fn in tqdm(data):
        if len(data[fn]['Payload']) != 0:
            chunks = HttpParser(data[fn]['Payload'])
            vec_dict[fn] = set(chunks)

    passed = set()
    cluster_jac = {}
    chunks_dict = {}
    idx = 0
    for f in tqdm(vec_dict):
        if f not in passed:
            passed.add(f)
            cluster_jac[idx] = [f]
            chunks_dict[idx] = {}
            for chunk in vec_dict[f]:
                if chunk not in chunks_dict:
                    chunks_dict[idx][chunk] = 0
                chunks_dict[idx][chunk] += 1
            for op in vec_dict:
                if op not in passed:
                    if jac_sim(vec_dict[f], vec_dict[op]) >= sim_rate:
                        passed.add(op)
                        cluster_jac[idx].append(op)
                        for chunk in vec_dict[op]:
                            if chunk not in chunks_dict[idx]:
                                chunks_dict[idx][chunk] = 0
                            chunks_dict[idx][chunk] += 1
            idx += 1

    title_vec = {}
    for i in tqdm(cluster_jac):
        sorted_dict = sorted(chunks_dict[i].items(),
                             reverse=True,
                             key=lambda x: x[1])
        mean_length = 0
        for j in cluster_jac[i]:
            mean_length += len(set(vec_dict[j]))
        mean_length /= len(cluster_jac[i])

        title_vec[i] = {sorted_dict[t][0] for t in range(int(mean_length))}

    make_result_csv(data, cluster_jac, vec_dict, title_vec, SAVE_PATH, obj)


def make_cluster(DATA_PATH, SAVE_PATH, sim_rate):
    file_list = os.listdir(rf"{DATA_PATH}{os.sep}plain")
    objects = ["IN_S", "IN_C", "OUT_S", "OUT_C"]
    objs = {obj: {} for obj in objects}
    print("---------- read payload ---------")
    for fname in tqdm(file_list):
        with open(rf"{DATA_PATH}{os.sep}plain{os.sep}{fname}") as f:
            pk_tmp = pickle.load(f)
            if pk_tmp[-1] <= 3:
                objs[objects[pk_tmp[-1]]][pk_tmp[1]] = {"DetectName": pk_tmp[21], "Result": pk_tmp[-3], "Payload": get_app(pk_tmp[-2])}

    for obj in objs:
        get_cluster(objs[obj], SAVE_PATH, sim_rate, obj)


if __name__ == '__main__':

    sim_rate = 0.90
    DATA_PATH = r"D:\KISTI\capstone\example\data"
    SAVE_PATH = r"D:\KISTI\capstone\example\result"

    make_cluster(DATA_PATH, SAVE_PATH, sim_rate)