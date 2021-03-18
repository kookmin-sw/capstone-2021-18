from enc import Check_enc
import os
import pickle
import pandas as pd
from tqdm import tqdm


if __name__ == '__main__':
    a = Check_enc()
    read_data_path = r"D:\KISTI\new2018\5"
    data_list = os.listdir(read_data_path)
    dir_save_path = {"plain": r"D:\KISTI\new2018\test\plain",
                     "encrypt": r"D:\KISTI\new2018\test\encrypt"}

    for key in dir_save_path.keys():
        if not os.path.exists(dir_save_path[key]):
            os.makedirs(dir_save_path[key])

    for fname in tqdm(data_list[:5]):
        with open(fr"{read_data_path}\{fname}", "rb") as f:
            pk = pickle.load(f)

        ## 이벤트 통계를 통해 객체 분리해서 pk에 객체 key:value 추가하는 코드 ##

        if a.separation(pk["Payload"]):
            pd.to_pickle(pk, os.path.join(dir_save_path["encrypt"], fname))
        else:
            pd.to_pickle(pk, os.path.join(dir_save_path["plain"], fname))
