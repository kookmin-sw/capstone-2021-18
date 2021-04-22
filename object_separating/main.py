import os
import sys
import pickle

from tqdm import tqdm #pip install tqdm

from preprocessor import preprocess, parse_ip_port
from separator import separate, set_threshold
from is_encrypt import IsEncrypt

def ip_16_32_count(file_name):
    # adding ip count, network(IP/16bit) count to 'stat_dict' by preprocess.py
    stat_dict = {'ip':{}, 'network':{}}
    for fname in tqdm(file_name, total=len(file_name)):
            with open(rf"{data_path}{os.sep}{fname}", "rb") as file:
                pk = pickle.load(file)
                preprocess(pk, stat_dict)
    return stat_dict

def object_separate(stat_dict, file_name):
    # encryption determinating and separating objects by is_encrypt.py, separator.py
    count_result = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    set_threshold(stat_dict)
    for fname in tqdm(file_name, total=len(file_name)):
        with open(rf"{data_path}{os.sep}{fname}", "rb") as file:
            pk = pickle.load(file)

        # Separation from separate.py
        parsed = parse_ip_port(pk)
        if parsed != -1:
            obj = separate(parsed, stat_dict)
            
            # Can separate
            if obj <= 3:
                if encrypt.encryption_determinate(pk[-1]):
                    place = "encrypt"
                    count_result[7] += 1
                else:
                    place = "plain"
                    count_result[8] += 1
                with open(rf"{save_path}{os.sep}{place}{os.sep}{fname}", "wb") as p_file:
                    pickle.dump(pk + [obj], p_file)
            count_result[obj] += 1
        # ICMP
        else:
            count_result[6] += 1
    return count_result

if __name__ == "__main__":
    data_path = sys.argv[1] # dataset directory path
    save_path = sys.argv[2] # result dataset will be saved directory path
    file_name = os.listdir(data_path) # IPS event filenames from 'data_path'

    # Create Is_encrypt Class object -> Generate data required for encryption determination
    encrypt = IsEncrypt(save_path)

    # Generate data required for separate inner-outer, server-client
    stat_dict = ip_16_32_count(file_name)

    # Separate inner-outer, server-client and encryption determination
    count_result = object_separate(stat_dict, file_name)

    # Print Separated event counts
    count_all_event = len(file_name)
    count_normal_event = sum(count_result[:4])
    print(f" Count inner_server events:         {count_result[0]:<8}/{count_all_event}\n",
          f"Count inner_client events:          {count_result[1]:<8}/{count_all_event}\n",
          f"Count outer_server events:          {count_result[2]:<8}/{count_all_event}\n",
          f"Count outer_client events:          {count_result[3]:<8}/{count_all_event}\n",
          f"Can't separate inner-outer:         {count_result[4]:<8}/{count_all_event}\n",
          f"Can't separate server-client:       {count_result[5]:<8}/{count_all_event}\n",
          f"ICMP:                               {count_result[6]:<8}/{count_all_event}\n",
           "------------------------------------------------------\n",
          f"Encrypted events:                   {count_result[7]:<8}/{count_normal_event}\n",
          f"Plain events:                       {count_result[8]:<8}/{count_normal_event}")
