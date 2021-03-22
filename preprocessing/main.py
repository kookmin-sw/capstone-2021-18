from preprocess import preprocess, parse_ip_port
from separate import separate
import os
import pickle
from tqdm import tqdm
from is_encrypt import Is_encrypt
import sys

def ip_16_32_count(file_name):
    stat_dict = {'ip':{}, 'network':{}}
    for fname in tqdm(file_name, total=len(file_name)):
            with open(rf"{data_path}\{fname}", "rb") as file:
                pk = pickle.load(file)
                preprocess(pk, stat_dict)
    return stat_dict

def object_separate(stat_dict, file_name):
    count_result = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    for fname in tqdm(file_name, total=len(file_name)):
        with open(rf"{data_path}\{fname}", "rb") as file:
            pk = pickle.load(file)
            
            # Separation from separate.py
            parsed = parse_ip_port(pk)
            if parsed:
                obj = separate(parsed, stat_dict)
                
                # Can separate
                if obj <= 3:
                    if encrypt.is_encrypt(pk[-1]):
                        place = "encrypt"
                        count_result[7] += 1
                    else:
                        place = "plain"
                        count_result[8] += 1
                    with open(rf"{save_path}\{place}\{fname}", "wb") as p_file: ######
                        pickle.dump(pk + [obj], p_file)
                count_result[obj] += 1
            # ICMP
            else:
                count_result[-1] += 1
    return count_result

if __name__ == "__main__":
    data_path = sys.argv[1] # dataset directory path
    save_path = sys.argv[2] # result dataset will be saved directory path
    file_name = os.listdir(data_path) # IPS event filenames from 'data_path'

    # Create Is_encrypt Class object -> Generate data required for encryption determination
    encrypt = Is_encrypt(save_path)

    # Generate data required for separate inner-outer, server-client
    stat_dict = ip_16_32_count(file_name)

    # Separate inner-outer, server-client and encryption determination
    count_result = object_separate(stat_dict, file_name)

    # Print Separated event counts
    count_all_event = len(file_name)
    count_normal_event = sum(count_result[:4])
    print(f" Count inner_server events:          %-8d/{count_all_event}\n" % count_result[0],
          f"Count inner_client events:          %-8d/{count_all_event}\n" % count_result[1],
          f"Count outer_server events:          %-8d/{count_all_event}\n" % count_result[2],
          f"Count outer_client events:          %-8d/{count_all_event}\n" % count_result[3],
          f"Can't separate inner-outer:         %-8d/{count_all_event}\n" % count_result[4],
          f"Can't separate server-client:       %-8d/{count_all_event}\n" % count_result[5],
          f"ICMP:                               %-8d/{count_all_event}\n" % count_result[6],
           "------------------------------------------------------\n",
          f"Plain events:                       %-8d/{count_normal_event}\n" % count_result[7],
          f"Encrypted events:                   %-8d/{count_normal_event}" % count_result[8])
