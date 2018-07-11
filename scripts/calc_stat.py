import sys
import os, os.path as op
import statistics
from collections import OrderedDict
import time

CSV = True

tag_dic = {
        'CLIENT_TCP_CONNECT_START': 8,
        'CLIENT_TCP_CONNECT_END': 9,
        'CLIENT_HANDSHAKE_START': 0, 
        'CLIENT_EXTENDED_FINISHED_START': 6,
        'CLIENT_EXTENDED_FINISHED_END': 7,
        'CLIENT_HANDSHAKE_END': 1,
        'CLIENT_CERT_VALIDATION_START': 2, 
        'CLIENT_CERT_VALIDATION_END': 3,
        'CLIENT_MODIFICATION_RECORD_START': 10,
        'CLIENT_MODIFICATION_RECORD_END': 11,
        'CLIENT_FETCH_HTML_END': 5
}


def get_stats(lst):
    lst = list(sorted(lst))

    front_cut = int(len(lst) * .1)
    last_cut = int(len(lst) * .9)

    lst = lst[front_cut:last_cut]

    return statistics.mean(lst), statistics.pstdev(lst), max(lst), min(lst)


def parse_log(file_path):
    fp = open(file_path, 'r')

    lines = fp.read().splitlines()

    log_unit_lst = []
    log_unit = {} 
    for line in lines:
        us_tstamp, tag_num, tag_type = line.split(', ')
        us_tstamp = int(us_tstamp)
        tag_num = int(tag_num)
    
        if tag_num in log_unit:
            print('Error')

        log_unit[tag_num] = us_tstamp

        if tag_num == 6:
            log_unit_lst.append(log_unit)
            log_unit = {}

    tcp_time_lst = []
    hs_time_lst = []
    cert_valid_time_lst = []
    fin_valid_time_lst = []
    total_time_lst = []
    mod_record_time_lst = []

    for log_unit in log_unit_lst:
        tcp_time = log_unit[tag_dic['CLIENT_TCP_CONNECT_END']] - log_unit[tag_dic['CLIENT_TCP_CONNECT_START']]
        tcp_time_lst.append(tcp_time)

        hs_time = log_unit[tag_dic['CLIENT_HANDSHAKE_END']] - log_unit[tag_dic['CLIENT_HANDSHAKE_START']]
        hs_time_lst.append(hs_time)

        cert_valid_time = log_unit[tag_dic['CLIENT_CERT_VALIDATION_END']] - log_unit[tag_dic['CLIENT_CERT_VALIDATION_START']]
        cert_valid_time_lst.append(cert_valid_time)

        fin_valid_time = log_unit[tag_dic['CLIENT_EXTENDED_FINISHED_END']] - log_unit[tag_dic['CLIENT_EXTENDED_FINISHED_START']]
        fin_valid_time_lst.append(fin_valid_time)

        mod_record_time = log_unit[tag_dic['CLIENT_FETCH_HTML_END']] - log_unit[tag_dic['CLIENT_TCP_CONNECT_START']]
        mod_record_time_lst.append(mod_record_time)

        total_time = log_unit[tag_dic['CLIENT_FETCH_HTML_END']] - log_unit[tag_dic['CLIENT_TCP_CONNECT_START']]
        total_time_lst.append(total_time)

    stats = OrderedDict()
    stats['TCP_CONNECT_TIME'] = get_stats(tcp_time_lst)
    stats['HANDSHAKE_TIME'] = get_stats(hs_time_lst) 
    stats['FINISHED_VALIDATION_TIME'] = get_stats(fin_valid_time_lst)
    stats['CERT_VALIDATION_TIME'] = get_stats(cert_valid_time_lst)
    stats['MODIFICATION_RECORD_TIME'] = get_stats(mod_record_time_lst)
    stats['TOTAL_TIME'] = get_stats(total_time_lst)

    return stats

            
if __name__ == '__main__':
    d = 'csv_data'
    for i in range(0, 17):
        result_fp = open('mb_%d_read_result.csv' % i, 'w')
        file_path = op.join(d, 'mb_%d_read' % i, 'mb_%d_read.csv' % i)
        stats = parse_log(file_path)
        
        result_fp.write('Tag,Mean,Stdev,Max,Min\n')
        for stat in stats:
            result_fp.write('{tag},{mean},{stdev},{max},{min}\n'.format(
                                                        tag=stat,
                                                        mean=stats[stat][0],
                                                        stdev=stats[stat][1],
                                                        max=stats[stat][2],
                                                        min=stats[stat][3]
                                                      ))

    for i in range(0, 17):
        result_fp = open('mb_%d_write_result.csv' % i, 'w')
        file_path = op.join(d, 'mb_%d_write' % i, 'mb_%d_write.csv' % i)
        stats = parse_log(file_path)
        
        result_fp.write('Tag,Mean,Stdev,Max,Min\n')
        for stat in stats:
            result_fp.write('{tag},{mean},{stdev},{max},{min}\n'.format(
                                                        tag=stat,
                                                        mean=stats[stat][0],
                                                        stdev=stats[stat][1],
                                                        max=stats[stat][2],
                                                        min=stats[stat][3]
                                                      ))
