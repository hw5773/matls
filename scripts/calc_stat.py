import sys
import os
import statistics
from collections import OrderedDict
import time

CSV = True

def get_stats(data, stripping=False):
    if stripping:
        _data = data[10:-10]
    else:
        _data = data[:]
    return (
        statistics.mean(_data),
        statistics.pstdev(_data),
        max(_data),
        min(_data),
    )

def align_log_by_tag(log, tags):
    
    aligned_log = {}
    fail = 0
    num_tags = len(tags)
    num_log = len(log)

    if num_log != num_tags:
        return None, num_log
    
    log_names = list(map(lambda x: x['name'], log))
    for tag in tags:
        if tag not in log_names:
            fail += 1

    if fail:
        return None, num_log - fail

    for i, tag in enumerate(tags):
        aligned_log[tag] = log[i]['time']

    return aligned_log, num_tags


def calc_client(log, stripping):
    tags = [
        'CLIENT_TCP_CONNECT_START',
        'CLIENT_TCP_CONNECT_END',
        'CLIENT_HANDSHAKE_START',
        'CLIENT_HANDSHAKE_END',
        'CLIENT_EXTENDED_FINISHED_START',
        'CLIENT_EXTENDED_FINISHED_END',
        'CLIENT_CERT_VALIDATION_START',
        'CLIENT_CERT_VALIDATION_END',
        'CLIENT_MODIFICATION_RECORD_START',
        'CLIENT_MODIFICATION_RECORD_END',
        'CLIENT_FETCH_HTML_END',
    ]

    len_tags = len(tags)
    len_log = len(log)

    tcp_times = []
    hs_times = []
    cert_validation_times = []
    finished_validation_times = []
    total_times = []
    modification_record_times = []

    i = 0
    while i < len_log:
        _log, num_valid = align_log_by_tag(log[i:i+len_tags], tags)
        i += num_valid

        if not _log:
            continue

        tcp_times.append(_log['CLIENT_TCP_CONNECT_END'] - _log['CLIENT_TCP_CONNECT_START'])
        hs_times.append(_log['CLIENT_HANDSHAKE_END'] - _log['CLIENT_HANDSHAKE_START'])
        cert_validation_times.append(_log['CLIENT_CERT_VALIDATION_END'] - _log['CLIENT_CERT_VALIDATION_START']) 
        finished_validation_times.append(_log['CLIENT_EXTENDED_FINISHED_END'] - _log['CLIENT_EXTENDED_FINISHED_START'])
        total_times.append(_log['CLIENT_FETCH_HTML_END'] - _log['CLIENT_TCP_CONNECT_START'])
        modification_record_times.append(_log['CLIENT_MODIFICATION_RECORD_END'] - _log['CLIENT_MODIFICATION_RECORD_START'])

    stats = OrderedDict()
    stats['TCP_CONNECT_TIME'] = get_stats(tcp_times, stripping)
    stats['HANDSHAKE_TIME'] = get_stats(hs_times, stripping) 
    stats['FINISHED_VALIDATION_TIME'] = get_stats(finished_validation_times, stripping)
    stats['CERT_VALIDATION_TIME'] = get_stats(cert_validation_times, stripping)
    stats['MODIFICATION_RECORD_TIME'] = get_stats(modification_record_times, stripping)
    stats['TOTAL_TIME'] = get_stats(total_times, stripping)

    return stats


def calc_server(log, stripping):
    tags = [
        'SERVER_ACCEPT_START',
        'SERVER_ACCEPT_END',
    ]

    len_tags = len(tags)
    len_log = len(log)


    _log = {}
    for l in log:
        if not _log.get(l['name']):
            _log[l['name']] = [l['time']]
        else:
            _log[l['name']].append(l['time'])

    hs_times = list(map(lambda time: time[1]-time[0], zip(_log['SERVER_ACCEPT_START'], _log['SERVER_ACCEPT_END'])))

    stats = OrderedDict()
    stats['HANDSHAKE_TIME'] = get_stats(hs_times)

    return stats


def main():

    if len(sys.argv) < 3:
        print('[*] usage python {} <client/server> <log file/log files directory> [--strip]'.format(sys.argv[0]))
        exit()

    log_file_name = sys.argv[2]
    log_type = sys.argv[1].upper()
    stripping = '--strip' in sys.argv

    if os.path.isdir(log_file_name):
        log_lines = []
        for f in os.listdir(log_file_name):
            log_lines.extend(open(os.path.join(log_file_name, f), 'r').readlines())
    else:
        log_lines = open(log_file_name, 'r').readlines()

    raw_log = []
    log = []
    for line in log_lines:
        
        # ignore duplicate
        if line in raw_log:
            continue

        values = [v.strip() for v in line.strip().split(',')]
        raw_log.append(line)
        log.append({
            'time': int(values[0]),
            'number': int(values[1]),
            'name': values[2],
        })

    if log_type == 'CLIENT':
        stats = calc_client(log, stripping)
    elif log_type == 'SERVER':
        stats = calc_server(log, stripping)

    if CSV:
        print('Tag,Mean,Stdev,Max,Min')
        for stat in stats:
            print('{tag},{mean},{stdev},{max},{min}'.format(
                                                        tag=stat,
                                                        mean=stats[stat][0],
                                                        stdev=stats[stat][1],
                                                        max=stats[stat][2],
                                                        min=stats[stat][3]
                                                      ))
    else:
        for stat in stats:
            print(stat)
            print('----------')
            print('Mean:', stats[stat][0])
            print('Stdev:', stats[stat][1])
            print('Max:', stats[stat][2])
            print('Min:', stats[stat][3])
            print('----------')
            
if __name__ == '__main__':
    main()
