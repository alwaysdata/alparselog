#!/usr/bin/env python34
# -*- coding: utf-8 -*-
#
# Log parser for checking if there's any differences
# between alproxy log file and Apache access' log file(s)
#


import argparse
import gzip
import re
import sys
import time
from os import listdir


LINE = 'line'
IPSRC = 'ip_src'
TIMEST = 'timestamp'
DATE_TIME = 'date_time'
EPOCH_TIME = 'epoch'
STATUSCODE = 'status_code'
PAYLOAD = 'payload'
REQUEST = 'request'


def argparser():
    """
    Handles input arguments parsing.

    Returns successfully parsed vars.
    """
    statuscode_choices = [100, 101,
                          200, 201, 202, 203, 204, 205,
                          300, 301, 302, 303, 305, 307,
                          400, 402, 403, 404, 405, 406,
                          408, 409, 410, 411, 413, 414,
                          415, 417, 426,
                          500, 502, 503, 504, 505]
    statustype_choices = [1, 2, 3, 4, 5]

    descrip = 'Parse and compare log files from Apache and alproxy'
    parser = argparse.ArgumentParser(description=descrip)

    # Positionnal args
    parser.add_argument('apache_logfile',
                        help='log file used as reference')
    parser.add_argument('alproxy_logfile',
                        help='log file used for comparison ')
    # Optional agrs
    group1 = parser.add_mutually_exclusive_group()
    group2 = parser.add_mutually_exclusive_group()
    group3 = parser.add_mutually_exclusive_group()
    group1.add_argument('-c', '--count',
                        help='''compare number log lines
                        between apache_logfile
                        and alproxy_logfile''',
                        action='store_true')
    group1.add_argument('-m', '--match',
                        help='''look for log line match
                        between apache_logfile
                        and alproxy_logfile''',
                        action='store_true')
    group2.add_argument('-s', '--statuscode',
                        help='look for a specific HTTP status code (e.g. 404)',
                        type=int,
                        choices=statuscode_choices)
    group2.add_argument('-S', '--statustype',
                        help='look for a range of HTTP status code (e.g. 4xx)',
                        type=int,
                        choices=statustype_choices)
    group3.add_argument('-R', '--recursive',
                        help='process all file ending with \'.log.gz\'',
                        action='store_true')
    group3.add_argument('-u', '--user',
                        help='filter comparison to a specific user')
    parser.add_argument('-v', '--verbose',
                        help='output log lines found',
                        action='store_true')

    args = parser.parse_args()

    if not (args.statuscode or args.statustype) and args.match:
        print('[ERROR] No HTTP status code/type typed.\nAborting...')
        exit(1)
    elif (args.statuscode or args.statustype) and not args.match:
        print('[ERROR] HTTP status code typed',
              'but match mode [-m, --match] not enabled.\nAborting...')
        exit(1)

    return args


def get_useracc(apache_userlog_name):
    """
    Fetch user account based on the name of apache log file.
    Filename must be formatted as follow:
    'access-<useraccount>.log.gz

    Returns user acccount
    """
    preffix = 'access-'
    suffix = '.log.gz'
    nopreffix = apache_userlog_name[len(preffix):]
    useracc = nopreffix[:-len(suffix)]
    return useracc


def date2epoch(date_time):
    """
    Converts a date with the format 'DD/MMM/YYYY:hh:mm:ss'
    into seconds since epoch.
    This format is used in Apache log files.

    Returns an int (seconds since epoch)
    """
    pattern = r'%d/%b/%Y:%H:%M:%S'
    epoch = int(time.mktime(time.strptime(date_time, pattern)))

    return epoch


def extract_infos(logline, status_code):
    """
    Looks for patterns matching regexp for a log line.

    If time_and_request_only is set to True, the function will looks for
    a match for the date and then returns a tuple : epoch_time , request.
    If statuscode_only is set to True, the function will return only
    info[STATUSCODE] even if it's empty string.

    Returns a dict of information about logline
    """
    info = {LINE: logline,
            IPSRC: None,
            TIMEST: {DATE_TIME: None,
                     EPOCH_TIME: None},
            STATUSCODE: '',
            PAYLOAD: None,
            REQUEST: None}

    # Getting ip source address
    ipaddr_patt = r'.[^-] (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - -'
    patt = re.compile(ipaddr_patt)
    matchip = patt.search(logline)
    if matchip:
        info[IPSRC] = matchip.group(1)
    re.purge()

    # Getting timestamp and HTTP request
    timest_patt = r'\[(\d{2}\/.{3}\/\d{4}:\d{2}:\d{2}:\d{2}) \+0200\] "(.*?)"'
    patt = re.compile(timest_patt)
    match1 = patt.search(logline)
    if match1:
        info[TIMEST][DATE_TIME] = match1.group(1)
        info[TIMEST][EPOCH_TIME] = date2epoch(match1.group(1))
        info[REQUEST] = match1.group(2)
    re.purge()

    # Getting status code and payload
    if len(str(status_code)) == 1:  # Status code is actually a status type
        statuscode_payload_patt = (r'HTTP\/1\.1" ('
                                   + str(status_code)
                                   + r'\d\d) (\d*) "')
    else:
        statuscode_payload_patt = (r'HTTP\/1\.1" ('
                                   + str(status_code)
                                   + ') (\d*) "')
    patt = re.compile(statuscode_payload_patt)
    match2 = patt.search(logline)
    if match2:
        info[STATUSCODE] = match2.group(1)
        info[PAYLOAD] = match2.group(2)
    re.purge()

    return info


def log_lookup(log_filename, useracc=None,
               status_code=None, status_type=None,
               filt=False):
    """
    Looks into a log file for HTTP error.

    Args:
    log_filename -> log file to look up
    useracc -> user of the service in log file
    status_code -> type of http error code (e.g 502)
    filt -> filter log file by user if set to True

    Returns a line of lines containing errors
    """
    error_lines = []

    if status_type:
        status_code = status_type

    if status_code:
        error_format = '" ' + str(status_code)
        print('[INFO] Parsing "', log_filename, '"... ', sep='', end='')

        if '.log.gz' in log_filename:
            reflog = gzip.open(log_filename, 'rt')
        else:
            reflog = open(log_filename, 'r')

        for line in reflog:
            if line.startswith(useracc):
                info = extract_infos(line, status_code)
                if info[STATUSCODE]:
                    error_lines.append(info)
            else:
                continue

        print('DONE')
        print('[INFO] Lines found :', len(error_lines))
        reflog.close()

    return error_lines


def log_compare(log_filename, error_lines,):
    """
    Compares timestamp from log file to a list of lines with HTTP error.
    """
    separator = '-*--*' * 50
    max_delta = 5  # seconds between timestamps in log files
    count = 0
    lines_found = error_lines[:]
    same_lines = []
    payload_delta = []
    statuscode_delta = []
    status_and_payload_delta = []
    nomatch_lines = []

    print('[INFO] Comparison with "', log_filename, '"... ', sep='', end='')

    if '.log.gz' in log_filename:
        complog = gzip.open(log_filename, 'rt')
    else:
        complog = open(log_filename, 'r')

    for logline in complog:
        info = extract_infos(logline, '')
        if not info[TIMEST][DATE_TIME]:
            continue

        for ind, error_line in enumerate(lines_found):
            if not lines_found:
                break
            delta = error_line[TIMEST][EPOCH_TIME] - info[TIMEST][EPOCH_TIME]
            cond_delta = delta >= -2 and delta <= max_delta
            cond_ip = error_line[IPSRC] == info[IPSRC]
            cond_request = error_line[REQUEST] in info[REQUEST]
            cond_statuscode = error_line[STATUSCODE] == info[STATUSCODE]
            cond_payload = error_line[PAYLOAD] == info[PAYLOAD]
            base_cond = cond_delta and cond_ip and cond_request

            if base_cond:
                if cond_statuscode and cond_payload:
                    same_lines.append((error_line, logline))
                    count += 1
                    lines_found.pop(ind)
                    break
                elif cond_statuscode and not cond_payload:
                    payload_delta.append((error_line, logline))
                    lines_found.pop(ind)
                    break
                elif not cond_statuscode and cond_payload:
                    statuscode_delta.append((error_line, logline))
                    lines_found.pop(ind)
                    break
                elif not cond_statuscode and not cond_payload:
                    status_and_payload_delta.append((error_line, logline))
                    lines_found.pop(ind)
                    break
    # Get remaining log lines
    nomatch_lines = lines_found[:]

    print('DONE')
    complog.close()

    return (same_lines,
            payload_delta,
            statuscode_delta,
            status_and_payload_delta,
            nomatch_lines)


def log_linecount(log_filename1, log_filename2, useracc=None):
    """
    Counts and compares the number of log lines written
    between log_filename1 and log_filename2.

    log_filename1 --> apache access log (in this version)
    log_filename2 --> alproxy log (in this version)
    useracc --> user account for filtering alproxy log
    """
    refcount = 0
    compcount = 0

    with open(log_filename1, 'r') as reflog:
        for line in reflog:
            refcount += 1

    with open(log_filename2, 'r') as complog:
        for line in complog:
            # Alproxy log file
            if line.startswith(useracc) and ' | ' in line:
                compcount += 1

    if compcount < refcount:
        print('[ERROR] Log lines in "', log_filename2,
              '" for user account "', useracc,
              '" is smaller than "', log_filename1, '"',
              sep='')
        print('[INFO] Second input file MUST be alproxy log file.')
    else:
        print('[INFO] Normal behavior for "', log_filename2, '"', sep='')
    print('[INFO] Number of lines [',
          refcount, '/', compcount,
          '] [', log_filename1, '/', log_filename2, ']',
          sep='')


def make_summary(same_lines,
                 payload_delta_lines,
                 statuscode_delta_lines,
                 status_and_payload_delta,
                 nomatch_lines,
                 verbose=False):
    """
    Prints out the comparison results in a formatted way.
    """
    sep1 = '#' * 80
    sep2 = '-*--*' * 16
    sep3 = '+' * 30
    sep4 = '_' * 60
    empty_msg = sep3 + '\n\tEMPTY\n' + sep3
    match_section = '\t\t\tMATCH section'
    nomatch_section = '\t\t\tNO MATCH section'
    same_lines_subsect = 'Log lines are the same |'
    payload_delta_subsect = 'Payloads are different |'
    statuscode_delta_subsect = 'Status codes are different |'
    status_and_payload_subsect = 'Status codes and payloads are different |'
    no_lines_subsect = 'Log with no match found |'
    alproxy_line_msg = '##### ALPROXY log #####'
    apache_line_msg = '##### APACHE log #####'

    def print_loglines(loglines_list):
        """
        loglines_list MUST be formatted as follow:
        [(alproxy_line1, apache_line1),
        (alproxy_line2, apache_line2),
        ...]
        """
        for alproxy_logline, apache_logline in loglines_list:
            print(sep2)
            print(alproxy_line_msg)
            print(alproxy_logline[LINE], end='')
            print(apache_line_msg)
            print(apache_logline, end='')

    def print_subsect(subsect_values,
                      subsect_msg,
                      verbose,
                      empty_msg='',):
        if subsect_values:
            print(subsect_msg,
                  ' Total = ', len(subsect_values),
                  '\n', sep4, '\n', sep4,
                  sep='')
            if verbose:
                print_loglines(subsect_values)
        else:
            return

    if not (same_lines
            and payload_delta_lines
            and statuscode_delta_lines
            and status_and_payload_delta
            and nomatch_lines):
        print('[INFO] No results to print\n', sep1)
        return

    print('[INFO] Generating results...')
    # Match section
    print(sep1, match_section, sep1, sep='\n')

    print_subsect(same_lines,
                  same_lines_subsect,
                  verbose,
                  empty_msg=empty_msg)
    print_subsect(payload_delta_lines,
                  payload_delta_subsect,
                  verbose,
                  empty_msg=empty_msg)
    print_subsect(statuscode_delta_lines,
                  statuscode_delta_subsect,
                  verbose,
                  empty_msg=empty_msg)
    print_subsect(status_and_payload_delta,
                  status_and_payload_subsect,
                  verbose,
                  empty_msg=empty_msg)

    # No match section
    print(sep1, nomatch_section, sep1, sep='\n')
    print(no_lines_subsect,
          ' Total = ', len(nomatch_lines),
          '\n', sep4, '\n', sep4,
          sep='')
    if nomatch_lines:
        if verbose:
            for line in nomatch_lines:
                print(line[LINE], end='\n')
    else:
        print(empty_msg)


def process_files(alproxy_logfile,
                  apache_logfile,
                  useracc,
                  status_code,
                  status_type,
                  verbose,):

    errors = log_lookup(alproxy_logfile,
                        useracc=useracc,
                        status_code=status_code,
                        status_type=status_type)
    (same_lines,
     payload_delta,
     statuscode_delta,
     status_and_payload_delta,
     nomatch_lines) = log_compare(apache_logfile, errors)

    make_summary(same_lines,
                 payload_delta,
                 statuscode_delta,
                 status_and_payload_delta,
                 nomatch_lines,
                 verbose=verbose)


if __name__ == '__main__':
    args = argparser()

    if args.match:
        if args.recursive:
            ind = args.apache_logfile.rfind('/')
            path = args.apache_logfile[:ind]
            loglist = listdir(path=path)
            loglist = [(path + '/' + i, get_useracc(i)) for i in loglist
                       if (i.endswith('.log.gz') and 'alproxy' not in i)]
            for logfile in loglist:
                if args.user:
                    useracc = args.user
                else:
                    useracc = logfile[1]

                process_files(args.alproxy_logfile,
                              logfile[0],
                              useracc,
                              args.statuscode,
                              args.statustype,
                              args.verbose)
        else:
            process_files(args.alproxy_logfile,
                          args.apache_logfile,
                          args.user,
                          args.statuscode,
                          args.statustype,
                          args.verbose)

    elif args.count:
        log_linecount(args.apache_logfile,
                      args.alproxy_logfile,
                      useracc=args.user)
