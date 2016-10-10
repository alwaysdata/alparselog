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
import os


MAX_TIMESTAMP_DELTA = 5  # seconds between timestamps in log files

USERACCOUNT_REGEX = re.compile(r'^(.*) - \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - ')
IPV4_REGEX = re.compile(r'.[^-] (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - -')
DATE_REGEX = re.compile(r'\[(\d{2}\/.{3}\/\d{4}:\d{2}:\d{2}:\d{2}) \+0200\]')
HTTP_REQUEST_REGEX = re.compile(r':\d{2} \+0200\] "(.*?)"')
PAYLOAD_REGEX = re.compile(r'HTTP\/1\.[0-1]" \d{3} ([\-\d]+) "')

separator1 = '#' * 80
separator2 = '-*--*' * 16
separator3 = '+' * 30
separator4 = '_' * 60
alproxy_line_message = '##### ALPROXY log #####'
apache_line_message = '##### APACHE log #####'

data_bucket = {}


def argparser():
    """
    Handles input arguments parsing.

    Returns successfully parsed vars.
    """
    statuscode_choices = ['100', '101',
                          '200', '201', '202', '203', '204', '205',
                          '300', '301', '302', '303', '305', '307',
                          '400', '402', '403', '404', '405', '406',
                          '408', '409', '410', '411', '413', '414',
                          '415', '417', '426',
                          '500', '502', '503', '504', '505']
    statustype_choices = ['1', '2', '3', '4', '5']

    description = 'Parse and compare log files from Apache and alproxy'
    parser = argparse.ArgumentParser(description=description)

    # Positionnal args
    parser.add_argument('apache_logfile',
                        help='log file used as reference')
    parser.add_argument('alproxy_logfile',
                        help='log file used for comparison ')
    # Optional agrs
    group_mode = parser.add_mutually_exclusive_group()
    group_status = parser.add_mutually_exclusive_group()
    group_scope = parser.add_mutually_exclusive_group()
    group_mode.add_argument('-c', '--count',
                            help='''compare number log lines
                            between apache_logfile
                            and alproxy_logfile''',
                            action='store_true')
    group_mode.add_argument('-m', '--match',
                            help='''look for log line match
                            between apache_logfile
                            and alproxy_logfile''',
                            action='store_true')
    group_status.add_argument('-s', '--statuscode',
                              help='''look for a specific
                              HTTP status code (e.g. 404)''',
                              type=str,
                              choices=statuscode_choices)
    group_status.add_argument('-S', '--statustype',
                              help='''look for a range of
                              HTTP status code (e.g. 4xx)''',
                              type=str,
                              choices=statustype_choices)
    group_scope.add_argument('-R', '--recursive',
                             help='process all file ending with \'.log.gz\'',
                             action='store_true')
    group_scope.add_argument('-u', '--user',
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


def get_user_account(apache_userlog_name):
    """
    Fetch user account based on the name of apache log file.
    Filename must be formatted as follow:
    'access-<useraccount>.log.gz

    Returns user acccount
    """
    preffix = 'access-'
    suffix = '.log.gz'
    nopreffix = apache_userlog_name[len(preffix):]
    user_account = nopreffix[:-len(suffix)]
    return user_account


def date_to_epoch(date_time):
    """
    Converts a date with the format 'DD/MMM/YYYY:hh:mm:ss'
    into seconds since epoch.
    This format is used in Apache log files.

    Returns an int (seconds since epoch)
    """
    pattern = r'%d/%b/%Y:%H:%M:%S'
    epoch = int(time.mktime(time.strptime(date_time, pattern)))

    return epoch


class LogRecord():
    def __init__(self, logline, statuscode):
        self.line = logline
        self.ip_source = None
        self.date = None
        self.timestamp = None
        self.statuscode = None
        self.payload = None
        self.request = None
        self.match_found = False
        self.extract_infos(self.line, statuscode)

    def extract_infos(self, logline, status_code):
        """
        Looks for patterns matching regexp for a log line.
        """
        # Getting ip source address
        ip_found = IPV4_REGEX.search(logline)
        if ip_found:
            self.ip_source = ip_found.group(1)

        # Getting date and timestamp
        date_found = DATE_REGEX.search(logline)
        if date_found:
            self.date = date_found.group(1)
            self.timestamp = date_to_epoch(date_found.group(1))

        # Getting HTTP request
        request_found = HTTP_REQUEST_REGEX.search(logline)
        if request_found:
            self.request = request_found.group(1)

        # Getting status code
        if len(status_code) == 1:  # Status code is actually a status type
            statuscode_pattern = (r'HTTP\/1\.[0-1]" ('
                                  + status_code
                                  + r'\d\d) ')
        else:
            statuscode_pattern = (r'HTTP\/1\.[0-1]" ('
                                  + status_code
                                  + ') ')
        statuscode_regex = re.compile(statuscode_pattern)
        statuscode_found = statuscode_regex.search(logline)
        if statuscode_found:
            self.statuscode = statuscode_found.group(1)

        # Getting payload
        payload_found = PAYLOAD_REGEX.search(logline)
        if payload_found:
            self.payload = payload_found.group(1)

    def set_matched(self,):
        self.match_found = True

    def has_logs_dates_match(self, other_record):
        delta = self.timestamp - other_record.timestamp
        result = delta >= -2 and delta <= MAX_TIMESTAMP_DELTA
        return result

    def has_ips_match(self, other_record):
        return self.ip_source == other_record.ip_source

    def has_requests_match(self, other_record):
        """
        Check if self.request is contained in other_record.request
        Caveat : it dosen't handle the case where the test is true but
        other_record.request is longer than self.request.
        """
        return self.request in other_record.request

    def has_statuscodes_match(self, other_record):
        return self.statuscode == other_record.statuscode

    def has_payloads_match(self, other_record):
        """
        Handle case where other_record has '-' instead of '0'
        as payload (e.g. 503 error in Apache log).
        """
        result = (self.payload == other_record.payload
                  or (self.payload == ('0' or '-')
                      and other_record.payload == ('-' or '0')))
        return result

    def has_partial_logs_match(self, other_record):
        result = (self.has_logs_dates_match(other_record)
                  and self.has_ips_match(other_record)
                  and self.has_requests_match(other_record))
        return result

    def has_full_logs_match(self, other_record):
        result = (self.has_partial_logs_match(other_record)
                  and self.has_statuscodes_match(other_record)
                  and self.has_payloads_match(other_record))
        return result


def sort_logline(logline, data_bucket):
    """
    Gets user account of `logline` and add it to  `data_bucket`,
    if user account doesn't exist in `data_bucket` a new entry
    is created.

    Returns the updated dict `data_bucket`
    """
    useraccount_found = USERACCOUNT_REGEX.search(logline)
    if useraccount_found:
        useraccount = useraccount_found.group(1)
        if useraccount in data_bucket:
            data_bucket[useraccount].append(logline)
        else:
            data_bucket.update({useraccount: [logline]})

    return data_bucket


def open_log(log_filename):

    if log_filename.endswith('.log.gz'):
        print ('[INFO] Uncompressing file... ', end='')
        logfile = gzip.open(log_filename, 'rt')
        print('DONE')
    else:
        logfile = open(log_filename, 'r')
    return logfile


def lookup_log(log_filename, data_bucket, user_account=None, status_code=None):
    """
    Looks into a log file for HTTP error.

    Args:
    log_filename -> log file to look up
    user_account -> user of the service in log file
    status_code -> type of http error code (e.g 502)

    Returns a line of lines containing errors
    """
    error_lines = []

    if not data_bucket:
        reference_log = open_log(log_filename)
        print('[INFO] Parsing "', log_filename, '"... ',
              sep='', end='', flush=True)
        with reference_log:
            for line in reference_log:
                data_bucket = sort_logline(line, data_bucket)
            print('DONE')

    if status_code:
        error_format = '" ' + str(status_code)

        print('[INFO] Looking for status code in user acccount "',
              user_account, '"... ',
              sep='', end='', flush=True)
        for line in data_bucket[user_account]:
            loginfo = LogRecord(line, status_code)
            if loginfo.statuscode:
                error_lines.append(loginfo)

        print('DONE')
        print('[INFO] Lines found :', len(error_lines), flush=True)

    return error_lines


def compare_logs(log_filename, error_lines, status_code):
    """
    Compares timestamp from log file to a list of lines with HTTP error.
    """
    count = 0
    lines_found = error_lines[:]
    apache_lines = []
    same_lines = []
    payload_delta = []
    statuscode_delta = []
    status_and_payload_delta = []
    nomatch_lines = []

    comparison_log = open_log(log_filename)

    print('[INFO] Comparison with "', log_filename, '"... ',
          sep='', end='', flush=True)
    with comparison_log:
        for logline in comparison_log:
            apache_logline = LogRecord(logline, status_code)
            if not apache_logline.date or not apache_logline.statuscode:
                continue
            elif (apache_logline.statuscode
                  and status_code not in apache_logline.statuscode):
                continue

            apache_lines.append(apache_logline)

            for error_line in error_lines:
                if error_line.match_found:
                    continue

                if error_line.has_full_logs_match(apache_logline):
                    same_lines.append((error_line, apache_logline.line))
                    error_line.set_matched()
                    apache_logline.set_matched

                elif error_line.has_partial_logs_match(apache_logline):
                    if (error_line.has_statuscodes_match(apache_logline)
                            and not error_line.has_payloads_match(apache_logline)):
                        payload_delta.append((error_line, apache_logline.line))
                    elif error_line.has_statuscodes_match(apache_logline):
                        statuscode_delta.append((error_line,
                                                 apache_logline.line))

                    error_line.set_matched()
                    apache_logline.set_matched()

    # Get remaining log lines
    nomatch_lines = [line for line in error_lines if not line.match_found]
    print('DONE')

    return (same_lines,
            payload_delta,
            statuscode_delta,
            status_and_payload_delta,
            nomatch_lines,
            apache_lines)


def count_loglines(apache_log_filename,
                   alproxy_log_filename,
                   user_account=None):
    """
    Counts and compares the number of log lines written
    between apache_log_filename and alproxy_log_filename.
    """
    refcount = 0
    compcount = 0

    reference_log = open_log(apache_log_filename)
    with reference_log:
        for line in reference_log:
            refcount += 1

    comparison_log = open_log(alproxy_log_filename)
    with comparison_log:
        for line in comparison_log:
            # According to alproxy line format :
            if line.startswith(user_account) and ' | ' in line:
                compcount += 1

    if compcount < refcount:
        print('[ERROR] Log lines in "', alproxy_log_filename,
              '" for user account "', user_account,
              '" is smaller than "', apache_log_filename, '"',
              sep='')
        print('[INFO] Second input file MUST be alproxy log file.')
    else:
        print('[INFO] Normal behavior for "', alproxy_log_filename, '"',
              sep='')
    print('[INFO] Number of lines [',
          refcount, '/', compcount,
          '] [', apache_log_filename, '/', alproxy_log_filename, ']',
          sep='')


def print_loglines(loglines_list):
    """
    loglines_list MUST be formatted as follow:
    [(alproxy_line1, apache_line1),
    (alproxy_line2, apache_line2),
    ...]
    """
    for alproxy_logline, apache_logline in loglines_list:
        print(separator2)
        print(alproxy_line_message)
        print(alproxy_logline.line, end='')
        print(apache_line_message)
        print(apache_logline, end='')


def print_subsection(subsection_values, subsection_message, verbose):
    if subsection_values:
        print(subsection_message,
              ' Total = ', len(subsection_values),
              '\n', separator4, '\n', separator4,
              sep='')
        if verbose:
            print_loglines(subsection_values)


def make_summary(same_lines,
                 payload_delta_lines,
                 statuscode_delta_lines,
                 status_and_payload_delta,
                 nomatch_lines,
                 apache_lines,
                 verbose=False):
    """
    Prints out the comparison results in a formatted way.
    """
    match_section = '\t\t\tMATCH section'
    nomatch_section = '\t\t\tNO MATCH section'
    same_lines_subsect = 'Log lines are the same |'
    payload_delta_subsect = 'Payloads are different |'
    statuscode_delta_subsect = 'Status codes are different |'
    status_and_payload_subsect = 'Status codes and payloads are different |'
    no_lines_subsect = 'Log with no match found |'

    if (not same_lines
            and not payload_delta_lines
            and not statuscode_delta_lines
            and not status_and_payload_delta
            and not nomatch_lines):
        print('[INFO] No results to print\n', separator1, '\n')
        return

    print('[INFO] Generating results...')

    # Match section
    if (same_lines
            or payload_delta_lines
            or statuscode_delta_lines
            or status_and_payload_delta):
        print(separator1, match_section, separator1, sep='\n')

    print_subsection(same_lines,
                     same_lines_subsect,
                     verbose)
    print_subsection(payload_delta_lines,
                     payload_delta_subsect,
                     verbose=True)
    print_subsection(statuscode_delta_lines,
                     statuscode_delta_subsect,
                     verbose=True)
    print_subsection(status_and_payload_delta,
                     status_and_payload_subsect,
                     verbose=True)

    # No match section
    if nomatch_lines:
        print(separator1, nomatch_section, separator1, sep='\n')
        print(no_lines_subsect,
              ' Total = ', len(nomatch_lines),
              '\n', separator4, '\n', separator4,
              sep='')
        print(alproxy_line_message)
        for line in nomatch_lines:
            print(line.line, end='')
        print(apache_line_message)
        for line in apache_lines:
            print(line.line, end='')

    print()  # Display results bloc as paragraph


def process_files(alproxy_logfile,
                  apache_logfile,
                  data_bucket,
                  user_account,
                  status_code,
                  status_type,
                  verbose,):

    if status_type:
        status_code = status_type

    errors = lookup_log(alproxy_logfile,
                        data_bucket,
                        user_account=user_account,
                        status_code=status_code)

    results = compare_logs(apache_logfile, errors, status_code)

    make_summary(*results, verbose=verbose)


if __name__ == '__main__':
    args = argparser()

    if args.match:
        if args.recursive:
            ind = args.apache_logfile.rfind('/')
            path = args.apache_logfile[:ind]
            loglist = os.listdir(path=path)
            loglist = [(path + '/' + i, get_user_account(i)) for i in loglist
                       if (i.endswith('.log.gz') and 'alproxy' not in i)]
            for logfile in loglist:
                if args.user:
                    user_account = args.user
                else:
                    user_account = logfile[1]

                process_files(args.alproxy_logfile,
                              logfile[0],
                              data_bucket,
                              user_account,
                              args.statuscode,
                              args.statustype,
                              args.verbose)
            else:
                print('[INFO] Log files processed | Total =', len(loglist))
        else:
            process_files(args.alproxy_logfile,
                          args.apache_logfile,
                          data_bucket,
                          args.user,
                          args.statuscode,
                          args.statustype,
                          args.verbose)

    elif args.count:
        count_loglines(args.apache_logfile,
                       args.alproxy_logfile,
                       user_account=args.user)
