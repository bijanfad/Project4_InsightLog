import re
import calendar
from insightlog.settings import *
from insightlog.validators import *
from datetime import datetime
from typing import Iterable, TextIO
import os
import csv



def get_service_settings(service_name):

    """
    Get default settings for the said service
    :param service_name: service name (example: nginx, apache2...)
    :return: service settings if found or None
    """
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception(f'Service "{service_name}" doesn\'t exists!')
        


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):
    """
    Get the date pattern that can be used to filter data from logs based on the params
    :raises Exception:
    :param settings: dict
    :param minute: int
    :param hour: int
    :param day: int
    :param month: int
    :param year: int
    :return: string
    """
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")
    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise Exception("Date elements aren't valid")
    return date_filter


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    """
    Filter received data/file content and return the results
    :except IOError:
    :except EnvironmentError:
    :raises Exception:
    :param log_filter: string
    :param data: string
    :param filepath: string
    :param is_casesensitive: boolean
    :param is_regex: boolean
    :param is_reverse: boolean to inverse selection
    :return: string
    """
    # BUG: This function returns None on error instead of raising
    # BUG: No encoding handling in file reading (may crash on non-UTF-8 files)
    # TODO: Log errors/warnings instead of print
    # FIX (#6): add encoding handling and fallbacks to avoid UnicodeDecodeError on non-UTF-8 files
    return_data = ""
    if filepath:
        try:
            # with open(filepath, 'r') as file_object:
            #     for line in file_object:
            #         if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
            #             return_data += line
            with open(filepath, "r", encoding="utf-8", errors="replace") as file_object:
            # with _open_text_with_fallback(filepath) as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            print(e.strerror)
            # TODO: Log error instead of print
            # raise  # Should raise instead of just printing
            return None
    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line+"\n"
        return return_data
    else:
        # TODO: Better error message for missing data/filepath
        raise Exception("Data and filepath values are NULL!")

def _open_text_with_fallback(path: str, encodings: Iterable[str] = ("utf-8","utf-8-sig","cp1252","latin-1")) -> TextIO:
    """
    Open a text file trying multiple encodings before falling back to 'errors=replace'.
    Returns a file object ready for iteration.
    """
    last_err = None
    for enc in encodings:
        try:
            return open(path, "r", encoding=enc)
        except UnicodeDecodeError as ue:
            last_err = ue
            continue
    # Final safe fallback: do not crash; replace undecodable bytes
    try:
        return open(path, "r", encoding="utf-8", errors="replace")
    except Exception as e:
        # Propagate non-decode errors (e.g., file not found) to caller
        raise e from last_err

def check_match(line, filter_pattern, is_regex, is_casesensitive, is_reverse):
    """
    Check if line contains/matches filter pattern
    :param line: string
    :param filter_pattern: string
    :param is_regex: boolean
    :param is_casesensitive: boolean
    :param is_reverse: boolean
    :return: boolean
    """
    if is_regex:
        check_result = re.match(filter_pattern, line) if is_casesensitive \
            else re.match(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    return check_result and not is_reverse
                          

def get_web_requests(data, pattern, date_pattern=None, date_keys=None, collect_stats=False):
    """
    Analyze data (from the logs) and return list of requests formatted consistently
    with get_auth_requests output.
    

    :param data: string
    :param pattern: string
    :param date_pattern: regex|None
    :param date_keys: dict|None
    :return: list  |  (list, {'malformed_lines': int}) if collect_stats=True
    """
    # BUG: Output format inconsistent with get_auth_requests
    # BUG: No handling/logging for malformed lines
    # Handle malformed lines by counting lines that don't match the pattern.
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    requests = []
    malformed = 0
    regex = re.compile(pattern, flags=re.IGNORECASE)
    for line in data.splitlines():
        m = regex.search(line)
        if not m:
            if line.strip():  # ignore blank lines
                malformed += 1
            continue
        request_tuple = m.groups()
        if date_pattern:
            str_datetime = __get_iso_datetime(request_tuple[1], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[1]
        requests.append({
            'DATETIME': str_datetime,
            'IP': request_tuple[0],
            'USER': '-',  # Web logs typically don't have user info, use placeholder
            'METHOD': request_tuple[2],
            'ROUTE': request_tuple[3],
            'CODE': request_tuple[4],
            'REFERRER': request_tuple[5],
            'USERAGENT': request_tuple[6],
        })
    if collect_stats:
        return requests, {'malformed_lines': malformed}
    return requests

def get_auth_requests(data, pattern, date_pattern=None, date_keys=None, collect_stats=False):
    """
    Analyze data (from the logs) and return list of auth requests formatted as the model (pattern) defined.
    :param data: string
    :param pattern: string
    :param date_pattern:
    :param date_keys:
    :return: list of dicts  |  (list, {'malformed_lines': int}) if collect_stats=True
    """
    # requests_dict = re.findall(pattern, data)
    # requests = []
    # for request_tuple in requests_dict:
    #     if date_pattern:
    #         str_datetime = __get_iso_datetime(request_tuple[0], date_pattern, date_keys)
    #     else:
    #         str_datetime = request_tuple[0]
    #     data = analyze_auth_request(request_tuple[2])
    #     data['DATETIME'] = str_datetime
    #     data['SERVICE'] = request_tuple[1]
    #     requests.append(data)
    # return requests
    requests = []
    malformed = 0
    regex = re.compile(pattern)
    for line in data.splitlines():
        m = regex.search(line)
        if not m:
            if line.strip():
                malformed += 1
            continue
        request_tuple = m.groups()
        if date_pattern:
            str_datetime = __get_iso_datetime(request_tuple[0], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[0]
        item = analyze_auth_request(request_tuple[2])
        item['DATETIME'] = str_datetime
        item['SERVICE'] = request_tuple[1]
        requests.append(item)
    if collect_stats:
        return requests, {'malformed_lines': malformed}
    return requests

def analyze_auth_request(request_info):
    """
    Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)
    :param request_info: string
    :return: dicts
    """
    # BUG: No handling/logging for malformed lines
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()
    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed}


def __get_iso_datetime(str_date, pattern, keys):
    """
    Change raw datetime from logs to ISO 8601 format.
    :param str_date: string
    :param pattern: regex (date_pattern from settings)
    :param keys: dict (date_keys from settings)
    :return: string
    """
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    a_date = re.findall(pattern, str_date)[0]
    d_datetime = datetime(int(a_date[keys['year']]) if 'year' in keys else __get_auth_year(),
                          months_dict[a_date[keys['month']]], int(a_date[keys['day']].strip()),
                          int(a_date[keys['hour']]), int(a_date[keys['minute']]), int(a_date[keys['second']]))
    return d_datetime.isoformat(' ')


def __get_auth_year():
    # TODO: Add support for analysis done in different terms
    """
    Return the year when the requests happened so there will be no bug if the analyze is done in the new year eve,
    the library was designed to be used for hourly analysis.
    :return: int
    """
    if datetime.now().month == 1 and datetime.now().day == 1 and datetime.now().hour == 0:
        return datetime.now().year - 1
    else:
        return datetime.now().year


class InsightLogAnalyzer:

    def __init__(self, service, data=None, filepath=None):
        """
        Constructor, define service (nginx, apache2...), set data or filepath if needed
        :param service: string: service name (nginx, apache2...)
        :param data: string: data to be filtered if not from a file
        :param filepath: string: file path from which the data will be loaded if data isn't defined
        and you are not using the default service logs filepath
        :return:
        """
        self.__filters = []
        self.__settings = get_service_settings(service)
        self.data = data
        if filepath:
            self.filepath = filepath
        else:
            self.filepath = self.__settings['dir_path']+self.__settings['accesslog_filename']

    def add_filter(self, filter_pattern, is_casesensitive=True, is_regex=False, is_reverse=False):
        """
        Add filter data the filters list
        :param filter_pattern: boolean
        :param is_casesensitive: boolean
        :param is_regex: boolean
        :param is_reverse: boolean
        :return:
        """
        self.__filters.append({
            'filter_pattern': filter_pattern,
            'is_casesensitive': is_casesensitive,
            'is_regex': is_regex,
            'is_reverse': is_reverse
        })

    def add_date_filter(self, minute=datetime.now().minute, hour=datetime.now().hour,
                        day=datetime.now().day, month=datetime.now().month, year=datetime.now().year):
        """
        Set datetime filter
        :param minute: int
        :param hour: int
        :param day: int
        :param month: int
        :param year: int
        """
        date_filter = get_date_filter(self.__settings, minute, hour, day, month, year)
        self.add_filter(date_filter)

    def get_all_filters(self):
        """
        return all defined filters
        :return: List
        """
        return self.__filters

    def get_filter(self, index):
        """
        Get a filter data by index
        :param index:
        :return: Dictionary
        """
        return self.__filters[index]

    def remove_filter(self, index):
        """
        Remove one filter from filters list using it's index
        :param index:
        :return:
        """
        # BUG: This method does not remove by index
        #This is the firs bug which is resolved by Bijan
        if not isinstance(index, int):
            raise TypeError("index must be an int")
        try:
            self.__filters.pop(index)
        except IndexError:
            raise IndexError("filter index out of range")

    def clear_all_filters(self):
        """
        Clear all filters
        :return:
        """
        self.__filters = []

    def check_all_matches(self, line, filter_patterns):
        """
        Check if line contains/matches all filter patterns
        :param line: String
        :param filter_patterns: List of dictionaries containing
        :return: boolean
        """
        if not filter_patterns:
            return True  # No filters means include all lines
        to_return = None
        for pattern_data in filter_patterns:
            tmp_result = check_match(line=line, **pattern_data)
            to_return = tmp_result if to_return is None else (tmp_result and to_return)
        return to_return

    def iter_filtered_lines(self):
        """
        Yield filtered lines lazily to avoid large in-memory buffers.
        """
        if self.data:
            # data is already in-memory; still iterate without rebuilding strings
            for line in self.data.splitlines(True):  # keep line endings
                if self.check_all_matches(line, self.__filters):
                    yield line
        else:
            # Encoding errors shouldn't crash analysis (Bug #6); keepends to preserve parsing
            with open(self.filepath, 'r', encoding='utf-8', errors='replace') as file_object:
                for line in file_object:
                    if self.check_all_matches(line, self.__filters):
                        yield line

    def filter_all(self):
        """
        Back-compat helper: return all filtered lines as a single string.
        Prefer iter_filtered_lines() for streaming.
        """
        buf = []
        append = buf.append
        for line in self.iter_filtered_lines():
            append(line)
        return ''.join(buf)

    def get_requests(self, output_format='list', log_level=None, start_time=None, end_time=None):
        """
        Analyze data (from the logs) and return list of requests formatted as the model (pattern) defined.
        
        :param output_format: 'list', 'csv', 'json' - output format for results
        :param log_level: string - filter by log level (e.g., 'ERROR', 'WARNING')
        :param start_time: datetime - start time for filtering
        :param end_time: datetime - end time for filtering
        :return: requests in specified format
        """
        request_pattern = self.__settings['request_model']
        date_pattern = self.__settings.get('date_pattern')
        date_keys = self.__settings.get('date_keys')

        CHUNK_LINES = 10000
        chunk = []
        requests = []
        extend = requests.extend

        def flush_chunk():
            if not chunk:
                return
            data_block = ''.join(chunk)
            # Support more log formats (e.g., IIS, custom logs)
            if self.__settings['type'] == 'web0':
                extend(get_web_requests(data_block, request_pattern, date_pattern, date_keys))
            elif self.__settings['type'] == 'auth':
                extend(get_auth_requests(data_block, request_pattern, date_pattern, date_keys))
            elif self.__settings['type'] == 'iis':
                # TODO: Implement IIS log format parsing
                print("IIS log format support not yet implemented")
            elif self.__settings['type'] == 'custom':
                # TODO: Implement custom log format parsing
                print("Custom log format support not yet implemented")
            else:
                # Unknown log format
                return None
            chunk.clear()

        # Add log level filtering
        for line in self.iter_filtered_lines():
            if log_level and not self._matches_log_level(line, log_level):
                continue
            chunk.append(line)
            if len(chunk) >= CHUNK_LINES:
                flush_chunk()
        flush_chunk()

        # Add support for time range filtering
        if start_time or end_time:
            requests = self._filter_by_time_range(requests, start_time, end_time)

        # Add support for CSV and JSON output
        if output_format == 'csv':
            return self._convert_to_csv(requests)
        elif output_format == 'json':
            return self._convert_to_json(requests)
        else:  # Default to list format
            return requests

    def _matches_log_level(self, line, log_level):
        """
        Check if line matches the specified log level
        :param line: string - log line
        :param log_level: string - log level to filter by
        :return: boolean
        """
        # Simple implementation - can be enhanced based on log format
        return log_level.upper() in line.upper()

    def _filter_by_time_range(self, requests, start_time, end_time):
        """
        Filter requests by datetime range
        :param requests: list of request dicts
        :param start_time: datetime - start time
        :param end_time: datetime - end time
        :return: filtered list of requests
        """
        filtered_requests = []
        for request in requests:
            if 'DATETIME' in request:
                try:
                    # Parse the datetime string to compare
                    request_time = datetime.strptime(request['DATETIME'], '%Y-%m-%d %H:%M:%S')
                    if start_time and request_time < start_time:
                        continue
                    if end_time and request_time > end_time:
                        continue
                    filtered_requests.append(request)
                except (ValueError, KeyError):
                    # If datetime parsing fails, include the request
                    filtered_requests.append(request)
            else:
                # If no DATETIME field, include the request
                filtered_requests.append(request)
        return filtered_requests

    def _convert_to_csv(self, requests):
        """
        Convert requests list to CSV format
        :param requests: list of request dicts
        :return: CSV string
        """
        if not requests:
            return ""
        
        import io
        output = io.StringIO()
        if requests:
            fieldnames = list(requests[0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(requests)
        
        return output.getvalue()

    def _convert_to_json(self, requests):
        """
        Convert requests list to JSON format
        :param requests: list of request dicts
        :return: JSON string
        """
        import json
        return json.dumps(requests, indent=2)

    def export_to_csv(self, path):
        """
        Export filtered results to a CSV file.
        Returns the number of rows written.
        :param path: string
        """
        rows = self.get_requests() or []

        # Ensure parent folder exists (if a folder is provided)
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)

        # If there are no rows, write an empty file with no header and return 0
        if not rows:
            # still create/overwrite the file so the caller gets a tangible result
            with open(path, "w", encoding="utf-8", newline="") as f:
                pass
            return 0

        fieldnames = list(rows[0].keys())
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return len(rows)

# TODO: Write more tests for edge cases, error handling, and malformed input