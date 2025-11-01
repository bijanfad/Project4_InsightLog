import os
from unittest import TestCase
from insightlog.lib import *
import csv
import tempfile
from insightlog.lib import InsightLogAnalyzer


class TestInsightLog(TestCase):

    def test_get_date_filter(self):
        nginx_settings = get_service_settings('nginx')
        self.assertEqual(get_date_filter(nginx_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#1")
        self.assertEqual(get_date_filter(nginx_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#2")
        self.assertEqual(get_date_filter(nginx_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#3")
        apache2_settings = get_service_settings('apache2')
        self.assertEqual(get_date_filter(apache2_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#4")
        self.assertEqual(get_date_filter(apache2_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#5")
        self.assertEqual(get_date_filter(apache2_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#6")
        auth_settings = get_service_settings('auth')
        self.assertEqual(get_date_filter(auth_settings, 13, 13, 16, 1),
                         'Jan 16 13:13:', "get_date_filter#7")
        self.assertEqual(get_date_filter(auth_settings, '*', '*', 16, 1),
                         'Jan 16 ', "get_date_filter#8")

    def test_filter_data(self):
        nginx_settings = get_service_settings('nginx')
        date_filter = get_date_filter(nginx_settings, '*', '*', 27, 4, 2016)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.168.5', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 28, "filter_data#1")
        self.assertRaises(Exception, filter_data, log_filter='192.168.5')
        apache2_settings = get_service_settings('apache2')
        date_filter = get_date_filter(apache2_settings, 27, 11, 4, 5, 2016)
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.0.1', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 34, "filter_data#2")
        self.assertRaises(Exception, filter_data, log_filter='127.0.0.1')
        auth_settings = get_service_settings('auth')
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 19, "filter_data#3")
        data = filter_data('120.25.229.167', filepath=file_name, is_reverse=True)
        self.assertFalse('120.25.229.167' in data, "filter_data#4")

    def test_get_web_requests(self):
        nginx_settings = get_service_settings('nginx')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.10.1.1', filepath=file_name)
        requests = get_web_requests(data, nginx_settings['request_model'])
        self.assertEqual(len(requests), 2, "get_web_requests#1")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#2")
        requests = get_web_requests(data, nginx_settings['request_model'],
                                    nginx_settings['date_pattern'], nginx_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-04-24 06:26:37', "get_web_requests#3")
        apache2_settings = get_service_settings('apache2')
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.1.1', filepath=file_name)
        requests = get_web_requests(data, apache2_settings['request_model'])
        self.assertEqual(len(requests), 1, "get_web_requests#4")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#5")
        requests = get_web_requests(data, apache2_settings['request_model'],
                                    nginx_settings['date_pattern'], nginx_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-05-04 11:31:39', "get_web_requests#3")

    def test_get_auth_requests(self):
        auth_settings = get_service_settings('auth')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        requests = get_auth_requests(data, auth_settings['request_model'])
        self.assertEqual(len(requests), 18, "get_auth_requests#1")
        self.assertEqual(requests[17]['INVALID_PASS_USER'], 'root', "get_auth_requests#2")
        self.assertEqual(requests[15]['INVALID_USER'], 'admin', "get_auth_requests#3")
        requests = get_auth_requests(data, auth_settings['request_model'],
                                     auth_settings['date_pattern'], auth_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'][4:], '-05-04 22:00:32', "get_auth_requests#4")

    def test_logsanalyzer(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        auth_logfile = os.path.join(base_dir, 'logs-samples/auth.sample')
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        auth_logsanalyzer = InsightLogAnalyzer('auth', filepath=auth_logfile)
        nginx_logsanalyzer = InsightLogAnalyzer('nginx', filepath=nginx_logfile)
        auth_logsanalyzer.add_filter('120.25.229.167')
        auth_logsanalyzer.add_date_filter(minute='*', hour=22, day=4, month=5)
        requests = auth_logsanalyzer.get_requests()
        self.assertEqual(len(requests), 18, "LogsAnalyzer#1")
        nginx_logsanalyzer.add_filter('192.10.1.1')
        requests = nginx_logsanalyzer.get_requests()
        self.assertEqual(len(requests), 2, "LogsAnalyzer#2")

   
    def test_remove_filter_bug(self):
        analyzer = InsightLogAnalyzer('nginx')
        analyzer.add_filter('test1')
        analyzer.add_filter('test2')
        analyzer.add_filter('test3')
        analyzer.remove_filter(1)  # Should remove the second filter
        filters = analyzer.get_all_filters()
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[0]['filter_pattern'], 'test1')
        self.assertEqual(filters[1]['filter_pattern'], 'test3')
        # The bug: remove_filter currently tries to remove by value, not index

    #UnitTest for export CSV
    def test_export_to_csv(self):    
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        an = InsightLogAnalyzer('nginx', filepath=nginx_logfile)
        an.add_filter('192.10.1.1') 
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "export.csv")
            written = an.export_to_csv(out_path)
            self.assertEqual(written, 2)
            with open(out_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertTrue({'DATETIME','IP','METHOD','ROUTE','CODE','REFERRER','USERAGENT'}.issubset(rows[0].keys()))
    #UnitTest for BUG #5
    def test_auth_only_malformed_lines_returns_empty_list(self):
        """
        If the input contains only malformed lines, parsing should not raise
        and should return an empty list.
        """
        malformed = "TotallyWrongFormat without date host or process\nAnother bad line"
        analyzer = InsightLogAnalyzer('auth', data=malformed)
        requests = analyzer.get_requests()
        self.assertIsInstance(requests, list)
        self.assertEqual(len(requests), 0)

    def test_auth_malformed_lines_are_ignored_among_valid(self):
        """
        Mixing a malformed line into a valid auth log should not change the
        number of parsed requests (malformed line is ignored).
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        auth_logfile = os.path.join(base_dir, 'logs-samples/auth.sample')

        with open(auth_logfile, 'r', encoding='utf-8') as f:
            original = f.read()
        a1 = InsightLogAnalyzer('auth', data=original)
        n1 = len(a1.get_requests())
        mixed = original + "\nTHIS IS A MALFORMED LINE WITH NO MATCHING FIELDS\n"
        a2 = InsightLogAnalyzer('auth', data=mixed)
        n2 = len(a2.get_requests())

        self.assertEqual(n2, n1, "Malformed line should be ignored, not counted")

    #TestUnit BUG #6
    def test_file_encoding_handling(self):
        """
        BUG #6: Ensure non-UTF-8 files don't crash and can be filtered.
        The file is written as Latin-1 and includes a non-ASCII character.
        """
        # Minimal nginx-like lines; second line has a non-ASCII char in Latin-1
        lines = [
            '192.0.2.1 - - [16/Jan/2016:13:13:37 +0000] "GET / HTTP/1.1" 200 123\n',
            '198.51.100.7 - - [16/Jan/2016:13:13:38 +0000] "GET / café HTTP/1.1" 404 0\n',  # café (é in latin-1)
        ]
        content = ''.join(lines).encode('latin-1')  # write as NON-UTF-8

        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            tmp.write(content)
            tmp.flush()

            # 1) Core assertion: filter_data must not crash on non-UTF-8 input
            out = filter_data('192.0.2.1', filepath=tmp.name)
            self.assertIsInstance(out, str, "Should return a string, not None/bytes")
            # Should contain exactly the matching line
            self.assertIn('192.0.2.1', out)
            self.assertTrue(out.strip().endswith('"GET / HTTP/1.1" 200 123'),
                            "Returned line content should be intact for the matching line")

            # 2) Optional: analyzer path also must not crash
            analyzer = InsightLogAnalyzer('nginx', filepath=tmp.name)
            analyzer.add_filter('198.51.100.7')
            res = analyzer.filter_all()
            # We don't assert the exact non-ASCII character; some fixes use errors='replace'
            self.assertIn('198.51.100.7', res)
            self.assertIn('GET / ', res)  # general shape still present
    
    # UnitTest BUG #7
    def test_large_nginx_file_streaming(self):
        """
        BUG #7: Ensure very large log files are processed without loading
        everything into memory at once.
        The test creates a large temporary nginx log file and checks that all
        lines are parsed correctly without errors.
        """
        import tempfile
        import os

        sample_line = (
            '192.168.0.1 - - [24/Apr/2016:06:26:37 +0000] '
            '"GET / HTTP/1.1" 200 612 "-" "daedalu5"\n'
        )
        repeat_count = 50_000  # ~5–7 MB file; enough to catch non-streaming issues

        with tempfile.NamedTemporaryFile('w+', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.writelines(sample_line for _ in range(repeat_count))

        try:
            analyzer = InsightLogAnalyzer('nginx', filepath=tmp_path)
            analyzer.add_filter('192.168.0.1')
            results = analyzer.get_requests()

            # Verify all lines are parsed and fields are correct
            self.assertEqual(len(results), repeat_count)
            self.assertEqual(results[0]['IP'], '192.168.0.1')
            self.assertEqual(results[0]['METHOD'], 'GET')
        finally:
            os.remove(tmp_path)


# TODO: Add more tests for edge cases and error handling
