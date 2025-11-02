import argparse
from insightlog.lib import InsightLogAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    parser.add_argument("--export-csv",type=str,help="Export filtered results to a CSV file at the given path")

    args = parser.parse_args()

    analyzer = InsightLogAnalyzer(args.service, filepath=args.logfile)
    if args.filter:
        analyzer.add_filter(args.filter)
    requests = analyzer.get_requests()
    for req in requests:
        print(req)
    
    if args.export_csv:
        try:
            count = analyzer.export_to_csv(args.export_csv)
            print(f"[INFO] Exported {count} rows to {args.export_csv}")
        except Exception as e:
            print(f"[ERROR] Failed to export CSV: {e}")

if __name__ == '__main__':
    main() 