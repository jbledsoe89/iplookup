#!/usr/bin/env python3

import re
import csv
import argparse
import ipaddress
import urllib.request
import urllib.parse
import json
import sys
import os
import time
import datetime
from json.decoder import JSONDecodeError

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Query IP addresses (IPv4 and IPv6) using the AbuseIPDB API and save the results to a CSV file.'
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-r",
        "--regex",
        help="Read IP addresses from a file using regex.",
        action="store"
    )

    group.add_argument(
        "-t",
        "--textfile",
        help="Read IP addresses from a text file.",
        action="store"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output results to a CSV file.",
        action="store",
        default="abuseipdb_" + datetime.datetime.now().strftime("%Y%m%d_%H%M") + ".csv"
    )

    parser.add_argument(
        "-d", "--days",
        help="Number of days in history to go back for IP reports. Default: 30 days.",
        type=int,
        default=30
    )

    parser.add_argument(
        "-s", "--sleep",
        help="Time in seconds to sleep between API requests to respect rate limits (Default: 0.2).",
        type=float,
        default=0.2
    )

    parser.add_argument(
        "-a", "--apikey",
        help="Your API key for AbuseIPDB. Can also be set via the ABUSEIPDB_API_KEY environment variable."
    )

    args = parser.parse_args()

    if args.sleep < 0:
        parser.error("Sleep time cannot be negative.")

    return args

def extract_ips(content):
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'\b(?:[A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}\b'
    pattern = f'({ipv4_pattern})|({ipv6_pattern})'
    matches = re.findall(pattern, content, re.IGNORECASE)
    ips = set()
    for match in matches:
        ips.update(filter(None, match))
    return ips

def check_ip(api_key, ip, days):
    result = {'ip': ip}
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            result['error'] = "Private IP address. No results."
            return result

        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }

        # Construct the URL with properly encoded query parameters
        params = {
            'ipAddress': ip,
            'maxAgeInDays': days,
            'verbose': 'true'
        }
        query_string = urllib.parse.urlencode(params)
        url = f"https://api.abuseipdb.com/api/v2/check?{query_string}"

        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request) as response:
            data = response.read().decode('utf-8')
            api_result = json.loads(data)

        if 'errors' in api_result:
            result['error'] = api_result['errors'][0]['detail']
        else:
            result.update(api_result['data'])
    except ValueError:
        result['error'] = "Invalid IP address."
    except urllib.error.HTTPError as e:
        result['error'] = f"HTTP error occurred: {e.code} {e.reason}"
    except urllib.error.URLError as e:
        result['error'] = f"URL error occurred: {e.reason}"
    except JSONDecodeError as e:
        result['error'] = f"JSON decoding failed: {e}"
    except Exception as e:
        result['error'] = f"An unexpected error occurred: {e}"
    return result

def check_file(api_key, filename, days, sleep_time, use_regex=False):
    logs = []
    try:
        with open(filename, 'r') as file:
            if use_regex:
                content = file.read()
                ips = extract_ips(content)
            else:
                ips = set(line.strip() for line in file)

        ips = [ip for ip in ips if ip]  # Remove empty strings

        # Validate IPs before processing
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                logs.append({'ip': ip, 'error': "Invalid IP address."})
                continue

        if not valid_ips:
            print("No valid IP addresses found to process.")
            return logs

        for idx, ip in enumerate(valid_ips, 1):
            print(f"Processing {idx}/{len(valid_ips)}: {ip}")
            result = check_ip(api_key, ip, days)
            logs.append(result)
            # Adjust rate limit.
            time.sleep(sleep_time)
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")
    return logs

def write_to_csv(logs, output_file):
    if logs:
        # Collect all keys from logs to ensure all columns are represented
        keys = set().union(*(log.keys() for log in logs))
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sorted(keys))
            writer.writeheader()
            writer.writerows(logs)
        print(f"Results written to {output_file}")
    else:
        print("No data to write to CSV.")

def main():
    args = parse_arguments()

    # API key management
    api_key = args.apikey or os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        print("API key not provided. Use -a/--apikey or set the ABUSEIPDB_API_KEY environment variable.")
        sys.exit(1)

    # Overwrite prevention check
    if os.path.exists(args.output):
        response = input(f"Output file {args.output} already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Operation cancelled by user.")
            sys.exit(1)  # Exit the script if the user doesn't confirm overwrite

    if args.regex:
        logs = check_file(api_key, args.regex, args.days, args.sleep, use_regex=True)
        write_to_csv(logs, args.output)
    elif args.textfile:
        logs = check_file(api_key, args.textfile, args.days, args.sleep, use_regex=False)
        write_to_csv(logs, args.output)
    else:
        print("Please specify a file using -r/--regex or -t/--textfile.")
        sys.exit(1)

if __name__ == "__main__":
    main()