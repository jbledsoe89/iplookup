# AbuseIPDB IP Lookup

A Python script to query IP addresses (IPv4 and IPv6) using the [AbuseIPDB API](https://www.abuseipdb.com/api) and save the results to a CSV file.

## Features

- Extract IP addresses from any file using regular expressions.
- Read IP addresses directly from a text file (one IP per line).
- Validate IP addresses before querying.
- Query AbuseIPDB for reports on IP addresses with adjustable history length.
- Handle API rate limiting with adjustable sleep time between requests.
- Output results to a CSV file with detailed information.

## Requirements

- Python 3.x
- An API key from [AbuseIPDB](https://www.abuseipdb.com/register).

## Usage

```base
python3 ip_checker.py -r /path/to/logfile.log -o results.csv -a YOUR_API_KEY
```

Options
-r, --regex <file>
Extract IP addresses from a file using regex.

-t, --textfile <file>
Read IP addresses from a text file (one IP per line).

-o, --output <file>
Specify the output CSV file. Default is output_YYYYMMDD_HHMM.csv.

-d, --days <int>
Number of days in history to search for IP reports. Default is 30 days.

-s, --sleep <float>
Sleep time in seconds between API requests to respect rate limits. Default is 0.2 seconds.

-a, --apikey <key>
Your API key for AbuseIPDB. Alternatively, set the ABUSEIPDB_API_KEY environment variable.

## Using an environment variable for the API key
```bash
export ABUSEIPDB_API_KEY=YOUR_API_KEY
python3 ip_checker.py -t ips.txt
```
