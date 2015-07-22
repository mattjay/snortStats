# snortStats
Python module to scrape snort alert log and spit out some useful stats

It takes snort log files via -f, the number of hours back you'd like to look -t (Default = 24 hours), and if you want the actual list of unique IPs -i or a list of the Top N most common IPs via -n

Note: Since snort alert logs don't include a year in the timestamp, this script does a comparison assuming everything is in current year.

Options:
```
-h, --help  show this help message and exit
-i, --ips   shows list of unique IPs that caused alerts
-t HOURS    number of hours back you want to look
-n IPS      List the n most common IPs to cause alerts in the given time period
-f FILES, --files=FILES
       		list of snort log file paths
```

Usage Examples:
```
python snortStats.py -f "snort.log"
python snortStats.py -i -t 48 -n 10 -f "../path/to/snort.log.0, ../path/to/snort.log.1, alert.fast.0.pcap"
