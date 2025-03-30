# Socks5_checker
Socks5 Proxy checker in python , for data scraping with high level of anonymity, this program MUST be used carefully regarding the law in vigor into the country there the user live.

## Features
This program is for educational use only, it supports denylist, mutiples csv inputs, and stealth mode (proxy whith proxy), support for CIDR format for denylist.

## Installation
* Create the folder inc/ and socks5/,
* put your csv containing your IP socks 5 into the socks5/ directory (csv must contains IP;Port columns and field at first or IP:Port format in the first field)
* put your denylist.csv file at the root of the script in the working directory
* start the script with python ./socks5.py


**Dependencies**
```py
pip3 install requests geoip2 pysocks
```

## Usage 

Non verbose mode :
```sh
./Socks5_checker.py
```
Verbose mode and check if a  scanned ip is blacklisted:
```sh
./Socks5_checker.py --v=log --isblacklisted
```
