# Socks5_checker
Socks5 Proxy checker in python , for data scraping with anonimity, this program MUST be used carefully regarding the law in vigor into you country.

## Features
This program is for educational use only, it supports  blacklist, mutiples csv inputs, and stealth mode (proxy whith proxy), support for CIDR format for blacklist.

## Installation
* Create the folder inc/ and socks5/,
* put your csv containing your IP socks 5 into the socks5/ directory (csv must contains IP;Ports columns or IP:Ports format in the first field)
* put your blacklist.csv file at the root of the script in the working directory
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
Verbose mode and check if a blackliste:
```sh
./Socks5_checker.py --v=log --isblacklisted
```
