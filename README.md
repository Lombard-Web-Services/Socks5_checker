# 🕵️‍♂️ Socks5_checker 

Socks5 Proxy checker in python , for data scraping with high level of anonymity, this program MUST be used carefully regarding the law in vigor into the country there the user live.

## 🌟 Features 

This program is for educational use only, it supports denylist, mutiples csv inputs, and stealth mode (proxy whith proxy), support CIDR format for denylist.

## 🛠️ Installation 

* Create the folder `inc/` and `socks5/`.
* put your csv containing your IP socks 5 into the `socks5/` directory (csv must contains IP;Port columns and field at first or IP:Port format in the first field).
* put your `denylist.csv` file at the root of the script in the working directory.
* start the script with `python ./socks5.py`.

**Dependencies**
```py
pip3 install requests geoip2 pysocks
```

## 💻 Usage 

Non verbose mode :
```sh
./Socks5_checker.py
```
Verbose mode and check if a scanned ip is blacklisted:
```sh
./Socks5_checker.py --v=log --isdenylisted
```

## ⚖️ Credits & License 

**License:** 

![Logo de la licence CC BY-NC-ND](CC_BY-NC_ND.png)

**Author:** Thibaut LOMBARD

**GitHub:** [https://github.com/Lombard-Web-Services/Socks5_checker/](https://github.com/Lombard-Web-Services/Socks5_checker/)

### 📖 License Details 

This work is licensed under the **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License**. To view a copy of this license, visit [http://creativecommons.org/licenses/by-nc-nd/4.0/](http://creativecommons.org/licenses/by-nc-nd/4.0/) or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

The main conditions of this license are:
* **Attribution (BY):** You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **NonCommercial (NC):** You may not use the material for commercial purposes.
* **NoDerivatives (ND):** If you remix, transform, or build upon the material, you may not distribute the modified material.
