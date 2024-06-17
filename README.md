# L2_Burp
An attempt to create an analog of Burp Suite working not only for http(s), but for any traffic.

# Demo video 
![](https://gemoo.com/tools/upload-video/share/661392139245830144)

# Сapabilities
- Sniff like Wireshark
- Edit sniffed traffic
- Intercept and edit traffic from netfilter OUTPUT chain

# Install
```
sudo pacman -S libnetfilter_queue
or 
sudo apt-get install build-essential python-dev libnetfilter-queue-dev
```
```
python3 -m venv myenv
sudo bash
source myenv/bin/activate
pip install -r requirements.txt
python3 main_dev.py
```
