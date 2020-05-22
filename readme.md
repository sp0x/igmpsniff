# IGMPSniff
This tool is an igmp sniffer that collects information about the igmp traffic through your interfaces.
All information is stored in a MySQL database so you can use it externally.

## Configuration
To configure the sniffer, just edit the file `config.ini`  
Also, to store data in the database, make sure you have created it firstly.


## Dependencies
This project uses pcap, dpkt and mysqlclient.  
Additional system libraries are also used, so make sure you have these installed:  
python3-dev, libmysqlclient-dev, libpcap-dev   

Install all the requirements using `pip install -r requirements.txt`

