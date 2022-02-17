# Hardware Inventory with SNMP

The script hw_inventory.py can be used to obtain the contents of the SNMP table entPhysicalTable of a list of network devices, for the purpose of building a CSV report of the contents of this table. The data contained in entPhysicalTable can be used by network administrators to audit their hardware inventory, find components that may be related to a vendors field notice, used for assessing lifecycle requirements, performing vendor maintenance true-ups, and many other reporting needs.

The script requires a single command line argument; a text file containing the IP addresses or FQDN's of the network devices to query. An optional argument of the maximum number of inventory components to query for a single device can also be provided. This defaults to 400 components, but for very large modular network switches it may be necessary to set this number higher if not all components are being seen in the output report.

```
% python get_inventory.py -h
usage: get_inventory.py...

SNMP Hardware Inventory. This script is used to query a list of devices for their entPhysicalTable. The results
are used to generate a CSV report detailing the hardware components for each device.

optional arguments:
  -h, --help    show this help message and exit
  -i inventory  An inventory text file containing an IP or FQDN per line.
  -m max-reps   The maximum number of inventory items to query for a network device. Default is 400.
```

The administrator will be prompted by the script for specifics associated with SNMP versions and authentication.

An example of running the script against an inventory file of two is as follows:

```
 % python get_inventory.py -i inventory.txt
Available SNMP Versions:
        Option 1: SNMP v1
        Option 2: SNMP v2c
        Option 3: SNMP v3
Option: 2
Community String:
Querying device 192.168.11.201
Querying device 192.168.11.202
Results written to hw_inventory.csv
```
