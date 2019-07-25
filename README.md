# Automating Cyber Incident Response

A common problem faced by cyber incident responders is the enormous amount of logs detected by sensors. In order to reduce the time spent on analysing them and eliminate false positives, our program helps to:
* Combine dynamic log information with static network information to automatically retrace the steps that the attacker took to conduct the intrusion
* List the possible paths that the attacker might take and the vulnerabilities in the network that the attacker could exploit, to reach the crown jewels, so that defenders can remove these paths 

## Getting Started

These instructions will get you a copy of the project up and running on your local machine. 

### Prerequisites

#### Python 3.x

* Visit https://www.python.org/downloads/ to download the latest suitable Python 3.x version according to your OS (we used Python 3.7 on Windows)

#### Splunk and Splunk SDK for Python

* Visit https://www.splunk.com/en_us/download.html and download the relevant edition of Splunk (we used the Splunk Enterprise 60-day trial)
* Set up the Splunk service to be running on your local machine
* Load your events into Splunk (we loaded `examples/eventSet.csv` as a local file to be monitored)
* Visit http://dev.splunk.com/view/python-sdk/SP-CAAAEDG to download the latest Splunk SDK for Python (we used version 1.6.6)
* Unpack and copy the downloaded package to the project folder, renaming the folder to `splunk`. Then install the splunk SDK using `python setup.py install`

#### MongoDB

* Visit https://www.mongodb.com/download-center/community to download the latest suitable Community server according to your OS (we used version 4.0.10 on Windows) 
* Set up MongoDB to run on `localhost:27017`

### Installation

The following Python packages are required:
1. networkx
2. pymongo
3. BeautifulSoup4
4. LXML
```
pip install networkx
pip install pymongo
pip install BeautifulSoup4
pip install LXML
```

### Configuration Files

These  contain data about your network and its vulnerabilities. Sample configuration files can be found in the `examples` folder.

#### Network Connectivity

Each host in a network can connect to the open ports on certain other hosts but not others, depending on firewall configurations. Create a CSV file encapsulating this information i.e. the hosts and ports each host in your network can reach. (See `reachability.csv` for an example)

* The first column contains the names of all hosts in your network
* The subsequent columns contain the other hosts and its ports that are connected to the host in the first column. Each host and port pairing is in the format `<host>,<port>`
* Each host is connected to its own open ports
* For example, if host B has port 1521 open and is connected to host A at port 1521 and host C at port 80, the row should be `B,"A,1521","B,1521","C,80"`

#### Vulnerabilities

Create a CSV file that contains information about the vulnerability occurrences in the network. (See `vulnerabilities.csv` for an example)
* The first column contains the name of the host having the vulnerability
* The second column contains the CVE ID of the vulnerability occurence
* The third column contains the vulnerability pertains to

#### CVEs
Create a CSV file that contains only the CVE ID of the vulnerabilities. This file is used by `web_scraping.py` (refer to the [next](#Running-the-Demo-Example) section) and has to contain minimally all the CVEs occuring in your network. (See `CVEs.csv` for an example)

#### Mapping of CVEs to Events

Create a CSV file that matches each CVE ID to an event description that the CVE manifests as. (See `cveToEvent.csv` for an example.)

* The first column contains the CVE ID in the form CVE-year-number.
* The second column contains the description of the event that happens when the corresponding CVE has been exploited.

### Running the Demo Example

This section assumes the demo event set `eventSet.csv` has been loaded into Splunk.

#### Preparation

The script `web_scraping.py` extracts information about the CVEs in `CVEs.csv` from https://www.cvedetails.com and https://nvd.nist.gov/ and loads it into MongoDB for later querying. This script should be run whenever a new CVE is discovered within your network (i.e. the CVE configuration file must be updated to contain this new CVE).

```
> python scripts/web_scraping.py
Enter CSV file (including extension) to read CVEs from: examples/CVEs.csv
Successfully imported CVE details
```
#### Event Reconstruction

Run the program `main.py` and input the entry points of the network (e.g. hosts A, B and C) and the configuration files: `reachability.csv`, `vulnerabilities.csv` and `cveToEvent.csv`. This generates the attack graph based on the given network topology and the vulnerabilities present in the network. 

Next, input a notable event with the assumed access level of the attacker.
* Event: `<timestamp>, <source host>, <destination host>, <source IP address>, <destination IP address>, <source port>, destination port>, <event description>`
* Access Level: `0 (None), 1 (User) or 2 (Root)`

```
> python main.py
Enter number of start nodes in attack graph: >>>3
Enter start node(s) name(s), separated by comma >>>A,B,C
Enter CSV file (including extension) containing reachability graph: examples/reachability.csv
Enter CSV file (including extension) containing vulnerabilities: examples/vulnerabilities.csv
Enter CSV file (including extension) containing mapping of CVE to event: examples/cveToEvent.csv

Enter notable event >>>
1563861901,F,U,192.170.27.22,102.68.0.2,7654,1521,suspected data exfiltration
Enter access level of attacker >>>2
```

##### Output

2 possible event sequences / attack paths are generated: 
```
Entry: 1563861738, U, C, chunk-encoded HTTP request received
 -> 1563861790, C, A, user_save function called with an explicit category
 -> 1563861805, A, D, SQL query submitted via url
 -> 1563861880, D, F, XPC message sent to make a new OpenVPN connection
 -> Notable event: 1563861901, F, U, suspected data exfiltration
 
Entry: 1563861738, U, C, chunk-encoded HTTP request received
 -> 1563861790, C, A, user_save function called with an explicit category
 -> 1563861805, A, D, SQL query submitted via url
 -> 1563861823, D, D, local user executes with root privilege
 -> 1563861880, D, F, XPC message sent to make a new OpenVPN connection
 -> Notable event: 1563861901, F, U, suspected data exfiltration
 ````

Now, you are ready to go ahead and input your own configuration files!

## Developer Guide
Refer [here](./DeveloperGuide.md) for the developer guide.

## Contributors

* Charmaine Lee 
* Daryl Tew
* Rebecca Tan 
