### Overview

Malcolm is a threat investigation and detection tool
- investigation: uses more Zeek plugins so extracted Zeek logs are more detailed 
than TIP. Also correlates data with Moloch
- detection: leverages on open source info like AV for signature detection
- requires at least 16 gb of RAM. 16 cores for large data volume
- designed to store 10 TB of data for up to 5 years

TIP has the ability to sessionise payload and search across PCAPS.

### Architecture
Both 
- are running on a Zeek-ELK microservice architecture
- use Kibana for investigation and visualisation
- lack a machine learning workflow to generate insights

### Conclusion
Malcolm is a threat investigation and detection tool. Development 
appears to be outsourced to Battelle Energy Alliance, LLC

### Nginx 
Can authenticate users with either local TLS-encrypted HTTP basic authentication or using a remote Lightweight Directory Access Protocol (LDAP) authentication server.
Authenticate against Lightweight Directory Access Protocol (LDAP) server? (y/N): n

Create daily snapshots (backups) of Elasticsearch indices? (y/N): n

Periodically close old Elasticsearch indices? (y/N): y

Indices older than 5 years will be periodically closed. Is this OK? (Y/n): y

Periodically delete old Elasticsearch indices? (y/N): y

Indices older than 10 years will be periodically deleted. Is this OK? (Y/n): y

Periodically delete the oldest Elasticsearch indices when the database exceeds a certain size? (y/N): y

Indices will be deleted when the database exceeds 10000 gigabytes. Is this OK? (Y/n): y

Automatically analyze all PCAP files with Zeek? (Y/n): y

Perform reverse DNS lookup locally for source and destination IP addresses in Zeek logs? (y/N): y

Perform hardware vendor OUI lookups for MAC addresses? (Y/n): y

Perform string randomness scoring on some fields? (Y/n): y

Expose Logstash port to external hosts? (y/N): y

Should Logstash require SSL for Zeek logs? (Note: This requires the forwarder to be similarly configured and a corresponding copy of the client SSL files.) (Y/n): n

Forward Logstash logs to external Elasticstack instance? (y/N): n

Enable file extraction with Zeek? (y/N): y

Select file extraction behavior ('none', 'known', 'mapped', 'all', 'interesting'): all

Select file preservation behavior ('quarantined', 'all', 'none'): none

Scan extracted files with ClamAV? (y/N): y

Download updated ClamAV virus signatures periodically? (Y/n): y

Scan extracted files with Yara? (y/N): y

Scan extracted PE files with Capa? (y/N): y

Lookup extracted file hashes with VirusTotal? (y/N): n

Should Malcolm capture network traffic to PCAP files? (y/N): n

