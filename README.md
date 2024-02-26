# CTI-FAVICON

**Script was created with the aim of analyzing websites, utilizing favicons to identify potential threats. The main objective of the script is to use favicons as unique identifiers for searching other services using the same favicon, with a particular focus on the possibility of hunting down Command and Control (C2) servers**

# Main Aspects
**Favicon Analysis:**
- Script analyzes favicons assigned to different websites, treating them as unique identification marks.
  
**Favicon Hash Lookup in Shodan:**

- It searches the Shodan service for related IP addresses using unique favicon hashes, particularly with the intention of hunting down C2 servers.
  
**Information from AbuseIPDB and IPData.**
- For the identified IP addresses, the script leverages AbuseIPDB and IPData services, providing additional context for Threat Intelligence analysis. This includes information about whether an IP is marked as abuse, vpn, proxy, Tor, etc.

**Scan results.**
- The results of the analysis, along with information, are stored in a JSON file.

# How To Use

- Fill the script with the required api keys.
- Create a txt file named ulrs.txt put the url there.
- run python3 ctifavion.py

# Example Result
```{
  "Total Shodan IPs found": 1,
  "Total pages processed": 1,
  "Total pages skipped": 0,
  "Valid IPs": [
    "127.0.0.1"
  ],
  "Data": [
    {
      "shodan_result": {
        "ip": "127.0.0.1",
        "port": 80,
        "header": "HTTP/1.1 200 OK",
        "name": "localhost"
      },
      "abuseipdb_result": {},
      "ipdata_result": {
        "threat": {
          "is_tor": false,
          "is_icloud_relay": false,
          "is_proxy": false,
          "is_datacenter": false,
          "is_anonymous": false,
          "is_known_attacker": false,
          "is_known_abuser": false,
          "is_threat": false,
          "is_bogon": false,
          "blocklists": [],
          "scores": {}
        }
      }
    }
  ]
}```
