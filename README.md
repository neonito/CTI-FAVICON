# CTI-FAVICON

**Script was created with the aim of analyzing websites, utilizing favicons to identify potential threats. The main objective of the script is to use favicons as unique identifiers for searching other services using the same favicon, with a particular focus on the possibility of hunting down Command and Control (C2) servers**

# Main Aspects
**Favicon Analysis:**
- Script analyzes favicons assigned to different websites, treating them as unique identification marks.
  
**Favicon Hash Lookup in Shodan:**

- It searches the Shodan service for related IP addresses using unique favicon hashes, particularly with the intention of hunting down C2 servers.
  
**Information from AbuseIPDB and IPData.**
- For the identified IP addresses, the script leverages AbuseIPDB and IPData services, providing additional context for Threat Intelligence analysis. This includes information about whether an IP is marked as abuse, vpn, proxy, Tor, etc.
