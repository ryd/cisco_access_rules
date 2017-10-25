# Cisco Access Rules list parser

The purpose of this application is supporting pentester and auditors finding 
and controlling firewall access rules. Based on one IP, all rules are shown.

This tool is developed with the purpose of PCI DSS auditing. With a copy of the
rules, proper isolation and zoning can be verified.

## Copyright
Copyright by Jens (ryd) Muecke under GPLv3.

## Howto
The application is developed in python. Binary executable are available as well.

The syntax is simple, first parameter define the IP to verify (e.g. Category 1 
System). Second and following parameter are list of files to parse.

* list_rules.py <IP> <list of text files>

Example:
```
# list_rules.py 10.0.0.1 *.log
```

## Feedback

Shoot me an email to j.muecke@kryptonsecurity.com or use the github page
under https://github.com/ryd/cisco_access_rules

