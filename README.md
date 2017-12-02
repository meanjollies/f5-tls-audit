# f5-tls-audit

This was originally written to quickly figure out which TLS certs in an F5 load balancer are affected by Google's plan to distrust Symantec-issued certs (and their subsidiaries). More info on that [here](https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html). This attempts to inspect which certs on an F5 are affected by this, although it can be modified for other purposes (including when a cert expires!). For each cert, the issuing CA is checked, in addition to the cert's issuing date. When a cert is found to have been issued by a flagged CA before the specific deadline, the cert's CA will be highlighted yellow, and the issuing date will be highlighted red.

This also functions as just a regular audir expired certs. Any certs that are expired will be highlighted red.

### Usage
```$ ./f5-tls-audit.rb```

### Configuration

Prior to running, make sure options.yaml is filled out. All parameters are required.

You should confirm the path where your F5's certs are stored. The stock location is what my F5 used, so yours might be different.

Flagged CAs are those you specifically care about. When the audit runs, only certs issued by these CAs will be given a particular color. Note that the CA names used here are their standard names. To find out the name used by a CA, inspect any of their public certs and use the issuer's name.

License
---
MIT
