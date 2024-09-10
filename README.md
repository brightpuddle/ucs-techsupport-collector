# Quick Start

1. `git clone git@github.com:brightpuddle/ucs-techsupport collector.git` **-or-** download and unzip [the code from this repo](https://github.com/brightpuddle/ucs-techsupport-collector/archive/refs/heads/main.zip).
2. Copy the `sample-config.yaml` file to `config.yaml`
3. If collecting from Intersight, follow the instructions to generate an Intersight API key.
4. Edit `config.yaml` to add your UCSM hosts or Intersight IPs.
5. Run the script with `python collect_ts.py`.

# Requirements

- Python 3.10 (expected to be compatible with Python 3.9, but not tested)
- `pip install -r requirements.txt`
- Network access to collection targets, e.g. UCSM hosts and/or https://intersight.com

# Intersight API key generation
This script can also be utlized to collect TechSupport files from UCSM domains running in IMM mode or UCSM domains claimed in IMM Mode.
For the domains running on Intersight in order to move forward and collect the information from various domain an OAuth key in needed. 

## Generation of API Key:
To obtain API keys for your API client, perform the steps below. Any user (Read-Only or Account Administrator) can generate API keys and can delete the keys that they generated. Account Administrators can delete the keys of the other users.

## Generating an API key from the User Interface
  1) Login to Intersight with your credentials
  2) From the Intersight dashboard, Select "system" in services drop down. Click OAuth2.0.
  3) Select "Create OAuth2.0" and enter the details required. (Ex: App Name: UCS_Vetr, Description: UCS Health Check Tech Support Collector)
  4) You are presented with a Client ID and Client Secret.       
       > Copy these details and appropriate.
       > Select "I have downloaded...." 
       > However, you can create new API keys at any time.
  5) Copy the ID and Key in a secure location. The client owns the ID and key and is responsible for maintaining the confidentiality of the ID and key. Secure storage of the ID and keys at the client side is beyond the scope of this document.
  The generated private ID and key can be used in the techsupport collector yaml input file.

## Authentication Process for API keys
When an ID and key are generated, the client can use the ID and key for authentication purpose to Intersight.


## Deleting API keys
API keys can be deleted at any time. You can login to Intersight. From the Intersight dashboard, go to where the OAuth ID/Key were created and delete as appropriate. 
