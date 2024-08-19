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
This script can also be utlized to collect TEchSupport files from UCSM domains running in IMM mode or UCSM domains claimed in IMM Mode.
For the domains running on Intersight in order to move forward and collect the information from various domain an API Key in needed. 

## Generation of API Key:
To obtain API keys for your API client, perform the steps below. Any user (Read-Only or Account Administrator) can generate API keys and can delete the keys that they generated. Account Administrators can delete the keys of the other users.

## Generating an API key from the User Interface
  1) Login to Intersight with your cisco.com credentials
  2) From the Intersight dashboard, click your name in the upper right corner, then click "Generate API Keys"
  3) You are presented with a key ID and private key.
       > This is your only opportunity to view, copy and download the private key.
       > Intersight does not store the private key, and the private key cannot be recovered.
       > However, you can create new API keys at any time.
  4) Copy the key ID and private in a secure location. The client owns the private key and is responsible for maintaining the confidentiality of the private key. Secure storage of the private keys at the client side is beyond the scope of this document.
  The generated private key and public key are encoded in PEM format.

## Authentication Process for API keys
When an API key is generated, the client can use the API key for authentication purpose to Intersight.
The client application uses the key-id and the cryptographic private key to sign HTTP requests.
Intersight verifies the signature of incoming HTTP requests by looking up the the public key for the specified key-id.

## Role-Based Access Control Policy and API Keys
The roles associated with the API key are inherited from the user who generated the API keys.

## Deleting API keys
API keys can be deleted at any time. You can login to Intersight with Single-Sign-On. From the Intersight dashboard, click your name in the upper right corner, then click "User Settings". Select the API key you want to delete.
