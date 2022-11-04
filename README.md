# Quick Start

1. `git clone git@github.com:brightpuddle/ucs-techsupport collector.git` **-or-** download and unzip [the code from this repo](https://github.com/brightpuddle/ucs-techsupport-collector/archive/refs/heads/main.zip).
2. Copy the `sample-config.yaml` file to `config.yaml`
3. If collecting from Intersight, follow the instructions to generate an Intersight API key.
4. Edit `config.yaml` to add your UCSM hosts or Intersight IPs.
5. Run the script with `python collect_ts.py`.

# Requirements

- Python 3.10 (expected to be compatible with Python 3.9, but not tested)
- `pip install requirements.txt`
- Network access to collection targets, e.g. UCSM hosts and/or https://intersight.com

# Intersight API key generation
#TODO
