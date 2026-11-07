# threat-YamlVulnChecker

A command-line tool that parses YAML files for common security misconfigurations (for example exposed keys or default passwords) based on a configurable ruleset. Rules use a dot path, a check type (equality or contains), and a value. A rule that sets `required: true` fires when its path is absent from the YAML file. Other rules whose path is absent are counted in the report as not evaluated. Matched expected and actual values are masked in the report (length and a short hash only, never the full contents). The checker exits 0 for a clean completed check, and exits 1 when vulnerabilities are found, when a rule cannot be evaluated, or when a file cannot be loaded or analyzed. Both files are loaded with yaml.safe_load.

## Install
`git clone https://github.com/ShadowGuard-AI/threat-yamlvulnchecker.git`

## Usage
`python3 main.py -f config.yaml -r rules.yaml`

The ruleset file is a YAML list of rules, or a mapping with a `rules` list. A rule entry that is not a mapping is counted as a rule error and the remaining rules are still evaluated.

## Parameters
- `-h`: Show help message and exit
- `-f`: The YAML file to analyze.
- `-r`: The ruleset file to use.
- `-v`: Enable verbose logging

## License
MIT License. See LICENSE.
Copyright (c) ShadowGuard-AI
