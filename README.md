# threat-YamlVulnChecker
A command-line tool that parses YAML files for common security misconfigurations (e.g., exposed keys, default passwords) based on a configurable ruleset. - Focused on Automates the creation and analysis of threat models from configuration files and simple descriptions.  Allows users to define system components, data flows, and potential threats, and then automatically generates attack graphs and prioritizes risks based on probability and impact. Uses YAML for system definition and leverages graph theory libraries for attack path analysis.

## Install
`git clone https://github.com/ShadowStrikeHQ/threat-yamlvulnchecker`

## Usage
`./threat-yamlvulnchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-f`: The YAML file to analyze.
- `-r`: The ruleset file to use.
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
