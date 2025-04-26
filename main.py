#!/usr/bin/env python3

import argparse
import logging
import yaml
import os
import sys
from networkx import DiGraph, all_simple_paths
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file (if present)
load_dotenv()


class YamlVulnChecker:
    """
    A class to represent the YAML vulnerability checker.
    """

    def __init__(self, yaml_file, ruleset_file):
        """
        Initializes the YamlVulnChecker with the YAML file to analyze and the ruleset file.
        """
        self.yaml_file = yaml_file
        self.ruleset_file = ruleset_file
        self.yaml_data = None
        self.rules = None
        self.vulnerabilities = []

    def load_yaml(self):
        """
        Loads the YAML data from the specified file.
        Handles file not found and YAML parsing errors.
        """
        try:
            with open(self.yaml_file, 'r') as f:
                self.yaml_data = yaml.safe_load(f)
            logging.info(f"Successfully loaded YAML file: {self.yaml_file}")
        except FileNotFoundError:
            logging.error(f"YAML file not found: {self.yaml_file}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML file: {self.yaml_file} - {e}")
            raise

    def load_ruleset(self):
        """
        Loads the ruleset from the specified file.
        Handles file not found and YAML parsing errors.
        """
        try:
            with open(self.ruleset_file, 'r') as f:
                self.rules = yaml.safe_load(f)
            logging.info(f"Successfully loaded ruleset file: {self.ruleset_file}")
        except FileNotFoundError:
            logging.error(f"Ruleset file not found: {self.ruleset_file}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing ruleset file: {self.ruleset_file} - {e}")
            raise

    def check_rules(self):
        """
        Applies the ruleset to the loaded YAML data and identifies potential vulnerabilities.
        """
        if not self.yaml_data:
            logging.error("YAML data not loaded.  Call load_yaml() first.")
            raise ValueError("YAML data not loaded")

        if not self.rules:
            logging.error("Ruleset not loaded. Call load_ruleset() first.")
            raise ValueError("Ruleset not loaded")

        self.vulnerabilities = []
        for rule in self.rules:
            name = rule.get("name")
            description = rule.get("description")
            path = rule.get("path")
            check_type = rule.get("type", "equality")  # Default to equality if not specified
            value = rule.get("value")
            severity = rule.get("severity", "medium") # Default to medium severity

            try:
                extracted_value = self._extract_value(self.yaml_data, path)

                if extracted_value is None:
                    logging.debug(f"Path {path} not found in YAML data.")
                    continue

                if check_type == "equality":
                    if extracted_value == value:
                        self.vulnerabilities.append({
                            "name": name,
                            "description": description,
                            "path": path,
                            "value": value,
                            "actual_value": extracted_value,
                            "severity": severity
                        })
                        logging.warning(f"Vulnerability found: {name} at path {path}")
                elif check_type == "contains":
                    if value in str(extracted_value): # Convert to string for broader matching
                        self.vulnerabilities.append({
                            "name": name,
                            "description": description,
                            "path": path,
                            "value": value,
                            "actual_value": extracted_value,
                            "severity": severity
                        })
                        logging.warning(f"Vulnerability found: {name} at path {path}")
                else:
                    logging.error(f"Invalid check type: {check_type}")

            except Exception as e:
                logging.error(f"Error checking rule {name}: {e}")

    def _extract_value(self, data, path):
        """
        Helper function to extract a value from the YAML data based on a path (dot notation).
        """
        try:
            parts = path.split('.')
            current = data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list):
                    try:
                        index = int(part)
                        current = current[index]
                    except ValueError:
                        return None
                    except IndexError:
                        return None
                else:
                    return None  # Path not found
            return current
        except Exception:
            return None

    def report_vulnerabilities(self):
        """
        Prints a report of the found vulnerabilities.
        """
        if self.vulnerabilities:
            print("Vulnerabilities found:")
            for vuln in self.vulnerabilities:
                print(f"  - Name: {vuln['name']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Path: {vuln['path']}")
                print(f"    Expected Value: {vuln['value']}")
                print(f"    Actual Value: {vuln['actual_value']}")
                print(f"    Severity: {vuln['severity']}")
                print("-" * 20)
        else:
            print("No vulnerabilities found.")

    def run(self):
        """
        Runs the vulnerability check process.
        """
        try:
            self.load_yaml()
            self.load_ruleset()
            self.check_rules()
            self.report_vulnerabilities()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            sys.exit(1)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="YAML Vulnerability Checker")
    parser.add_argument("-f", "--file", dest="yaml_file", required=True, help="The YAML file to analyze.")
    parser.add_argument("-r", "--rules", dest="ruleset_file", required=True, help="The ruleset file to use.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    return parser


def main():
    """
    Main function to execute the YAML vulnerability checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    try:
        checker = YamlVulnChecker(args.yaml_file, args.ruleset_file)
        checker.run()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()