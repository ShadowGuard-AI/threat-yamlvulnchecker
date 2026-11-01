#!/usr/bin/env python3

import argparse
import logging
import yaml
import os
import sys
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ABSENT = object()

def mask_value(v):
    if v is None:
        return "None (masked)"
    s = str(v)
    digest = hashlib.sha256(s.encode()).hexdigest()[:8]
    return f"*** (len={len(s)}, sha256:{digest})"




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
        self.rule_errors = 0
        self.skipped_absent = 0
        self._yaml_loaded = False
        self._rules_loaded = False

    def load_yaml(self):
        """
        Loads the YAML data from the specified file.
        Handles file not found and YAML parsing errors.
        """
        try:
            with open(self.yaml_file, 'r') as f:
                self.yaml_data = yaml.safe_load(f)
                self._yaml_loaded = True
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
                self._rules_loaded = True
            logging.info(f"Successfully loaded ruleset file: {self.ruleset_file}")
        except FileNotFoundError:
            logging.error(f"Ruleset file not found: {self.ruleset_file}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing ruleset file: {self.ruleset_file} - {e}")
            raise

    def check_rules(self):
        if not self._yaml_loaded:
            logging.error("YAML data not loaded.  Call load_yaml() first.")
            raise ValueError("YAML data not loaded")
        if self.yaml_data is None:
            logging.error("YAML file was empty or produced no data.")
            raise ValueError("YAML file was empty or produced no data")
        if not self._rules_loaded:
            logging.error("Ruleset not loaded. Call load_ruleset() first.")
            raise ValueError("Ruleset not loaded")
        if not self.rules:
            logging.error("Ruleset was empty or produced no data.")
            raise ValueError("Ruleset was empty or produced no data")
        self.vulnerabilities = []
        self.rule_errors = 0
        self.skipped_absent = 0
        for rule in self.rules:
            name = rule.get("name")
            description = rule.get("description")
            path = rule.get("path")
            check_type = rule.get("type", "equality")
            value = rule.get("value")
            severity = rule.get("severity", "medium")
            try:
                extracted_value = self._extract_value(self.yaml_data, path)
                if extracted_value is ABSENT:
                    expects_present = bool(rule.get("required") or rule.get("expect_present") or rule.get("treat_absence_as_finding") or check_type in ("missing", "absent", "exists"))
                    if expects_present or check_type in ("missing", "absent"):
                        self.vulnerabilities.append({
                            "name": name, "description": description, "path": path,
                            "value": value, "actual_value": "<absent>", "severity": severity})
                        logging.warning(f"Vulnerability found: {name} at path {path} (path absent)")
                    else:
                        self.skipped_absent += 1
                        logging.info(f"Rule {name}: path {path} absent, not evaluated.")
                    continue
                if check_type == "equality":
                    matched = extracted_value == value
                elif check_type == "contains":
                    matched = str(value) in str(extracted_value)
                elif check_type in ("missing", "absent"):
                    matched = False
                elif check_type == "exists":
                    matched = False
                else:
                    logging.error(f"Invalid check type: {check_type}")
                    self.rule_errors += 1
                    continue
                if matched:
                    self.vulnerabilities.append({
                        "name": name, "description": description, "path": path,
                        "value": value, "actual_value": extracted_value, "severity": severity})
                    logging.warning(f"Vulnerability found: {name} at path {path}")
            except Exception as e:
                self.rule_errors += 1
                logging.error(f"Error checking rule {name}: {e}")

    def _extract_value(self, data, path):
        """
        Helper function to extract a value from the YAML data based on a path (dot notation).
        """
        try:
            # Splitting the path on dots means a key that itself contains a dot cannot be reached.
            # Annotation style keys in real YAML are exactly that shape.
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
                        return ABSENT
                    except IndexError:
                        return ABSENT
                else:
                    return ABSENT  # Path not found
            return current
        except Exception:
            return ABSENT

    def report_vulnerabilities(self):
        if self.rule_errors:
            print(f"Rule errors: {self.rule_errors} rule(s) could not be evaluated.")
        if self.skipped_absent:
            print(f"Rules not evaluated (path absent): {self.skipped_absent}")
        if self.vulnerabilities:
            print("Vulnerabilities found:")
            for vuln in self.vulnerabilities:
                print(f"  - Name: {vuln['name']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Path: {vuln['path']}")
                print(f"    Expected Value: {mask_value(vuln['value'])}")
                print(f"    Actual Value: {mask_value(vuln['actual_value'])}")
                print(f"    Severity: {vuln['severity']}")
                print("-" * 20)
        elif not self.rule_errors:
            print("No vulnerabilities found.")
        else:
            print("No clean result: some rules could not be evaluated.")

    def run(self):
        try:
            self.load_yaml()
            self.load_ruleset()
            self.check_rules()
            self.report_vulnerabilities()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return 1
        if self.rule_errors:
            return 1
        if self.vulnerabilities:
            return 1
        return 0


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
        sys.exit(checker.run())
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()