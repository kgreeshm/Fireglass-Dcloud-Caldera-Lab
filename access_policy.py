#!/usr/bin/env python3
"""
Access Control Policy Automation for Caldera Lab

This module handles:
- Finding existing NGFW1 Firewall Policy
- Configuring Security Intelligence
- Adding URL blocking rules
- Adding application blocking rules  
- Adding inspect all rules
- Advanced settings configuration
"""

import requests
import json
import logging
import os
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class AccessPolicyManager:
    """Manages Access Control Policy configuration for Caldera Lab"""
    
    def __init__(self, fmc_host, api_token, domain_uuid):
        self.fmc_host = fmc_host
        self.api_token = api_token
        self.domain_uuid = domain_uuid
        self.base_url = f"{fmc_host}/api/fmc_config/v1"
        
        # Setup API client
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {api_token}'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False
        
        self.policies = {}
    
    def configure_access_policy(self, intrusion_policy_id=None, file_policy_id=None):
        """Configure NGFW1 Firewall Policy - must exist"""
        logger.info("=" * 60)
        logger.info("CONFIGURING ACCESS CONTROL POLICY")
        logger.info("=" * 60)
        
        # Try multiple access policy endpoints for CDO
        access_endpoints = [
            f"{self.fmc_host}/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies",
            f"{self.fmc_host}/fmc/api/fmc_config/v1/domain/{self.domain_uuid}/policy/accesspolicies"
        ]
        
        policy_id = None
        working_endpoint = None
        
        # Find NGFW1 Firewall Policy (exact name required)
        for endpoint in access_endpoints:
            try:
                logger.info(f"Trying access policy endpoint: {endpoint}")
                response = self.session.get(endpoint)
                logger.info(f"Access policy list response: {response.status_code}")
                
                if response.status_code == 200:
                    policies = response.json()
                    working_endpoint = endpoint
                    
                    # Look for exact name: NGFW1 Firewall Policy
                    for policy in policies.get('items', []):
                        if policy.get('name', '').strip() == 'NGFW1 Firewall Policy':
                            policy_id = policy['id']
                            logger.info(f"✓ Found required Access Policy: {policy['name']} (ID: {policy_id})")
                            break
                    break
                    
            except Exception as e:
                logger.warning(f"Error with {endpoint}: {e}")
                continue
        
        if not policy_id:
            logger.error("❌ Access Control Policy 'NGFW1 Firewall Policy' not found!")
            logger.error("❌ Required policy name: 'NGFW1 Firewall Policy'")
            logger.error("Please ensure the policy exists before running automation")
            return False
        
        self.policies['access'] = policy_id
        
        # Store security policy IDs for rules
        if intrusion_policy_id:
            self.policies['intrusion'] = intrusion_policy_id
        if file_policy_id:
            self.policies['file'] = file_policy_id
        
        # Configure comprehensive access control per lab guide
        success = True
        success &= self._configure_security_intelligence(working_endpoint, policy_id)
        success &= self._configure_access_rules(working_endpoint, policy_id)
        success &= self._configure_advanced_settings(working_endpoint, policy_id)
        
        if success:
            logger.info("✓ Access Control Policy 'NGFW1 Firewall Policy' comprehensively configured")
            return policy_id
        else:
            logger.warning("⚠️ Access Control Policy 'NGFW1 Firewall Policy' partially configured")
            return policy_id  # Still return ID as basic config worked
    
    def _configure_security_intelligence(self, endpoint, policy_id):
        """Configure Security Intelligence to block malicious IPs and URLs"""
        try:
            logger.info("Configuring Security Intelligence...")
            
            # Get current policy to update security intelligence
            policy_response = self.session.get(f"{endpoint}/{policy_id}")
            if policy_response.status_code != 200:
                logger.warning("Could not get current access policy for Security Intelligence")
                return False
            
            policy_data = policy_response.json()
            
            # Configure Security Intelligence per lab guide
            policy_data['securityIntelligence'] = {
                "blockMaliciousIPs": True,
                "blockMaliciousURLs": True,
                "logConnections": True
            }
            
            # Update policy with Security Intelligence
            update_response = self.session.put(f"{endpoint}/{policy_id}", json=policy_data)
            if update_response.status_code in [200, 201]:
                logger.info("✓ Security Intelligence configured (malicious IPs/URLs blocked)")
                return True
            else:
                logger.warning(f"Security Intelligence update failed: {update_response.status_code}")
                return False
                
        except Exception as e:
            logger.warning(f"Security Intelligence configuration error: {e}")
            return False
    
    def _configure_access_rules(self, endpoint, policy_id):
        """Configure the three access control rules exactly per lab guide with event viewer logging"""
        try:
            logger.info("Configuring Access Control Rules...")
            
            # Get URL categories first
            url_categories = self._get_url_categories(endpoint)
            
            # Rule 1: Block Unwanted URLs
            logger.info("Adding 'Block Unwanted URLs' rule...")
            url_rule = {
                "name": "Block Unwanted URLs",
                "action": "BLOCK",
                "enabled": True,
                "type": "AccessRule",
                "logBegin": True,
                "sendEventsToFMC": True,  # Event viewer logging
                "urls": {
                    "urlCategories": []
                }
            }
            
            # Add URL categories required by lab guide
            required_categories = [
                "Adult", "Botnets", "Filter Avoidance", "Gambling", "Hacking",
                "Illegal Activities", "Illegal Drugs", "Malicious Sites", 
                "Malware Sites", "Pornography", "Terrorism and Violent Extremism"
            ]
            
            for cat_name in required_categories:
                if cat_name in url_categories:
                    url_rule["urls"]["urlCategories"].append({
                        "name": cat_name,
                        "id": url_categories[cat_name],
                        "type": "URLCategory"
                    })
            
            # Add "Computers and Internet" with untrusted reputation (1)
            if "Computers and Internet" in url_categories:
                url_rule["urls"]["urlCategoriesWithReputation"] = [{
                    "category": {
                        "name": "Computers and Internet",
                        "id": url_categories["Computers and Internet"],
                        "type": "URLCategory"
                    },
                    "reputation": 1  # Untrusted
                }]
            
            rule1_response = self.session.post(f"{endpoint}/{policy_id}/accessrules", json=url_rule)
            if rule1_response.status_code == 201:
                logger.info("✓ 'Block Unwanted URLs' rule added with event logging")
            else:
                logger.warning(f"URL blocking rule failed: {rule1_response.status_code} - {rule1_response.text}")
            
            # Rule 2: Block Unwanted Applications  
            logger.info("Adding 'Block Unwanted Applications' rule...")
            app_rule = {
                "name": "Block Unwanted Applications",
                "action": "BLOCK_RESET",
                "enabled": True,
                "type": "AccessRule",
                "logBegin": True,
                "sendEventsToFMC": True,  # Event viewer logging
                "applications": {
                    "applications": []  # Will be populated with actual application objects
                }
            }
            
            # Get application filters for lab requirements
            app_filters = self._get_application_filters(endpoint)
            
            # Add applications based on lab guide requirements
            for app_name in ["Remote Desktop", "TeamViewer", "VNC"]:
                if app_name in app_filters:
                    app_rule["applications"]["applications"].append({
                        "name": app_name,
                        "id": app_filters[app_name],
                        "type": "Application"
                    })
            
            rule2_response = self.session.post(f"{endpoint}/{policy_id}/accessrules", json=app_rule)
            if rule2_response.status_code == 201:
                logger.info("✓ 'Block Unwanted Applications' rule added with event logging")
            else:
                logger.warning(f"Application blocking rule failed: {rule2_response.status_code} - {rule2_response.text}")
            
            # Rule 3: Inspect All (Allow with inspection)
            logger.info("Adding 'Inspect All' rule...")
            inspect_rule = {
                "name": "Inspect All",
                "action": "ALLOW",
                "enabled": True,
                "type": "AccessRule",
                "logEnd": True,
                "sendEventsToFMC": True  # Event viewer logging (no logFiles without file policy)
            }
            
            # Add security policies if available
            if 'intrusion' in self.policies:
                inspect_rule['intrusionPolicy'] = {
                    "id": self.policies['intrusion'],
                    "type": "IntrusionPolicy"
                }
            
            if 'file' in self.policies:
                inspect_rule['filePolicy'] = {
                    "id": self.policies['file'],
                    "type": "FilePolicy"
                }
                # Only enable file logging if file policy is attached
                inspect_rule['logFiles'] = True
            
            rule3_response = self.session.post(f"{endpoint}/{policy_id}/accessrules", json=inspect_rule)
            if rule3_response.status_code == 201:
                logger.info("✓ 'Inspect All' rule added with security policies and event logging")
            else:
                logger.warning(f"Inspect rule failed: {rule3_response.status_code} - {rule3_response.text}")
            
            return True
            
        except Exception as e:
            logger.warning(f"Access rules configuration failed: {e}")
            return False
    
    def _get_url_categories(self, endpoint):
        """Get available URL categories"""
        try:
            # Try the URL categories endpoint
            url_cat_endpoint = f"{endpoint.replace('/policy/accesspolicies', '/object/urlcategories')}"
            response = self.session.get(url_cat_endpoint)
            
            if response.status_code == 200:
                categories = {}
                data = response.json()
                for item in data.get('items', []):
                    categories[item['name']] = item['id']
                logger.info(f"Found {len(categories)} URL categories")
                return categories
            else:
                logger.warning(f"Failed to get URL categories: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.warning(f"Error getting URL categories: {e}")
            return {}
    
    def _get_application_filters(self, endpoint):
        """Get available application filters"""
        try:
            # Try the applications endpoint
            app_endpoint = f"{endpoint.replace('/policy/accesspolicies', '/object/applications')}"
            response = self.session.get(app_endpoint)
            
            if response.status_code == 200:
                applications = {}
                data = response.json()
                for item in data.get('items', []):
                    applications[item['name']] = item['id']
                logger.info(f"Found {len(applications)} applications")
                return applications
            else:
                logger.warning(f"Failed to get applications: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.warning(f"Error getting applications: {e}")
            return {}
    
    def _configure_advanced_settings(self, endpoint, policy_id):
        """Configure advanced access policy settings per lab guide"""
        try:
            logger.info("Configuring Advanced Settings...")
            
            # Get current policy to update advanced settings
            policy_response = self.session.get(f"{endpoint}/{policy_id}")
            if policy_response.status_code != 200:
                logger.warning("Could not get current access policy for advanced settings")
                return False
            
            policy_data = policy_response.json()
            
            # Configure advanced settings per lab guide
            policy_data.update({
                "earlyApplication": True,           # Enable early application detection
                "urlReputation": True,             # Enable URL reputation
                "dnsReputation": True,             # Enable DNS reputation  
                "logConnections": True,            # Log connection events
                "logViolations": True              # Log policy violations
            })
            
            # Update policy with advanced settings
            update_response = self.session.put(f"{endpoint}/{policy_id}", json=policy_data)
            if update_response.status_code in [200, 201]:
                logger.info("✓ Advanced Settings configured (early detection, reputation)")
                return True
            else:
                logger.warning(f"Advanced settings update failed: {update_response.status_code}")
                return False
                
        except Exception as e:
            logger.warning(f"Advanced settings configuration error: {e}")
            return False


if __name__ == "__main__":
    # Test the access policy manager standalone
    import os
    
    # Load configuration from environment
    fmc_host = os.getenv('FMC_HOST', '')
    api_token = os.getenv('FMC_API_TOKEN', '') 
    domain_uuid = "e276abec-e0f2-11e3-8169-6d9ed49b625f"  # Lab domain
    
    if not fmc_host or not api_token:
        print("❌ Please set FMC_HOST and FMC_API_TOKEN environment variables")
        print("   Run: source inputs.sh")
        exit(1)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Create and run access policy manager
    manager = AccessPolicyManager(fmc_host, api_token, domain_uuid)
    success = manager.configure_access_policy()
    
    if success:
        print(f"\n✅ Access Policy configured successfully! Policy ID: {success}")
    else:
        print("\n❌ Access Policy configuration failed!")
