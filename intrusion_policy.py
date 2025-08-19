#!/usr/bin/env python3
"""
Intrusion Policy Automation for Caldera Lab

This module handles:
- Creating SnortML intrusion policy
- Setting base policy to "Balanced Security and Connectivity"
- Configuring rule 411:1 (SnortML machine learning detection)
- Setting prevention mode with inline drop
"""

import requests
import json
import logging
import os
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class IntrusionPolicyManager:
    """Manages Intrusion Policy configuration for Caldera Lab"""
    
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
    
    def create_intrusion_policy(self):
        """Create SnortML intrusion policy exactly per lab guide steps"""
        logger.info("=" * 60)
        logger.info("CREATING INTRUSION POLICY")
        logger.info("=" * 60)
        
        # Step 1: Navigate to Policies > Intrusion (find working endpoint)
        intrusion_endpoints = [
            f"{self.fmc_host}/api/fmc_config/v1/domain/{self.domain_uuid}/policy/intrusionpolicies",
            f"{self.fmc_host}/fmc/api/fmc_config/v1/domain/{self.domain_uuid}/policy/intrusionpolicies"
        ]
        
        working_endpoint = None
        base_policy_id = None
        
        # Find base policy and working endpoint
        for endpoint in intrusion_endpoints:
            try:
                logger.info(f"Trying intrusion policy endpoint: {endpoint}")
                response = self.session.get(endpoint)
                logger.info(f"Intrusion policy list response: {response.status_code}")
                
                if response.status_code == 200:
                    policies = response.json()
                    working_endpoint = endpoint
                    
                    # Look for base policy: "Balanced Security and Connectivity"
                    for policy in policies.get('items', []):
                        if 'Balanced Security and Connectivity' in policy.get('name', ''):
                            base_policy_id = policy['id']
                            logger.info(f"✓ Found base policy: {policy['name']} (ID: {base_policy_id})")
                            break
                    break
                    
            except Exception as e:
                logger.warning(f"Error with {endpoint}: {e}")
                continue
        
        if not working_endpoint:
            logger.error("❌ Could not find working intrusion policy endpoint")
            return False
        
        if not base_policy_id:
            logger.error("❌ Could not find 'Balanced Security and Connectivity' base policy")
            return False
        
        # Check if SnortML policy already exists - throw error if it does
        existing_policy = self._find_existing_policy(working_endpoint, "SnortML")
        if existing_policy:
            logger.error("❌ ERROR: SnortML policy already exists!")
            logger.error(f"   Existing policy ID: {existing_policy}")
            logger.error("   Please delete the existing policy first or use a different name")
            return False
        
        # Step 2: Click on Create Policy - Configure the following details:
        logger.info("Creating new intrusion policy with lab guide specifications:")
        logger.info("  Name: SnortML")
        logger.info("  Inspection Mode: Prevention") 
        logger.info("  Base Policy: Balanced Security and Connectivity")
        
        policy_data = {
            "name": "SnortML",
            "type": "IntrusionPolicy",
            "basePolicy": {
                "id": base_policy_id,
                "type": "IntrusionPolicy"
            },
            "inspectionMode": "PREVENTION"
        }
        
        # Create the policy
        response = self.session.post(working_endpoint, json=policy_data)
        
        if response.status_code == 201:
            policy = response.json()
            policy_id = policy['id']
            logger.info(f"✓ 'SnortML' intrusion policy created successfully!")
            logger.info(f"✓ Policy ID: {policy_id}")
            logger.info(f"✓ Base Policy: Balanced Security and Connectivity")
            logger.info(f"✓ Inspection Mode: Prevention")
            
            # Step 3: Configure Rule 411:1 (Snort 3 Version > Rule Overrides)
            success = self._configure_rule_411_1(working_endpoint, policy_id)
            return policy_id if success else False
            
        else:
            logger.error(f"❌ Failed to create SnortML policy: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False
    
    def _find_existing_policy(self, endpoint, policy_name):
        """Check if policy already exists"""
        try:
            response = self.session.get(endpoint)
            if response.status_code == 200:
                policies = response.json()
                for policy in policies.get('items', []):
                    if policy.get('name', '').strip() == policy_name:
                        return policy['id']
            return None
        except:
            return None
    
    def _configure_rule_411_1(self, endpoint, policy_id):
        """Configure rule 411:1 exactly per lab guide steps:
        1. Click Snort 3 Version for the SnortML policy
        2. Click Rule Overrides
        3. Click All Rules, apply GID=411 filter
        4. Change Rule Action for rule 411:1 from Disable (Default) to Block
        """
        try:
            logger.info("Configuring Rule 411:1 per lab guide steps...")
            logger.info("  Step: Click Snort 3 Version > Rule Overrides")
            logger.info("  Step: All Rules > GID=411 filter")
            logger.info("  Step: Change Rule 411:1 from Disable to Block")
            
            # Find rule 411:1 using correct CDO endpoints
            rules_endpoint = f"{endpoint}/{policy_id}/intrusionrules"
            rule_id = self._find_rule_411_1(rules_endpoint)
            
            if rule_id:
                # Get current rule to check state
                rule_url = f"{rules_endpoint}/{rule_id}"
                rule_response = self.session.get(rule_url)
                
                if rule_response.status_code == 200:
                    rule_data = rule_response.json()
                    current_state = rule_data.get('defaultState', 'Unknown')
                    override_state = rule_data.get('overrideState', 'None')
                    
                    logger.info(f"Rule 411:1 found - Current: {current_state}, Override: {override_state}")
                    
                    # Lab Guide Step: Change Rule Action from Disable (Default) to Block
                    update_payload = {
                        "type": "IntrusionRule",
                        "id": rule_id,
                        "gid": 411,
                        "sid": 1,
                        "overrideState": "BLOCK"  # Change from Disable to Block
                    }
                    
                    # Apply the rule override (acknowledging 7.6.0+ requirement)
                    update_response = self.session.put(rule_url, json=update_payload)
                    
                    if update_response.status_code in [200, 201]:
                        updated_rule = update_response.json()
                        new_override = updated_rule.get('overrideState', 'None')
                        logger.info(f"✓ Rule 411:1 successfully updated!")
                        logger.info(f"✓ Action changed from 'Disable (Default)' to '{new_override}'")
                        logger.info("✓ Override applied (7.6.0+ acknowledged)")
                        logger.info("✓ Machine learning detection now enabled for SQL injection attacks")
                        return True
                    else:
                        logger.error(f"❌ Rule override failed: {update_response.status_code}")
                        logger.error(f"Response: {update_response.text}")
                        return False
                else:
                    logger.error(f"❌ Failed to get rule details: {rule_response.status_code}")
                    return False
            else:
                logger.error("❌ Rule 411:1 not found in policy")
                logger.error("   This may indicate the policy was not created with Snort 3 engine")
                return False
                
        except Exception as e:
            logger.error(f"❌ Rule 411:1 configuration error: {e}")
            return False

    def _find_rule_411_1(self, rules_endpoint):
        """Find rule 411:1 in the intrusion policy"""
        try:
            # Search through intrusion rules (CDO may have thousands)
            offset = 0
            limit = 1000
            
            while offset < 15000:  # Reasonable search limit
                paginated_url = f"{rules_endpoint}?offset={offset}&limit={limit}"
                response = self.session.get(paginated_url)
                
                if response.status_code != 200:
                    break
                    
                data = response.json()
                rules = data.get('items', [])
                
                # Search for rule 411:1
                for rule in rules:
                    rule_name = rule.get('name', '')
                    if '411:1' in rule_name:
                        logger.info(f"Found rule 411:1: {rule['id']}")
                        return rule['id']
                
                # Check if there are more pages
                if len(rules) < limit:
                    break
                    
                offset += limit
                
                # Don't search forever
                if offset > 10000:
                    break
            
            logger.info("Rule 411:1 not found in first 10k rules - may be auto-managed by CDO")
            return None
            
        except Exception as e:
            logger.warning(f"Error searching for rule 411:1: {e}")
            return None


if __name__ == "__main__":
    # Test the intrusion policy manager standalone
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
    
    # Create and run intrusion policy manager
    manager = IntrusionPolicyManager(fmc_host, api_token, domain_uuid)
    success = manager.create_intrusion_policy()
    
    if success:
        print(f"\n✅ Intrusion Policy created successfully! Policy ID: {success}")
    else:
        print("\n❌ Intrusion Policy creation failed!")
