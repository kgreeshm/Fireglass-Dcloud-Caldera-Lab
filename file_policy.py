#!/usr/bin/env python3
"""
File Policy Automation for Caldera Lab

This module handles:
- Creating File Policy with exact lab name
- Adding file type blocking rules (REG, TORRENT, PST)
- Adding malware detection rules (Spero + Dynamic + Local analysis)
- Configuring advanced archive inspection settings
"""

import requests
import json
import logging
import os
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


class FilePolicyManager:
    """Manages File Policy configuration for Caldera Lab"""
    
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
    
    def create_file_policy(self):
        """Create File Policy exactly per lab guide"""
        logger.info("=" * 60)
        logger.info("CREATING FILE POLICY")
        logger.info("=" * 60)
        
        # Try multiple file policy endpoints for CDO
        file_endpoints = [
            f"{self.fmc_host}/api/fmc_config/v1/domain/{self.domain_uuid}/policy/filepolicies",
            f"{self.fmc_host}/fmc/api/fmc_config/v1/domain/{self.domain_uuid}/policy/filepolicies"
        ]
        
        working_endpoint = None
        
        # Find working endpoint
        for endpoint in file_endpoints:
            try:
                logger.info(f"Trying file policy endpoint: {endpoint}")
                response = self.session.get(endpoint)
                logger.info(f"File policy list response: {response.status_code}")
                
                if response.status_code == 200:
                    working_endpoint = endpoint
                    break
                    
            except Exception as e:
                logger.warning(f"Error with {endpoint}: {e}")
                continue
        
        if not working_endpoint:
            logger.error("❌ Could not find working file policy endpoint")
            return False
        
        # Check if File Policy already exists
        existing_policy = self._find_existing_policy(working_endpoint, "File Policy")
        if existing_policy:
            logger.info(f"✓ File Policy already exists (ID: {existing_policy})")
            # Configure the existing policy
            success = self._configure_file_policy_rules(working_endpoint, existing_policy)
            return existing_policy if success else False
        
        # Create File Policy per lab guide (exact name required)
        logger.info("Creating 'File Policy'...")
        
        policy_data = {
            "name": "File Policy",  # Exact name from lab guide
            "type": "FilePolicy",
            "description": "Caldera Lab - File Analysis and Blocking Policy"
        }
        
        # Create the policy
        response = self.session.post(working_endpoint, json=policy_data)
        
        if response.status_code == 201:
            policy = response.json()
            policy_id = policy['id']
            logger.info(f"✓ 'File Policy' created successfully!")
            logger.info(f"✓ Policy ID: {policy_id}")
            
            # Configure file policy rules
            success = self._configure_file_policy_rules(working_endpoint, policy_id)
            return policy_id if success else False
            
        else:
            logger.error(f"❌ Failed to create File Policy: {response.status_code}")
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
    
    def _configure_file_policy_rules(self, endpoint, policy_id):
        """Configure file policy rules exactly per lab guide"""
        try:
            logger.info("Configuring File Policy rules...")
            
            # Get file types for blocking rules
            file_types = self._get_file_types(endpoint)
            
            # Rule 1: Block specific file types per lab guide
            logger.info("Adding file type blocking rule...")
            
            # Required file types to block: REG, TORRENT, PST
            required_types = ["REG", "TORRENT", "PST"]
            block_types = []
            
            for file_type in required_types:
                if file_type in file_types:
                    block_types.append({
                        "name": file_type,
                        "id": file_types[file_type],
                        "type": "FileType"
                    })
            
            if block_types:
                block_rule = {
                    "name": "Block File Types",
                    "type": "FileRule",
                    "action": "BLOCK",
                    "enabled": True,
                    "fileTypes": block_types,
                    "direction": "ANY",
                    "applicationProtocol": "ANY"
                }
                
                rule1_response = self.session.post(f"{endpoint}/{policy_id}/filerules", json=block_rule)
                if rule1_response.status_code == 201:
                    logger.info(f"✓ File type blocking rule added: {required_types}")
                else:
                    logger.warning(f"File type blocking rule failed: {rule1_response.status_code}")
            
            # Rule 2: Malware analysis per lab guide  
            logger.info("Adding malware detection rule...")
            
            malware_rule = {
                "name": "Malware Detection",
                "type": "FileRule", 
                "action": "BLOCK_MALWARE",
                "enabled": True,
                "fileTypes": [{"name": "Any", "type": "FileType"}],  # All file types
                "direction": "ANY",
                "applicationProtocol": "ANY",
                "speroAnalysis": True,        # Spero analysis
                "dynamicAnalysis": True,      # Dynamic analysis 
                "localMalwareAnalysis": True  # Local malware analysis
            }
            
            rule2_response = self.session.post(f"{endpoint}/{policy_id}/filerules", json=malware_rule)
            if rule2_response.status_code == 201:
                logger.info("✓ Malware detection rule added (Spero + Dynamic + Local)")
            else:
                logger.warning(f"Malware detection rule failed: {rule2_response.status_code}")
            
            # Configure advanced settings
            success = self._configure_advanced_settings(endpoint, policy_id)
            
            return True
            
        except Exception as e:
            logger.warning(f"File policy rules configuration failed: {e}")
            return False
    
    def _get_file_types(self, endpoint):
        """Get available file types"""
        try:
            # Try the file types endpoint
            file_types_endpoint = f"{endpoint.replace('/policy/filepolicies', '/object/filetypes')}"
            response = self.session.get(file_types_endpoint)
            
            if response.status_code == 200:
                types = {}
                data = response.json()
                for item in data.get('items', []):
                    types[item['name']] = item['id']
                logger.info(f"Found {len(types)} file types")
                return types
            else:
                logger.warning(f"Failed to get file types: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.warning(f"Error getting file types: {e}")
            return {}
    
    def _configure_advanced_settings(self, endpoint, policy_id):
        """Configure advanced file policy settings per lab guide"""
        try:
            logger.info("Configuring advanced file settings...")
            
            # Get current policy to update advanced settings
            policy_response = self.session.get(f"{endpoint}/{policy_id}")
            if policy_response.status_code != 200:
                logger.warning("Could not get current file policy for advanced settings")
                return False
            
            policy_data = policy_response.json()
            
            # Configure advanced settings per lab guide
            policy_data.update({
                "archiveInspection": True,              # Enable archive inspection
                "maxArchiveDepth": 3,                   # Archive depth limit
                "customDetectionList": True,            # Custom detection
                "cleanList": True,                      # Clean list for known good files
                "threatScore": "MODERATE_AND_HIGHER"    # Threat score threshold
            })
            
            # Update policy with advanced settings
            update_response = self.session.put(f"{endpoint}/{policy_id}", json=policy_data)
            if update_response.status_code in [200, 201]:
                logger.info("✓ Advanced file settings configured (archive inspection enabled)")
                return True
            else:
                logger.warning(f"Advanced file settings update failed: {update_response.status_code}")
                return False
                
        except Exception as e:
            logger.warning(f"Advanced file settings configuration error: {e}")
            return False


if __name__ == "__main__":
    # Test the file policy manager standalone
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
    
    # Create and run file policy manager
    manager = FilePolicyManager(fmc_host, api_token, domain_uuid)
    success = manager.create_file_policy()
    
    if success:
        print(f"\n✅ File Policy created successfully! Policy ID: {success}")
    else:
        print("\n❌ File Policy creation failed!")
