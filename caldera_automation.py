#!/usr/bin/env python3
"""
Minimal Cisco Secure Firewall Caldera Lab Automation

This script automates the complete Caldera lab with minimal user input:
1. Authenticates with cdFMC using API token
2. Creates all required security policies  
3. Deploys policies to target device
4. Shows completion status

Usage: python caldera_automation.py
"""

import requests
import json
import time
import sys
import os
import logging
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Simple logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class CalderaLabAutomation:
    """Minimal Caldera Lab Automation"""
    
    def __init__(self):
        """Initialize with user input or saved config"""
        print("=" * 60)
        print("Cisco Secure Firewall Caldera Lab Automation")
        print("=" * 60)
        
        # Check for saved configuration
        config_file = ".env"
        saved_config = self.load_saved_config(config_file)
        
        if saved_config:
            print(f"\nFound saved configuration in {config_file}")
            use_saved = input("Use saved configuration? [Y/n]: ").strip().lower()
            if use_saved in ('', 'y', 'yes'):
                self.fmc_host = saved_config.get('FMC_HOST', '')
                self.api_token = saved_config.get('FMC_API_TOKEN', '')
                self.target_device = saved_config.get('TARGET_DEVICE', 'NGFW1')
                print(f"Using saved config - Host: {self.fmc_host}, Device: {self.target_device}")
            else:
                self.get_user_input()
        else:
            self.get_user_input()
            
        # Offer to save configuration
        if not saved_config or not os.path.exists(config_file):
            save_config = input("\nSave configuration for future use? [y/N]: ").strip().lower()
            if save_config in ('y', 'yes'):
                self.save_config(config_file)
        
        # Setup API client
        self.setup_api_client()
        
        self.domain_uuid = None
        self.device_id = None
        self.policies = {}
    
    def get_user_input(self):
        """Get configuration from user input"""
        # Get minimal required inputs
        self.fmc_host = input("Enter cdFMC URL (e.g., https://tenant.us.cdo.cisco.com): ").strip()
        self.api_token = input("Enter API Token: ").strip()
        
        # Optional inputs with defaults
        self.target_device = input("Target device name [NGFW1]: ").strip() or "NGFW1"
    
    def load_saved_config(self, config_file):
        """Load configuration from file"""
        if not os.path.exists(config_file):
            return None
            
        config = {}
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
            return config
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
            return None
    
    def save_config(self, config_file):
        """Save configuration to file"""
        try:
            with open(config_file, 'w') as f:
                f.write("# Caldera Lab Configuration\n")
                f.write("# Generated automatically - you can edit these values\n\n")
                f.write(f"FMC_HOST={self.fmc_host}\n")
                f.write(f"FMC_API_TOKEN={self.api_token}\n")
                f.write(f"TARGET_DEVICE={self.target_device}\n")
            print(f"✓ Configuration saved to {config_file}")
        except Exception as e:
            logger.warning(f"Could not save config: {e}")
    
    def setup_api_client(self):
        """Setup API client with current configuration"""
        self.base_url = f"{self.fmc_host}/api/fmc_config/v1"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-auth-access-token': self.api_token
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False
        
    def authenticate(self):
        """Test authentication and get domain"""
        logger.info("Testing authentication...")
        
        try:
            response = self.session.get(f"{self.base_url}/domain")
            if response.status_code == 200:
                domains = response.json()
                if 'items' in domains and domains['items']:
                    self.domain_uuid = domains['items'][0]['uuid']
                    logger.info(f"✓ Authentication successful - Domain: {self.domain_uuid}")
                    return True
            
            logger.error(f"Authentication failed: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def get_device(self):
        """Find target device"""
        logger.info(f"Finding device: {self.target_device}")
        
        try:
            response = self.session.get(f"{self.base_url}/domain/{self.domain_uuid}/devices/devicerecords")
            if response.status_code == 200:
                devices = response.json()
                for device in devices.get('items', []):
                    if self.target_device.lower() in device.get('name', '').lower():
                        self.device_id = device['id']
                        logger.info(f"✓ Found device: {device['name']}")
                        return True
            
            logger.error(f"Device '{self.target_device}' not found")
            return False
            
        except Exception as e:
            logger.error(f"Device lookup error: {e}")
            return False
    
    def create_dns_policy(self):
        """Create DNS policy"""
        logger.info("Creating DNS Policy...")
        
        policy_data = {
            "name": "Caldera_DNS_Policy",
            "description": "DNS policy for Caldera lab",
            "type": "DNSPolicy"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/domain/{self.domain_uuid}/policy/dnspolicies", 
                json=policy_data
            )
            
            if response.status_code == 201:
                policy = response.json()
                self.policies['dns'] = policy['id']
                logger.info("✓ DNS Policy created")
                
                # Add blocking rule
                rule_data = {
                    "name": "Block_Malicious_DNS",
                    "action": "DOMAIN_NOT_FOUND",
                    "enabled": True,
                    "type": "DNSRule"
                }
                
                self.session.post(
                    f"{self.base_url}/domain/{self.domain_uuid}/policy/dnspolicies/{policy['id']}/blockdnsrules",
                    json=rule_data
                )
                
                return True
            else:
                logger.warning("DNS Policy creation failed")
                return False
                
        except Exception as e:
            logger.warning(f"DNS Policy error: {e}")
            return False
    
    def create_file_policy(self):
        """Create file policy"""
        logger.info("Creating File Policy...")
        
        policy_data = {
            "name": "Caldera_File_Policy",
            "description": "File policy for Caldera lab",
            "type": "FilePolicy"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/domain/{self.domain_uuid}/policy/filepolicies",
                json=policy_data
            )
            
            if response.status_code == 201:
                policy = response.json()
                self.policies['file'] = policy['id']
                logger.info("✓ File Policy created")
                
                # Add malware blocking rule
                rule_data = {
                    "name": "Block_Malware",
                    "action": "BLOCK_MALWARE",
                    "enabled": True,
                    "speroAnalysis": True,
                    "dynamicAnalysis": True,
                    "localMalwareAnalysis": True,
                    "type": "FileRule"
                }
                
                self.session.post(
                    f"{self.base_url}/domain/{self.domain_uuid}/policy/filepolicies/{policy['id']}/filerules",
                    json=rule_data
                )
                
                return True
            else:
                logger.warning("File Policy creation failed")
                return False
                
        except Exception as e:
            logger.warning(f"File Policy error: {e}")
            return False
    
    def create_intrusion_policy(self):
        """Create intrusion policy with SnortML"""
        logger.info("Creating Intrusion Policy...")
        
        # Find base policy
        base_policy_id = None
        try:
            response = self.session.get(f"{self.base_url}/domain/{self.domain_uuid}/policy/intrusionpolicies")
            if response.status_code == 200:
                policies = response.json()
                for policy in policies.get('items', []):
                    if "balanced" in policy.get('name', '').lower():
                        base_policy_id = policy['id']
                        break
        except:
            pass
        
        policy_data = {
            "name": "Caldera_SnortML_Policy",
            "description": "Intrusion policy with SnortML for Caldera lab",
            "inspectionMode": "PREVENTION",
            "type": "IntrusionPolicy"
        }
        
        if base_policy_id:
            policy_data["basePolicyId"] = base_policy_id
        
        try:
            response = self.session.post(
                f"{self.base_url}/domain/{self.domain_uuid}/policy/intrusionpolicies",
                json=policy_data
            )
            
            if response.status_code == 201:
                policy = response.json()
                self.policies['intrusion'] = policy['id']
                logger.info("✓ Intrusion Policy created")
                return True
            else:
                logger.warning("Intrusion Policy creation failed")
                return False
                
        except Exception as e:
            logger.warning(f"Intrusion Policy error: {e}")
            return False
    
    def configure_access_policy(self):
        """Configure access control policy"""
        logger.info("Configuring Access Control Policy...")
        
        # Find existing policy
        policy_id = None
        try:
            response = self.session.get(f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies")
            if response.status_code == 200:
                policies = response.json()
                for policy in policies.get('items', []):
                    if any(keyword in policy.get('name', '').lower() for keyword in ['ngfw', 'firewall', 'access']):
                        policy_id = policy['id']
                        logger.info(f"✓ Found Access Policy: {policy['name']}")
                        break
        except:
            pass
        
        if not policy_id:
            # Create new policy
            policy_data = {
                "name": "Caldera_Access_Policy",
                "type": "AccessPolicy"
            }
            
            try:
                response = self.session.post(
                    f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies",
                    json=policy_data
                )
                
                if response.status_code == 201:
                    policy = response.json()
                    policy_id = policy['id']
                    logger.info("✓ Created new Access Policy")
            except:
                logger.warning("Could not create Access Policy")
                return False
        
        if policy_id:
            self.policies['access'] = policy_id
            
            # Add inspect rule
            rule_data = {
                "name": "Caldera_Inspect_All",
                "action": "ALLOW",
                "enabled": True,
                "type": "AccessRule",
                "logEnd": True
            }
            
            # Add policies if created
            if 'intrusion' in self.policies:
                rule_data['intrusionPolicy'] = {
                    "id": self.policies['intrusion'],
                    "type": "IntrusionPolicy"
                }
            
            if 'file' in self.policies:
                rule_data['filePolicy'] = {
                    "id": self.policies['file'],
                    "type": "FilePolicy"
                }
            
            try:
                self.session.post(
                    f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules",
                    json=rule_data
                )
                logger.info("✓ Added inspection rule")
            except:
                logger.warning("Could not add inspection rule")
            
            return True
        
        return False
    
    def deploy_policies(self):
        """Deploy policies to device"""
        if not self.device_id:
            logger.warning("No device to deploy to")
            return False
            
        logger.info("Deploying policies...")
        
        deployment_data = {
            "type": "DeploymentRequest",
            "version": int(time.time()),
            "forceDeploy": False,
            "ignoreWarning": True,
            "deviceList": [self.device_id]
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/domain/{self.domain_uuid}/deployment/deploymentrequests",
                json=deployment_data
            )
            
            if response.status_code == 202:
                deployment = response.json()
                logger.info(f"✓ Deployment started: {deployment.get('id')}")
                
                # Monitor deployment (simplified)
                for i in range(30):  # Wait up to 5 minutes
                    time.sleep(10)
                    try:
                        status_response = self.session.get(
                            f"{self.base_url}/domain/{self.domain_uuid}/deployment/deploymentrequests/{deployment['id']}"
                        )
                        if status_response.status_code == 200:
                            status = status_response.json()
                            state = status.get('state', 'UNKNOWN')
                            
                            if state == 'DEPLOYED':
                                logger.info("✓ Deployment completed successfully")
                                return True
                            elif state in ['FAILED', 'CANCELLED']:
                                logger.error(f"✗ Deployment failed: {state}")
                                return False
                            
                            logger.info(f"Deployment status: {state}")
                    except:
                        pass
                
                logger.warning("Deployment timeout - may still be in progress")
                return True
            else:
                logger.error("Deployment failed to start")
                return False
                
        except Exception as e:
            logger.error(f"Deployment error: {e}")
            return False
    
    def run(self):
        """Run complete automation"""
        try:
            # Authenticate
            if not self.authenticate():
                print("❌ Authentication failed")
                return False
            
            # Find device
            if not self.get_device():
                print("❌ Device not found")
                return False
            
            print("\n🔧 Creating security policies...")
            
            # Create policies
            dns_ok = self.create_dns_policy()
            file_ok = self.create_file_policy()
            intrusion_ok = self.create_intrusion_policy()
            access_ok = self.configure_access_policy()
            
            # Deploy
            print("\n🚀 Deploying policies...")
            deploy_ok = self.deploy_policies()
            
            # Summary
            print("\n" + "=" * 60)
            print("AUTOMATION SUMMARY")
            print("=" * 60)
            print(f"DNS Policy:       {'✓' if dns_ok else '✗'}")
            print(f"File Policy:      {'✓' if file_ok else '✗'}")
            print(f"Intrusion Policy: {'✓' if intrusion_ok else '✗'}")
            print(f"Access Policy:    {'✓' if access_ok else '✗'}")
            print(f"Deployment:       {'✓' if deploy_ok else '✗'}")
            print("=" * 60)
            
            if deploy_ok and any([dns_ok, file_ok, intrusion_ok, access_ok]):
                print("🎉 Caldera lab automation completed successfully!")
                print("\nNext steps:")
                print("1. Run Caldera assessment from WKST1")
                print("2. Check security events in Security Cloud Control")
                print("3. Verify 100% threat blocking in final assessment")
                return True
            else:
                print("⚠️  Automation completed with some issues")
                return False
                
        except KeyboardInterrupt:
            print("\n❌ Automation interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Automation failed: {e}")
            return False


def main():
    """Main function"""
    automation = CalderaLabAutomation()
    success = automation.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
