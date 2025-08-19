#!/usr/bin/env python3
"""
Caldera Lab Automation - Main Orchestrator

This script coordinates the three policy modules:
1. File Policy (file_policy.py) - Malware detection and file blocking
2. Intrusion Policy (intrusion_policy.py) - SnortML and rule 411:1
3. Access Control Policy (access_policy.py) - URL/app blocking and inspection

Usage: python caldera_lab.py
"""

import requests
import json
import time
import sys
import os
import logging
from urllib3.exceptions import InsecureRequestWarning

# Import our modular policy managers
from file_policy import FilePolicyManager
from intrusion_policy import IntrusionPolicyManager
from access_policy import AccessPolicyManager

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Simple logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class CalderaLabOrchestrator:
    """Main orchestrator for Caldera Lab automation"""
    
    def __init__(self):
        """Initialize with configuration from environment variables"""
        print("=" * 80)
        print("Cisco Secure Firewall Caldera Lab Automation - Modular Version")
        print("=" * 80)
        
        # Load configuration from environment
        self.fmc_host = os.getenv('FMC_HOST', '')
        self.api_token = os.getenv('FMC_API_TOKEN', '')
        self.target_device = os.getenv('TARGET_DEVICE', 'NGFW1')
        self.domain_uuid = "e276abec-e0f2-11e3-8169-6d9ed49b625f"  # Lab domain
        
        # Validate configuration
        if not self.fmc_host or not self.api_token:
            print("\n❌ ERROR: Configuration not found in environment variables!")
            print("   Please run the script using: ./run.sh")
            print("   Make sure to edit the configuration in run.sh first")
            print("   Required: FMC_HOST and FMC_API_TOKEN")
            sys.exit(1)
        
        print(f"\n✓ Using configuration from environment:")
        print(f"  FMC Host: {self.fmc_host}")
        print(f"  Device: {self.target_device} (fixed for lab)")
        print(f"  Token: {self.api_token[:10]}...{self.api_token[-4:] if len(self.api_token) > 14 else ''}")
        
        # Initialize policy managers
        self.file_manager = FilePolicyManager(self.fmc_host, self.api_token, self.domain_uuid)
        self.intrusion_manager = IntrusionPolicyManager(self.fmc_host, self.api_token, self.domain_uuid)
        self.access_manager = AccessPolicyManager(self.fmc_host, self.api_token, self.domain_uuid)
        
        # Track policy IDs
        self.policy_ids = {}
    
    def run_automation(self):
        """Run the complete Caldera lab automation"""
        logger.info("\n🚀 Starting Caldera Lab Automation...")
        
        start_time = time.time()
        
        try:
            # Phase 1: Create File Policy
            print("\n" + "="*50)
            print("PHASE 1: FILE POLICY")
            print("="*50)
            
            file_policy_id = self.file_manager.create_file_policy()
            if file_policy_id:
                self.policy_ids['file'] = file_policy_id
                logger.info(f"✅ File Policy created: {file_policy_id}")
            else:
                logger.warning("⚠️ File Policy creation had issues")
            
            # Phase 2: Create Intrusion Policy
            print("\n" + "="*50)
            print("PHASE 2: INTRUSION POLICY")
            print("="*50)
            
            intrusion_policy_id = self.intrusion_manager.create_intrusion_policy()
            if intrusion_policy_id:
                self.policy_ids['intrusion'] = intrusion_policy_id
                logger.info(f"✅ Intrusion Policy created: {intrusion_policy_id}")
            else:
                logger.warning("⚠️ Intrusion Policy creation had issues")
            
            # Phase 3: Configure Access Control Policy
            print("\n" + "="*50)
            print("PHASE 3: ACCESS CONTROL POLICY")
            print("="*50)
            
            access_policy_id = self.access_manager.configure_access_policy(
                intrusion_policy_id=self.policy_ids.get('intrusion'),
                file_policy_id=self.policy_ids.get('file')
            )
            if access_policy_id:
                self.policy_ids['access'] = access_policy_id
                logger.info(f"✅ Access Control Policy configured: {access_policy_id}")
            else:
                logger.warning("⚠️ Access Control Policy configuration had issues")
            
            # Summary
            self._print_summary(time.time() - start_time)
            
            return len(self.policy_ids) > 0
            
        except KeyboardInterrupt:
            logger.info("\n\n⏹️ Automation stopped by user")
            return False
        except Exception as e:
            logger.error(f"\n❌ Automation failed: {e}")
            return False
    
    def _print_summary(self, elapsed_time):
        """Print automation summary"""
        print("\n" + "="*80)
        print("CALDERA LAB AUTOMATION SUMMARY")
        print("="*80)
        
        print(f"\n⏱️  Total time: {elapsed_time:.1f} seconds")
        print(f"📊 Policies configured: {len(self.policy_ids)}/3")
        
        if 'file' in self.policy_ids:
            print(f"✅ File Policy: {self.policy_ids['file']}")
            print("   - File type blocking (REG, TORRENT, PST)")
            print("   - Malware detection (Spero + Dynamic + Local)")
            print("   - Archive inspection enabled")
        
        if 'intrusion' in self.policy_ids:
            print(f"✅ Intrusion Policy: {self.policy_ids['intrusion']}")
            print("   - SnortML policy with Balanced Security base")
            print("   - Rule 411:1 configured for ML detection")
            print("   - Prevention mode with inline drop")
        
        if 'access' in self.policy_ids:
            print(f"✅ Access Control Policy: {self.policy_ids['access']}")
            print("   - Security Intelligence (malicious IPs/URLs)")
            print("   - URL blocking rules (Adult, Malware, etc.)")
            print("   - Application blocking (high risk, remote desktop)")
            print("   - Inspect All rule with security policies")
        
        # Next steps
        print(f"\n📝 Next Steps:")
        if len(self.policy_ids) == 3:
            print("   1. ✅ All security policies configured!")
            print("   2. 📝 Manually configure DNS Policy in CDO web interface")
            print("   3. 🚀 Deploy policies to NGFW1")
            print("   4. 🧪 Run Caldera assessment from WKST1")
        else:
            print("   1. ⚠️ Review any policy creation warnings above")
            print("   2. 🔧 Use individual policy modules for troubleshooting:")
            print("      - python file_policy.py")
            print("      - python intrusion_policy.py") 
            print("      - python access_policy.py")
        
        print(f"\n🎯 Lab Objective: Achieve 100% threat blocking posture!")


def main():
    """Main function"""
    try:
        orchestrator = CalderaLabOrchestrator()
        success = orchestrator.run_automation()
        
        if success:
            print("\n🎉 Automation completed successfully!")
            return 0
        else:
            print("\n⚠️ Automation completed with warnings - check logs above")
            return 1
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
