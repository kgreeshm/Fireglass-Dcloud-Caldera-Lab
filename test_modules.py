#!/usr/bin/env python3
"""
Test script for the modular Caldera Lab automation

This script verifies that all modules can be imported and initialized properly.
"""

import sys
import os

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from file_policy import FilePolicyManager
        print("✅ file_policy.py - Import successful")
    except ImportError as e:
        print(f"❌ file_policy.py - Import failed: {e}")
        return False
    
    try:
        from intrusion_policy import IntrusionPolicyManager
        print("✅ intrusion_policy.py - Import successful")
    except ImportError as e:
        print(f"❌ intrusion_policy.py - Import failed: {e}")
        return False
    
    try:
        from access_policy import AccessPolicyManager
        print("✅ access_policy.py - Import successful")
    except ImportError as e:
        print(f"❌ access_policy.py - Import failed: {e}")
        return False
    
    return True

def test_initialization():
    """Test that all managers can be initialized"""
    print("\nTesting manager initialization...")
    
    # Mock configuration
    fmc_host = "https://test.example.com"
    api_token = "test-token"
    domain_uuid = "test-uuid"
    
    try:
        from file_policy import FilePolicyManager
        file_manager = FilePolicyManager(fmc_host, api_token, domain_uuid)
        print("✅ FilePolicyManager - Initialization successful")
    except Exception as e:
        print(f"❌ FilePolicyManager - Initialization failed: {e}")
        return False
    
    try:
        from intrusion_policy import IntrusionPolicyManager
        intrusion_manager = IntrusionPolicyManager(fmc_host, api_token, domain_uuid)
        print("✅ IntrusionPolicyManager - Initialization successful")
    except Exception as e:
        print(f"❌ IntrusionPolicyManager - Initialization failed: {e}")
        return False
    
    try:
        from access_policy import AccessPolicyManager
        access_manager = AccessPolicyManager(fmc_host, api_token, domain_uuid)
        print("✅ AccessPolicyManager - Initialization successful")
    except Exception as e:
        print(f"❌ AccessPolicyManager - Initialization failed: {e}")
        return False
    
    return True

def main():
    """Main test function"""
    print("=" * 60)
    print("Caldera Lab Automation - Module Testing")
    print("=" * 60)
    
    # Test imports
    if not test_imports():
        print("\n❌ Module import tests failed!")
        return 1
    
    # Test initialization
    if not test_initialization():
        print("\n❌ Manager initialization tests failed!")
        return 1
    
    print("\n✅ All tests passed! Modular automation is ready.")
    print("\nTo run individual modules:")
    print("  python file_policy.py")
    print("  python intrusion_policy.py")
    print("  python access_policy.py")
    print("\nTo run full automation:")
    print("  python caldera_lab.py")
    
    return 0

if __name__ == "__main__":
    exit(main())
