#!/bin/bash

#######################################################################
# Caldera Lab Configuration File
# 
# Edit the values below with your specific lab configuration:
# - Replace the FMC_HOST with your cdFMC URL
# - Replace the FMC_API_TOKEN with your API token
# - Replace the SCC_HOST with your SCC URL (for deletions)
# - Keep TARGET_DEVICE as "NGFW1" for the lab
#######################################################################

# ====================================
# USER CONFIGURATION - EDIT THESE VALUES
# ====================================

# Your cdFMC URL (replace with your actual URL)
export FMC_HOST="https://cisco-kadadhic.app.apj.cdo.cisco.com"

# Your API Token (replace with your actual token)
export FMC_API_TOKEN=""

# Your SCC URL for deletion operations (replace with your actual SCC URL)
export SCC_HOST="https://apj.manage.security.cisco.com"

# Target device name (keep as NGFW1 for Caldera lab)
export TARGET_DEVICE="NGFW1"

# ====================================
# END USER CONFIGURATION
# ====================================
