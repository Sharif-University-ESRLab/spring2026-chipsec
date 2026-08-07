# Copyright (c) 2026, CHIPSEC Custom Module for Sharif University IoT Lab
# Module to passively scan for Lenovo Secure Boot bypass variables (CVE-2021-3971 to CVE-2022-3432)

from chipsec.module_common import *
from chipsec.hal.uefi import UEFI

class check_backdoor_vars(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.name = "UEFI Secure Boot Backdoor Variable Scanner"
        self.description = "Passively checks NVRAM for variables associated with CVE-2021-3971, 3972, 3430, 3431, 3432"
        self.config_required = False
        self._uefi = None

    def is_supported(self):
        return True

    def run(self, module_argv):
        self.logger.log_information("Starting passive compliance scan for Secure Boot vulnerabilities...")
        self._uefi = UEFI(self.cs)

        # Pull the variables dictionary using CHIPSEC HAL
        vars_dict = self._uefi.list_EFI_variables()

        if vars_dict is None:
            self.logger.log_error("Could not read EFI variables from runtime.")
            self.logger.log_warning("Ensure you are running with root privileges and efi/efivars is mounted.")
            return ModuleResult.ERROR

        vulnerabilities_found = 0
        LENOVO_GUID = "c083cef7-50ad-464f-90e0-d8227f954f51" # Standard Lenovo Backdoor Namespace GUID

        # Iterate through detected variables
        for var_name, var_instances in vars_dict.items():
            for instance in var_instances:
                # Structure of instance: (offset, buf, hdr, data, guid, attr)
                _, _, _, data, guid, _ = instance

                # 1. Check CVE-2021-3971 (CE!)
                if var_name == "CE!" and guid.lower() == LENOVO_GUID:
                    self.logger.log_error("CRITICAL: Found CVE-2021-3971 Indicator (CE! variable exists)!")
                    vulnerabilities_found += 1

                # 2. Check CVE-2021-3972 (ChgBootSecureBootDisable or ChgBootChangeLegacy)
                if var_name in ["ChgBootSecureBootDisable", "ChgBootChangeLegacy"] and guid.lower() == LENOVO_GUID:
                    self.logger.log_error(f"CRITICAL: Found CVE-2021-3972 Indicator ({var_name} variable exists)!")
                    vulnerabilities_found += 1

                # 3. Check CVE-2022-3430 (L05WSBD setup variable)
                if var_name == "L05WSBD":
                    # Checking if the Action field or data state implies modification (typically looking for non-default byte configurations)
                    self.logger.log_warning("WARNING: Found L05WSBD variable (Associated with CVE-2022-3430). Manual check required.")
                    vulnerabilities_found += 1

                # 4. Check CVE-2022-3431 (BootOrderSecureBootDisable)
                if var_name in ["BootOrderSecureBootDisable", "BootOrderDualBootMode"]:
                    self.logger.log_error(f"CRITICAL: Found CVE-2022-3431 Indicator ({var_name} variable exists)!")
                    vulnerabilities_found += 1

                # 5. Check CVE-2022-3432 (L05SecBootSmm equals 0)
                if var_name == "L05SecBootSmm":
                    if data and data[0] == 0:
                        self.logger.log_error("CRITICAL: Found CVE-2022-3432 Indicator (L05SecBootSmm is set to 0/Disabled)!")
                        vulnerabilities_found += 1

        # Final Evaluation
        if vulnerabilities_found > 0:
            self.logger.log_error(f"Scan complete. Found {vulnerabilities_found} vulnerability markers.")
            return ModuleResult.FAILED
        else:
            self.logger.log_good("No known firmware backdoor variables found in NVRAM. System looks clean!")
            return ModuleResult.PASSED