# CHIPSEC Custom Module for Sharif University IoT Lab
# Module to check if secureboot is enabled and EFI Shell is bootable, which can be used to bypass
# secureboot. See CVE-2023-48733.
# Requirements:
# - Guest Linux OS running inside QEMU
# - QEMU booting via OVMF
# - `chipsec.ko` signed by MOK
# Expected Behaviour:
# - `ovmf_2022.08-1_all.deb` should FAIL
# - `ovmf_2022.11-6+deb12u2_all.deb` should PASS
# - If secureboot is not enabled, neither FAIL nor PASS

from chipsec.module_common import *
from chipsec.hal.uefi import UEFI, EFI_VAR_NAME_SecureBoot
from chipsec.hal.uefi_common import EFI_VARIABLE_NON_VOLATILE, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS

import re
import subprocess

EFI_GLOBAL_VARIABLE_GUID = '8BE4DF61-93CA-11D2-AA0D-00E098032B8C'
FULLSHELL_GUID = '7C04A583-9E3E-4F1C-AD65-E05268D0B4D1'
SHELLMARK_GUID = 'CC80C59E-7482-11F1-AA45-507B9DBF9094'

STARTUP_NSH_PATH = '/boot/efi/startup.nsh'
SHELLMARK_ATTRS = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS

STARTUP_NSH_CONTENT = f"""\
@echo -off
setvar ShellMark -guid {SHELLMARK_GUID} -nv -bs -rt =0x01
reset
"""

class secureboot_fullshell(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.name = "Secure Boot Full Shell Presence Check"
        self.description = "Checks if Secure Boot is enabled but a UEFI shell (FULLSHELL_GUID) is embedded in firmware, allowing a potential bypass"
        self.config_required = False
        self._uefi = None

    def is_supported(self):
        return True

    def setup_boot_to_shell(self):
        result = subprocess.run(['efibootmgr'], capture_output=True, text=True)
        if result.returncode != 0:
            self.logger.log_error(f"efibootmgr failed: {result.stderr.strip()}")
            return ModuleResult.ERROR

        shell_boot_num = None
        for line in result.stdout.splitlines():
            m = re.match(r'^Boot([0-9A-Fa-f]{4})\*?\s+EFI Internal Shell', line)
            if m:
                shell_boot_num = m.group(1)
                break

        if shell_boot_num is None:
            self.logger.log_good("No 'EFI Internal Shell' boot option found. System is not vulnerable.")
            return ModuleResult.PASSED

        self.logger.log(f"Found EFI Internal Shell boot option: Boot{shell_boot_num}")

        import os
        if os.path.exists(STARTUP_NSH_PATH):
            self.logger.log_error(f"{STARTUP_NSH_PATH} already exists. Remove it before running setup.")
            return ModuleResult.ERROR

        with open(STARTUP_NSH_PATH, 'w') as f:
            f.write(STARTUP_NSH_CONTENT)
        self.logger.log(f"Wrote {STARTUP_NSH_PATH}")

        self._uefi.set_EFI_variable('ShellMark', SHELLMARK_GUID, b'\x00', attrs=SHELLMARK_ATTRS)
        self.logger.log("Set ShellMark EFI variable to 0x00")

        nb_result = subprocess.run(['efibootmgr', '-n', shell_boot_num], capture_output=True, text=True)
        if nb_result.returncode != 0:
            self.logger.log_error(f"efibootmgr -n failed: {nb_result.stderr.strip()}")
            return ModuleResult.ERROR

        self.logger.log(f"Next boot set to Boot{shell_boot_num} (EFI Internal Shell)")
        self.logger.log("Please reboot now. After the system comes back up, run this module without 'setup' to check the result.")
        return ModuleResult.WARNING

    def check_mark(self):
        data = self._uefi.get_EFI_variable(EFI_VAR_NAME_SecureBoot, EFI_GLOBAL_VARIABLE_GUID)
        secureboot_enabled = (data is not None) and (len(data) == 1) and (data[0] == 0x1)

        if not secureboot_enabled:
            self.logger.log_warning("Secure Boot is not enabled. Skipping shell presence check.")
            return ModuleResult.WARNING

        mark = self._uefi.get_EFI_variable('ShellMark', SHELLMARK_GUID)
        if not mark:
            self.logger.log_warning("ShellMark EFI variable not found. Run this module with 'setup' first.")
            return ModuleResult.WARNING

        if mark[0] == 0x00:
            self.logger.log_passed("ShellMark is 0x00: EFI Internal Shell did not run. Secure Boot correctly blocked it.")
            return ModuleResult.PASSED
        else:
            self.logger.log_failed("ShellMark is 0x01: EFI Internal Shell ran despite Secure Boot being enabled! System is VULNERABLE (CVE-2023-48733).")
            return ModuleResult.FAILED

    def run(self, module_argv):
        self._uefi = UEFI(self.cs)

        if len(module_argv) > 0 and module_argv[0] == 'setup':
            return self.setup_boot_to_shell()
        else:
            return self.check_mark()
