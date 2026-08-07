# Custom CHIPSEC Module

This project develops custom CHIPSEC modules for detecting UEFI and Secure Boot vulnerabilities. It
  begins by configuring CHIPSEC on physical hardware, studying its architecture, inspecting firmware
  and EFI variables, and investigating several Lenovo and OVMF vulnerabilities.

The vulnerabilities inverstigated in this project are CVE-2022-3432 and CVE-2023-48733.
CVE-2022-3432 is a Lenovo UEFI vulnerability in which the L05SecBootSmm EFI variable can be used to
  disable Secure Boot. The project explores a family of backdoor EFI variables including
  CVE-2022-3432 by developing a passive CHIPSEC module (`check_backdoor_vars`) to test and report.
  CVE-2023-48733 is caused by a misconfiguration of EDK II package that results in a bootable EFI
  Shell despite having Secure Boot enabled. A two phase CHIPSEC module (`secureboot_fullshell`) is
  developed to exploit this vulnerability on a simulated Debian enviornment running on OVMF.

## Tools

To run CHIPSEC successfully you will need:
- Linux operating system
- Python 3
- CHIPSEC v1.13.20 (https://github.com/chipsec/chipsec/tree/1.13.20)

To run `secureboot_fullshell` module, you need a simulating environment:
- QEMU
- OVMF (different versions from [debian snapshot](https://snapshot.debian.org/package/edk2/))


## Implementation Details

The implementation of this project is based on the CHIPSEC v1.13.20 source code. Apart from modules
implemented and developed within CHIPSEC itself, all the modules implemented in this project are
located at [chipsec/modules/sut](./Code/chipsec/chipsec/modules/sut/).

The module `check_backdoor_vars.py` will passively scan EFI variables for backdoor variables
specified in the following CVEs: CVE-2021-3971, CVE-2021-3972, CVE-2022-3430, CVE-2022-3431, and
CVE-2022-3432.

The module `secureboot_fullshell.py` has two phases. In the setup phase, it will set EFI Internal
Shell as the next boot option to run a startup shell script. In the check phase, it will check for
EFI mark variable set by the script. This module is expected to run within a simulated environment
that uses OVMF. See [chipsec/CVE-2023-48733/README.md](./Code/chipsec/CVE-2023-48733/README.md) on
how to setup the QEMU environment.

## How to Run

### Run CHIPSEC

Throughout the project, running CHIPSEC has the same procedure whether it is running on a physical
device or in a QEMU environment. Run the following commands inside the CHIPSEC source directory (./Code/chipsec).

#### Machine Owner Key

This step is only required when the operating system is booted with Secure Boot.

Generate and import Machine Owner Key (MOK).

```sh
openssl req -new -x509 -newkey rsa:2048 -keyout mok.priv -outform DER -out mok.der -nodes -days 3650 -subj "/CN=My MOK Key/"
sudo mokutil --import mok.der
```

Reboot the device. In the next boot, UEFI will prompt for importing the MOK. Provide the password
asked by the mokutil. If this step is running on a physical device, please note that you are
responsible to keep the MOK private or remove it when you are done with running CHIPSEC.

#### System Requirements

Please refer to CHIPSEC manual on the system requirements. This is one example for Debian-based distros.

```sh
sudo apt-get install build-essential python3-dev python3 gcc linux-headers-$(uname -r) nasm
```

#### Python Requirements

Setup a Python virtual environment.

```sh
virtualenv3 venv
source ./venv/bin/activate
```

Install Python requirements.

```sh
pip install -r linux_requirements.txt
```

Build the driver.

```sh
python setup.py build_ext -i
```

If a MOK is available, the CHIPSEC driver can be signed using the following command.

```sh
sudo /usr/src/kernels/$(uname -r)/scripts/sign-file sha256 mok.key mok.der chipsec/helper/linux/chipsec.ko
```

#### Run CHIPSEC

Run all CHIPSEC modules.

```sh
sudo $(which python3) chipsec_main.py
```

Run a specific CHIPSEC module.

```sh
sudo $(which python3) chipsec_main.py -m chipsec.modules.sut.check_backdoor_vars
```

### Run Simulated OVMF Environment

To test the second module, a specific test environment is need to test multiple OVMF versions.
In this case, the CHIPSEC will run in a Debian virtual machine within QEMU. Run all the following commands
inside ./Code/chipsec/CVE-2023-48733.

#### Requirements

Download [latest debian net installer](https://www.debian.org/distrib/) to `./disk`.
  You will need to install this in a simulated qemu instance.

Download three EDK II versions.

- [2022.08-1](https://snapshot.debian.org/package/edk2/2022.08-1/): This is the last version with
  the vulnerability. Put this inside `./old-debian`.
- [2022.11-6+deb12u2](https://snapshot.debian.org/package/edk2/2022.11-6%2Bdeb12u2/): This is the
  first fixed version. Put this in `./new-debian`.
- [2026.05-2](https://snapshot.debian.org/package/edk2/2026.05-2/): This is the latest version. Put
  this in `./latest-debian`.

For each package, you only need the `usr/share/edk2/ovmf` subdirectory. Move this so that OVMF files
 can be accessed like `./old-debian/OVMF/OVMF_CODE_4m.secboot.fd`.

Copy one instance of `OVMF_VARS_4M.ms.fd` (from any version) into `./new-debian/my_VARS_4M.ms.fd`.
This file contains the NVRAM content with Microsoft Secure Boot signatures, which allows debian's
`shim` bootloader to be able to execute under Secure Boot without MOK.

Create a QEMU disk file at `./disk/debian.qcow2`. This disk will be used to install debian on it.


#### Install Debian

Run the following command to start a QEMU process.

```sh
./my_qemu_efi.sh install-iso
```

Follow the installation wizard. After installing Debian, you will be able to boot into it via the following command:

```sh
./my_qemu_efi.sh vm-latest
```

You can specify `vm-old` or `vm-new` to change the OVMF version.

#### Run

Run `secureboot_fullshell` module in each of the three EDK II versions. You should expect:

- The module fails in `old` in the check phase because EFI Shell was bootable.
- The module passes in `new`  in the check phase because EFI Shell was not booted.
- The module passes in `latest` in the setup phase because EFI Shell is not a boot entry.

## Results

The `check_backdoor_vars` module reports a failure if one of the backdoor variables is present on the
system.

![Result of `check_backdoor_vars`](./Miscellaneous/images/result-backdoor.png)

The `secureboot_fullshell` module fails on the vulnerable version of OVMF (called `old`).

![Result of `secureboot_fullshell`](./Miscellaneous/images/result-old.png)

The `secureboot_fullshell` module passes on the first fixed version of OVMF (called `new`).

![Result of `secureboot_fullshell`](./Miscellaneous/images/result-new.png)

The `secureboot_fullshell` module passes on the latest version of OVMF (called `latest`).

![Result of `secureboot_fullshell`](./Miscellaneous/images/result-latest.png)


## Related Links

 - [EDK II](https://github.com/tianocore/edk2)
 - [CHIPSEC v1.13.20](https://github.com/chipsec/chipsec/tree/1.13.20)


## Authors

- [@ParsaAlizadeh](https://github.com/ParsaAlizadeh)
- [@AliAvd](https://github.com/AliAvd)

