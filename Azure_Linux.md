# Azure_Linux.md

=================

   * [Azure Linux](#azure-linux)
      * [Arch Related](#arch-related)
         * [Useful Link](#useful-link)
         * [Hyper-V](#hyper-v)
            * [Abbr](#abbr)
            * [VM Arch](#vm-arch)
            * [Attach disk to VM](#attach-disk-to-vm)
         * [Powershell](#powershell)
         * [VM Deployment](#vm-deployment)
            * [Redeploy](#redeploy)
            * [VM Migration](#vm-migration)
         * [Extension](#extension)
            * [VMAccessForLinux](#vmaccessforlinux)
            * [Use Powershell for the custom script](#use-powershell-for-the-custom-script)
         * [Waagent](#waagent)
            * [Waagent Basic](#waagent-basic)
            * [Waagent Functionality](#waagent-functionality)
         * [LIS](#lis)
            * [Manually install LIS driver](#manually-install-lis-driver)
         * [Logs](#logs)
            * [Serial Logs](#serial-logs)
            * [Snapshot](#snapshot)
            * [Backup](#backup)
      * [Fabric](#fabric)
         * [Install Fabric](#install-fabric)
         * [Fabric parameters](#fabric-parameters)
         * [Fabfile](#fabfile)
            * [Environment definition](#environment-definition)
      * [Storage](#storage)
         * [Basic concept](#basic-concept-1)
            * [Storage Account](#storage-account)
            * [Attach Disk](#attach-disk)
            * [Snapshot](#snapshot-1)
         * [Standard Storage](#standard-storage)
            * [Identify the Disk](#identify-the-disk)
            * [Storage Replication](#storage-replication)
            * [Storage Explorer](#storage-explorer)
         * [Useful Link](#useful-link-1)
         * [Disk Managing](#disk-managing)
         * [Disk URL](#disk-url)
         * [LVM](#lvm)
         * [Azure File Storage](#azure-file-storage)
            * [Limitation of AFS](#limitation-of-afs)
            * [AFS Basic](#afs-basic)
         * [Disk Encryption](#disk-encryption)
            * [Perform Disk Encryption](#perform-disk-encryption)
            * [Install AzureAD on Powershell](#install-azuread-on-powershell)
      * [RestAPI](#restapi)
      * [Network](#network)
            * [Reserved IP](#reserved-ip)
            * [DNS Name Resolution](#dns-name-resolution)
            * [Kernel Null Pointer](#kernel-null-pointer)
            * [Reconfigure SSHD file for Ubuntu](#reconfigure-sshd-file-for-ubuntu)
            * [Firewall](#firewall)
            * [Install xRDP for GUI remote access on Linux](#install-xrdp-for-gui-remote-access-on-linux)
            * [Move a directory onto an external data disk](#move-a-directory-onto-an-external-data-disk)
         * [Harden linux VM](#harden-linux-vm)
            * [Deny IP by IPset](#deny-ip-by-ipset)
            * [Harden SSHD](#harden-sshd)
            * [Add logging in Iptables](#add-logging-in-iptables)
      * [Performance](#performance)
            * [Disk Performance in Linux VM’s](#disk-performance-in-linux-vms)
         * [Ubuntu](#ubuntu)
         * [Suse](#suse)
      * [Kubernetes in Azure](#kubernetes-in-azure)
      * [Support Related](#support-related)
         * [Useful Link](#useful-link-2)
         * [Support Basic](#support-basic)
            * [Azure Gallery Image](#azure-gallery-image)
            * [Labor](#labor)
            * [Survey](#survey)
            * [SR Wait State](#sr-wait-state)
            * [Annual Leave](#annual-leave)
            * [Linux SME working process](#linux-sme-working-process)
         * [Support tools](#support-tools)
            * [Leaving WFM &amp;&amp; msvacation](#leaving-wfm--msvacation)
            * [KB](#kb)
            * [Resource Exploer](#resource-exploer)
            * [MSSolve](#mssolve)
               * [Scope](#scope)
               * [ResouceInstanceID](#resouceinstanceid)



## Arch Related 

### Useful Link

[Azure Arch](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/index)
[Linux Virtual Machine](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/)





### Hyper-V


Hyper-V can use para-virtualization or full-virtualization to create VM. 


#### Abbr

**ARM**: Azure Resource Manager. Pool
**ASM**: Azure Security Manager

#### VM Arch 


1 . Portal 
2 . Powershell

Serial Log is located in the Azure Host.


Refer to https://docs.microsoft.com/en-us/cli/azure/vm#create

```
```


```
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -
yum install nodejs -y
yum install npm -y
npm install -g azure-cli -y
```

Azure Login

```
az login 
```

Set azure account 

```
az account list 
az account set 
```

List the VM sizes available in a given region 

```
azure vm sizes --location <location> 
azure vm sizes --locatoin eastus 
az vm list-sizes -l eastus --output table
```

Enable diagnostics 

```
azure vm enable-diag <resource-group> <vm-name>
```

Deallocate a VM (Stop VM will be charged but deallocate won't charge)

```
azure vm deallocate <resource-group> <vm-name>
```

Add VMAccess extension to a VM

```
```

enable_extension_reset_sshd.json

```
{
}
```

output 

```
{
  "autoUpgradeMinorVersion": true,
  "instanceView": null,
  "location": "westus2",
  "name": "VMAccessForLinux",
  "protectedSettings": null,
  "provisioningState": "Succeeded",
  "resourceGroup": "yingresourcegroup",
  "settings": null,
  "tags": null,
  "typeHandlerVersion": "1.4",
}
```


```
az vm show -g yingresourcegroup -n yingrhel68 -d --output table
```


```
azure config mode arm 
azure config mode asm
```

Reset SSH credentials for a User (Password)

```
az vm access set-linux-user --resource-group myResourceGroup --name myVM \
     --username myUsername --password myPassword
```

Reset SSH credentials for a User (Public Key)

```
az vm access set-linux-user --resource-group myResourceGroup --name myVM \
    --username myUsername --ssh-key-value ~/.ssh/id_rsa.pub
```

Restart VM 

```
az vm restart --resource-group myResourceGroup --name myVM
```

Redeploy 

```
az vm redeploy --resource-group myResourceGroup --name myVM
```

Deallocate 

```
az vm deallocate --resource-group myResourceGroup --name Vm
```

Detach a Datadisk 

```
az vm disk detach -n testimage --vm-name yingrhel73 --resource-group yingresourcegroupasia
```



```
```

#### Attach disk to VM

```
az vm disk attach --vm-name myVM --resource-group myResourceGroupDisk --disk myDataDisk --size-gb 128 --sku Premium_LRS --new 
```

check all the disks

```
```

resize the disk 

```
az disk update --name myDataDisk --resource-group myResourceGroupDisk --size-gb 1023
```


```
```

### Powershell

Login Azure

```
Login-AzureRmAccount
```

Get the VM's Information 

```
 Get-AzureRmVM -ResourceGroupName yingresourcegroup -Name yingrhel68 -debug
```


```
ResourceGroupName  : yingresourcegroup
Id                 : /subscriptions/0f96dbcb-37cf-4c89-94ac-f9672a0ec207/resourceGroups/yingresourcegroup/pro
VmId               : 97b15b47-9896-41b7-bd7e-537863c12057
Name               : yingrhel68
Location           : eastus
DiagnosticsProfile : {BootDiagnostics}
HardwareProfile    : {VmSize}
NetworkProfile     : {NetworkInterfaces}
ProvisioningState  : Succeeded
```

Remove the VM

```
Remove-AzureRmVM -ResourceGroupName "yingresourcegroupasia" -Name "yingrhel68"
```

Stop VM

```
$rgName="yingresourcegroupasia"
$vmName="yingrhel68"
$vm=Get-AzureRmVM -ResourceGroupName $rgName -Name $vmName
Stop-AzureRmVM -ResourceGroupName $rgName -Name $vmName
```

Resize VM

```
update-AzureRmVm -ResourceGroupName $rgName -VM $vm
Start-AzureRmVM -ResourceGroupName $rgName -Name $vmName
```




```
Set-Alias gs \\fsu\shares\wats\scripts\Get-Sub\Get-Sub.ps1
```

Get the informaiton 

```
gs -subscriptionid  b8db94d4-edb3-4a41-a136-1896f9f2f028 -DeploymentId 1e468c9be5c74e01b071b06d70f5a921
```











### VM Deployment




#### Redeploy 

Redeploy option is avaiable only for ARM VMs
For ASM, resize is the option to achieve redeploy

#### VM Migration 

disk2vhd>azcopy


Azure Swap Partitions: https://wiki.ubuntu.com/AzureSwapPartitions


### Extension

For extension Upgrade, you need to uninstall it and re-install it again
Github Link [Extension](https://github.com/Azure/azure-linux-extensions/)

#### VMAccessForLinux

https://docs.microsoft.com/en-us/azure/virtual-machines/linux/extensions-customscript

VMAccessForLinux (automatically installed)
-- Resetting Password
-- Remote reset Access(Reset SSH configuration)


```
```


```json
{
  "fileUris": ["https://raw.githubusercontent.com/neilpeterson/test-extension/master/test.sh"],
}
```


```
az vm extension set --resource-group myResourceGroup --vm-name myVM --name customScript --publisher Microsoft.Azure.Extensions --settings ./script-config.json
```


```
{
  "fileUris": ["<url>"],
}
```


```
{
  "storageAccountName": "<storage-account-name>",
  "storageAccountKey": "<storage-account-key>"
}
```


```
az vm extension set \
  --resource-group exttest \
  --vm-name exttest \
  --name customScript \
  --publisher Microsoft.Azure.Extensions \
```

For V1 - asm 

```
azure config mode asm
```

Uninstalling an extension v1

```
```

For resetting SSH connection 
Refer to https://docs.microsoft.com/en-us/azure/virtual-machines/linux/troubleshoot-ssh-connection


For ASM, if the same command needs to be run more than once, needs to use unique value which can be achieved via timestamp

```
azure config mode asm

```


```
rg=yingresourcegroupasia
vmname=yingrhel68
timestamp=`date +%d-%h-%Y_%H:%M:%S`
```

Uninstall the extension 

```
```

Use fileuri to send a script, it's a most common way 

```
timestamp=`date +%d-%h-%Y_%:%M:%S`
file=recreate_empty
vmname=yourvm
```

#### Use Powershell for the custom script

```
$rg="debian-arm"
$vm="ssdebian8"
```

Sample 2

```
$RGName = 'yingresourcegroupasia'
$VmName = 'yingrhel68'
$Location = 'southeastasia'
 
$ExtensionName = 'customscript'
$Publisher = 'Microsoft.Azure.Extensions'
$Version = '2.0'
 
    "fileUris": ["https://yingstorageaccountus.blob.core.windows.net/sscustomscript/testfile.sh.txt"],
}'
 
Set-AzureRmVMExtension -ResourceGroupName $RGName -VMName $VmName -Location $Location `
  -Name $ExtensionName -Publisher $Publisher `
```





LinuxDiagnostics

VMSnapshot Microsoft Recovery Services 
-- Backup/Recovery Vault/Add your VM/Schedule 

### Waagent



#### Waagent Basic

Source code: https://github.com/Azure/WALinuxAgent/blob/master/bin/waagent2.0
Github of Waagent: https://github.com/Azure/WALinuxAgent
Waagent Release: https://github.com/Azure/WALinuxAgent/releases/
Waagent Guide: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/agent-user-guide

Manually install Agent 

```
cd /tmp
wget https://raw.githubusercontent.com/Azure/WALinuxAgent/WALinuxAgent-2.0.18/waagent
sudo chmod +x waagent 
sudo cp waagent /usr/sbin/waagent 
sudo /usr/sbin/waagent -install-verbose
sudo service waagent restart 
```

#### Waagent Functionality 

**Image Provission**
Deployment of SSH public keys and key pairs 
Setting the host name 
Publishing SSH host key fingerprint to the platform 
Resource Disk Management 
Formatting and mounting the resource disk 
**Networking**
Ensures the stability of the network interface name 
**Kernel**
**Diagnostics**
**VM Extension**
Inject component authored by Microsoft and Partners into Linux VM(IaaS) to enable software and configuration automation 
VM Extension reference implementation on https://github.com/Azure/azure-linux-extensions


### LIS


Modules used in LIS:
hv_netvsc: provides support for a Hyper-V specific( or "synthetic") network adapter. 
hv_utils: provides integrated shutdown, key-value pari data exchange, heartbeat, mouse and live backup.
hv_storvsc: provides support for all storage devices attched to a virtual machine 
hv_vmbus: the fast commnication channel between the server running Hyper-V and virtual Machine 

#### Manually install LIS driver

Download the lis-rpms-4.1.1.tar.gz

```
gunzip lis-rpms-4.1.1.tar.gz
tar -xf lis-rpms-4.1.1.tar
./install.sh
reboot
```




### Logs

waagent logs 

```
/var/log/waagentlog
```

extension.log

```
```

#### Serial Logs 

Kernel parameters are required to generate serial/boot logs are 

```
console=ttyS0 earlyprintk=ttyS0 rootdelay=300
```

**Get the Serial logs from Get-Sub**

#### Snapshot 

https://blogs.technet.microsoft.com/canitpro/2014/12/10/step-by-step-creating-a-vm-snapshot-in-azure/

#### Backup 

https://docs.microsoft.com/en-us/azure/backup/backup-azure-vms



## Fabric

A tool used to run Python function and  ssh to run Shell command. 

### Install Fabric 

Install virtualenv to make a virtual environment to run Fabric

```
pip install virtualenv  --trusted-host pypi.doubanio.com -i http://pypi.doubanio.com/simple
```

activated virtual environment 

```
virtualenv venv
source venv/bin/activate
# deactivate the virtual environment 
deactivate 
```

check the package 

```
pip freeze 
```

install fabric 

```
pip install fabric --trusted-host pypi.doubanio.com -i http://pypi.doubanio.com/simple
```

check Fabric version 

```
fab --version
```

### Fabric parameters 


```
-l: list the dedefined function task 
-f: define the fab entrance file, by default it's fabfile.py
-g: define the default gateway 
-u: user account 
-p: password
```

Single VM operation

```
fab -H root@192.168.48.130:22 -- 'hostname'
fab -u root -p nsadm -H 192.168.48.130 -- 'netstat -natup'
```

### Fabfile

#### Environment definition 


```
env.hosts = ["192.168.48.130", "192.168.48.131"]
```

env.user: define user account 

```
env.user = "root"
```

env.port: define port

```
env.port = 22 
```

env.password: define password

```
env.password = "1"
```

env.passwords: define multiple hosts, IP address, port and password

```
env.passwords = {
  "root@192.168.48.130:22": "nsadm",
  "root@192.168.48.131:22": "redhat"
}
```

env.gateway: define Gateway 

```
env.gateway = "192.168.48.130"
```

env.roledefs: define role group 

```
env.roledefs = {
  "webservers": ["192.168.48.130", "192.168.48.131"],
  "dbservers": ["192.168.48.140", "192.168.48.141"]
}
```


```
#coding:utf8
from fabric.api import *
env.hosts = ["192.168.48.130"]
env.user = "root"
env.password = "nsadm"
env.port = 22 
@task
def show():
    run("hostname")
    run("netstat -natup |grep 22")
    run("ls /root/")
@task
def catmem():
    run("free -m")
@task 
def run_all():
    execute(show)
    execute(catmem)
if __name__=="__main__":
    execute(run_all)
```

check function of fabfile

```
fab -f helloworld.py -l
Available commands:
    catmem
    show
```

Decorator @task can use some fucntion like run() which is used to run some realy command. And execute() is used to run some fucntion.

Decorator @roles("rolename") is used to declare which role will be used for the task




## Storage 

### Basic concept 

#### Storage Account 

Storage Account: Disk URL
Blob: Disk Name



Standard Storage [HDD-Hard Disk Drive]
1 Storage Account = 20,000/500 = 40 Disk (Soft limit)
Premium Storage [SSD-Solid State Drive]

#### Attach Disk

[Attach Disk](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/attach-disk-portal)

#### Snapshot

Snapshot only be available for managed disk

### Standard Storage

1 . Blobs: 
​	a. Block Blob(Unstructured date) eg: MP3, JPEG (Maxium 500GB)
3 . Queues: Message Queue 
4 . File: NFS Shares/Samba Shares
Premium Storage only support Blob

#### Identify the Disk 

https://<StorageAccount>.blob.core.windows.net/vhds/<osdiskname>            		--->  Page Blob
https://<StorageAccount>.blob.core.windows.net/vhds/rhel123132.MP3          		--->  Block Blob
https://linuxSA.file.core.windows.net/rampup/rhel212313123.txt              			--->  File Share
https://storageaccountname.storagetype.DNS/container/os|datadiskname.vhd 	


**Format: Am1prdstr03a**
Am: data center name 1: the first datacentor 
prd: production 
str: standard storage 
03: cluster name 
**by2prdstp02**
stp: premier 
**sg3prdapp02b**
app: Fabric

#### Storage Replication 

LRS ( Locally Redundant Storage) physcial region redundancy three copies on differenct data cluster
​	Spread across different cluster 
ZRS ( Zone Redundant Storage) Zone is logical concept  3 copies 
​	Spread across different datacentor but in same region 
​	More reliable than ZRS thereby costlier
​	Most reliable and costliest 
​	15 mins Delay for Data Sync 
RA-GRS ( Read-Access Geo Redundant Storage) simliar to GRS, read either primary or secondary 
​	Very similar to GRS
​	Read either primary or secondary 
​	Economic to GRS

#### Storage Explorer 

- release some disk 

Link to download [http://storageexplorer.com/](http://storageexplorer.com/) 

Storage Account name and key to share the VHD

```
Account: nestedvmst

```




1 Rack = 44(50) Nodes
​		= 20 * 50 = 1000 Nodes(Practical)
Difference = 1000 - 880 = 120 Nodes(Backup, compute etc)


### Useful Link

[Premier Storage](https://docs.microsoft.com/en-us/azure/storage/storage-premium-storage )
[Quotas and Limits](https://docs.microsoft.com/en-in/azure/azure-subscription-service-limits)
https://github.com/Azure/azure-quickstart-templates/tree/master/201-vm-specialized-vhd


### Disk Managing 


For Managed disk, change from portal directly
https://blogs.msdn.microsoft.com/madan/2016/09/28/resize-azure-resource-manager-arm-vm-os-data-disk-using-azure-portal/

For umanaged disk , change it by poweshell
https://docs.microsoft.com/en-us/azure/virtual-machines/windows/expand-os-disk




### Disk URL

Storage Account Name: azurecharlie2216.blob.core.windows.net



https://blogs.msdn.microsoft.com/mast/2013/12/06/understanding-the-temporary-drive-on-windows-azure-virtual-machines/

### LVM

After reboot or attach the data disk to the virtual machine. Device mapper needs to be rescaned 

```
vgscan --mknodes
vgchange -ay
lvscan
```




### Azure File Storage

[How to use AFS](https://docs.microsoft.com/en-us/azure/storage/storage-how-to-use-files-linux)
[Whatis Azure File storage?](http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/#what-is-azure-file-storage)
[UsePowerShell to create a file share](http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/#use-powershell-to-create-a-file-share)
[Mountthe share from an Azure virtual machine running Windows](http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/#mount-the-share-from-an-azure-virtual-machine-running-windows)
[Mountthe share from an Azure virtual machine running Linux](http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/#mount-the-share-from-an-azure-virtual-machine-running-linux)
[http://blogs.msdn.com/b/windowsazurestorage/archive/2014/05/12/introducing-microsoft-azure-file-service.aspx](http://blogs.msdn.com/b/windowsazurestorage/archive/2014/05/12/introducing-microsoft-azure-file-service.aspx)
[https://msdn.microsoft.com/en-us/library/azure/dn790517.aspx](https://msdn.microsoft.com/en-us/library/azure/dn790517.aspx)
[http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/](http://azure.microsoft.com/en-us/documentation/articles/storage-dotnet-how-to-use-files/)

#### Limitation of AFS

From Storage Account to share the AFS
Samba Version of 2.0+ supported
It is not recommended to use AFS for application and DB
AFS is not avaiable for all Azure Endorsed Images 

####  AFS Basic 


```
sudo mount -t cifs //<storage-account-name>.file.core.windows.net/<share-name> ./mymountpoint -o vers=3.0,username=<storage-account-name>,password=<storage-account-key>,dir_mode=0777,file_mode=0777,serverino
```

credentials=/etc/.smbcreds
Modify /etc/fstab

```
sudo bash -c 'echo "//<storage-account-name>.file.core.windows.net/<share-name> /mymountpoint cifs vers=3.0,username=<storage-account-name>,password=<storage-account-key>,dir_mode=0777,file_mode=0777,serverino" >> /etc/fstab'
```

### Disk Encryption 

https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption

When you need encryption to be enabled on a running VM in Azure, Azure Disk Encryption generates and writes the encryption keys to your key valut. Managing encryption keys in your key vault requires Azure AD authenticaiton. 

#### Perform Disk Encryption 

https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json


#### Install AzureAD on Powershell

Install AzureAD

```
Install-Module -Name AzureAD
Install-Module -Name AzureADPreview
```





Sar Average kps to calculate the Bandwidth

```
sar -n DEV -f sa08
```

https://toolstud.io/data/bandwidth.php?compare=network&speed=46895.74&speed_unit=KB%2Fs


nethogs
iptraf
iftop

## RestAPI

https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines


## Network



#### Reserved IP 

[Reserved IP](https://docs.microsoft.com/en-in/azure/virtual-network/virtual-networks-reserved-public-ip)

#### DNS Name Resolution  

https://docs.microsoft.com/en-us/azure/virtual-machines/linux/azure-dns




```
az network vnet create \
--resource-group yingresourcegroupasia \
--address-prefix 192.168.0.0/16 \
--subnet-name mySubnetFrontEnd \
--subnet-prefix 192.168.1.0/24 \
--name yingVnetfortest
```


```
az network vnet subnet create \
--resource-group yingresourcegroupasia \
--vnet-name yingVnetfortest \
--name mySubnetBackEnd \
--address-prefix 192.168.2.0/24
```


```
az network nsg create \
--resource-group yingresourcegroupasia \
--name myNetworkSecurityGroup
```


```
 az network nic create \
--resource-group yingresourcegroupasia \
--name yingtestNic1 \
--vnet-name yingVnetfortest \
--subnet mySubnetFrontEnd \
--network-security-group myNetworkSecurityGroup 
```


```
az network nic create \
--resource-group yingresourcegroupasia \
--name yingtestNic2 \
--vnet-name yingVnetfortest \
--subnet mySubnetBackEnd \
--network-security-group myNetworkSecurityGroup
```

Deploy Virtual Machine with nics 

```
az vm create \
--resource-group yingresourcegroupasia \
--name virtualmachinefortest \
--size Basic_A0 \
--admin-username yinsun \
--storage-sku Standard_LRS \
--nics yingtestNic1 yingtestNic2 \
--public-ip-address-allocation dynamic \
--os-disk-name virtualmachinefortest \
--nsg-rule SSH 
```


```
az network public-ip create -g yingresourcegroupasia -n publicipfortestvm
```







```
mount -o nouuid /dev/sdc2 /rescue
```

For Debian 8.2+, Ubuntu 16.04+, SUSE 12 SP4+

```
mount /dev/sdc1 /rescue

#mount proc /rescue/proc -t proc
cd /rescue
mount -t proc proc proc/
mount -t sysfs sys sys/
mount -o bind /dev dev/
mount -o bind /dev/pts dev/pts
# For Debian, you also need to mount run
mount -o bind /run run/
```

Debian regenerate SSH keys

```
sudo dpkg-reconfigure openssh-server
```

umount the folder and exit chroot 

```
exit 
cd /
umount /rescue/proc/
umount /rescue/sys/
umount /rescue/dev/pts
umount /rescue/dev/umount /mountpoint/run/
# For Debian and Ubuntu also umount run
umount /rescue/run
umount /rescue
```


Error logs 

```
```



```
echo 0 >/proc/sys/kernel/hung_task_timeout_secs
```


```
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
```



```
ls -lrt /dev/disk/by-uuid/
```

Rebuild initramfs 

```
dracut /tempmount/boot/initramfs-2.6.32-504.12.2.el6.x86_64.img 2.6.32-504.12.2.el6.x86_64
```


```
cp /boot/vmlinuz-2.6.32-504.12.2.el6.x86_64 /tempmount/boot/
```

Update the grub.conf

```
       root (hd0,0)
       initrd /boot/initramfs-2.6.32-504.12.2.el6.x86_64.img
```

#### Kernel Null Pointer

Error log shows

```
BUG: unable to handle kernel NULL pointer dereference at 0000000000000008
```



RH wont support their kernel if LIS is manually installed.

```
send host-name = gethostname();
default interface-mtu 1350;
supercede interface-mtu 1350;
```


```
```

#### Reconfigure SSHD file for Ubuntu


```
-rw-------.   1 root root 125811 Jul 17  2015 moduli
-rw-r--r--.   1 root root   2047 Jul 17  2015 ssh_config
-rw-------.   1 root root   3880 Mar  2  2016 sshd_config
```


```
#!/bin/bash
cd /etc/ssh/
rm -rf ssh_host*
dpkg-reconfigure openssh-server
```


Modifythe waagent configuration /etc/waagent.conf

```
ResourceDisk.Format=y 
ResourceDisk.EnableSwap=y   
ResourceDisk.SwapSizeMB=1024   
```

Restart the waagent service 

```
- Ubuntu
service walinuxagent restart 		
service waagent restart 
```

check the swap 

```
dmesg |grep swap 
swapon -s 
cat /proc/swaps 
file /mnt/resource/swapfile
```

#### Firewall

Firewall configuration file

| ---------------- | ----------------------- | ---------------------------------------- | ---------------------------------------- | ---------------------------------------- |
| *Stop Firewall*  | service iptables stop   | systemctl stop firewalld                 | rcSuSEfirewall2 stop                     | ufw stop                                 |
| *Start Firewall* | service iptables start  | systemctl start firewalld                | rcSuSEfirewall2  start                   | ufw enable                               |

#### Install xRDP for GUI remote access on Linux 

https://blogs.msdn.microsoft.com/linuxonazure/2016/09/26/unsupported-how-to-install-xrdp-for-gui-remote-access-on-linux/


Disable Hyper-V time synchronization behavior in Azure

#### Move a directory onto an external data disk

1 . Install rsync 
2 . Use rsync to copy /var/ to /var2/

```
rsync -aXS /var/. /var2/.
mv /var /var_old
umount /var2
mkdir /var
mount /dev/sdc1 /var
rmdir /var2
```

3 . Modify /etc/fstab

```
UUID=b5bc8356-0df4-4ade-9a64-8c054b8e7d58 /var  ext4    defaults        0 0
```







### Harden linux VM

#### Deny IP by IPset

Good webpage to check the suggested block IP ranges http://www.ipdeny.com/ipblocks/data/countries/


```
yum install ipset
#!/bin/sh
ipset -N geoblock nethash

ipset list

```

#### Harden SSHD

Use ssh keys instead of passwords
Restrict ssh to accept connections from specific networks or hosts when possible. 
Block all inbound ssh traffic and enable only good / known IPs or subnets in the VM
Use Azure Vnets and VPN with Site to Site or Point to Site connectivity


Allow port 22220 in Inbound rule
Manage SElinux to allow port 2220

```
sudo yum install policycoreutils-python
sudo semanage port -a -t ssh_port_t -p tcp 22220
```

Modify firewall to allow port 22220

```
sudo firewall-cmd --permanent --zone=public --add-port=22220/tcp
sudo firewall-cmd --reload
```

For Iptables 

```
```


```
Port 22220
```

restart sshd service(Depends on different distribution)

```
sudo systemctl restart sshd
```

#### Add logging in Iptables  

Add configuration below to /etc/sysconfig/iptables and restart the iptable services

```


```

After implement the configuraiton above, you would be able to see dirty attempted to your server in /var/log/message

```
samples:
```





```
python -c 'import platform;print platform.dist()[0]'
```

## Performance 


#### Disk Performance in Linux VM’s






### Ubuntu



### Suse

Suse on Azure: https://forums.suse.com/forumdisplay.php?95-Azure



## Kubernetes in Azure



```
tar -cvzf new.log.tgz /var/lib/docker/containers/*/*.log
ps docker --all
```

Get the logs 

```
sudo journalctl -u kubelet --no-pager  > /tmp/kubelet.log
```





```
az group create -n "yingresourcegroupk8s" -l "southeastasia"
```


```
```


```
Retrying role assignment creation: 1/36
{
  "appId": "6d02158e-1650-4dd8-a941-fa16a1d95a5f",
  "displayName": "azure-cli-2017-08-01-06-13-00",
  "name": "http://azure-cli-2017-08-01-06-13-00",
  "password": "ab968473-4084-4df5-85d3-cf708ccb07dc",
  "tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47"
}
```



## Support Related 

### Useful Link

[Azure Support Plan](https://azure.microsoft.com/en-in/support/plans/)
[Radius](https://expert.partners.extranet.microsoft.com/expert/Radius)
[Who](http://who)
[idweb](https://idweb/identitymanagement/default.aspx ): add permission to azlinuxesc 
[Bug Status](http://haridcloud/bugs)



### Support Basic 

#### Azure Gallery Image 

[Endorsed Distribution](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/endorsed-distros)
Azure Gallery Image // Marketplace Image 
1 . Premier Image (engaged the 3rd vendor) SUSE/Redhat
2 . Standard Image (Please involve ubuntu directly)



#### Labor 

1 . Non Scorecard Labor
-- General Administration 
2 . Scorecard Labor/ Burdened 65%
-- LMI
-- Mentoring

#### Survey

MB: Middle Box
BB: Bottom Box

#### SR Wait State

| **SR Wait State**                        | **Definition**                           |
| ---------------------------------------- | ---------------------------------------- |
|                                          |                                          |


**Problem:**
Should haveissue description / customer ask

**Actions Performed/Status:** 

**Next Action:**
Next courseof action intended to perform on the case which will driver for fast resolution

#### Annual Leave

Notify IM (aztechim@microsoft.com) and WFM (wfms@microsoft.com) for any annual leave,
sick leave, or training, meeting to avoid case assigned during your unavailability


 -- Need to update the above info if there is change/upgrade

#### Linux SME working process 


### Support tools

#### Leaving WFM && msvacation

	Shift details
	Send email for any unplanned leaves (sick)
	Do not send email for your planned leaves – As the leave will be automatically updated in the WFM tool if your leaves are approved by your manager


#### KB

[http://contentidea](http://contentidea). 


#### Resource Exploer

https://resources.azure.com/


[https://microsoft.sharepoint.com/sites/itweb/](https://microsoft.sharepoint.com/sites/itweb/)

#### MSSolve


##### Scope

In the due course of troubleshooting if we isolate the issue to be related to any of the internal Azure components, we will involve the team with the expertise and assist further.

##### ResouceInstanceID

subscriptions -> 1fd0b265-43cd-4317-a131-fcfb269477d5
resourceGroups -> Azure-DmVPN
virtualMachines -> Hikma-Azure-Dmvpn


Bugs of Ubuntu: https://bugs.launchpad.net/ubuntu
