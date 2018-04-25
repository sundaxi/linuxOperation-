# Azure_ansible.md

=================

   * [Azure Ansible](#azure-ansible)
      * [Guide](#guide)
      * [Install Ansible on Ubuntu server](#install-ansible-on-ubuntu-server)
         * [Get the credentials](#get-the-credentials)
      * [Run ansible-playbook](#run-ansible-playbook)


## Guide

http://docs.ansible.com/ansible/latest/scenario_guides/guide_azure.html

## Install Ansible on Ubuntu server 

Install azure-cli 
https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-apt?view=azure-cli-latest

```bash
curl -L https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt-get install apt-transport-https
sudo apt-get update && sudo apt-get install azure-cli
```

Install ansible[azure]

```bash
sudo apt-get update && sudo apt-get install -y libssl-dev libffi-dev python-dev python-pip
pip install ansible[azure]
```

### Get the credentials 

```bash
az ad sp create-for-rbac --query '{"client_id": appId, "secret": password, "tenant": tenant}'
az account show --query "{ subscription_id: id }"
```

Keep backup on ~/.ansible.credentails

```bash
{
  "client_id": "xxxx-xxxx-xxxx-xxxx",
  "secret": "xxxx-xxxx-xxxx-xxxx-xxxxx",
  "tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47"
}
```


```bash
[default]
subscription_id=0f96dbcb-37cf-4c89-94ac-f9672a0ec207
client_id=xxxx-xxxx-xxxx-xxxx
secret=xxxx-xxxx-xxxx-xxxx
tenant=72f988bf-86f1-41af-91ab-2d7cd011db47
```

## Run ansible-playbook 

You might get certificate errors 

```
Max retries exceeded with url: /72f9
r([('SSL routines', 'ssl3_get_server_certificate', 'certificate verify failed')],)\",),))\n", "m
```


```bash
://pypi.doubanio.com/simple
pip install cryptography --upgrade --trusted-host pypi.doubanio.com -i h
ttp://pypi.doubanio.com/simple
```


```yaml
  hosts: localhost
  connection: local
  tasks:
    azure_rm_virtualnetwork:
      resource_group: aztest
      name: testVnet
      address_prefixes: "192.168.0.0/16"
  - name: Add subnet
    azure_rm_subnet:
      resource_group: aztest
      name: mySubnet
      address_prefix: "192.168.48.0/24"
      virtual_network: testVnet
    azure_rm_publicipaddress:
      resource_group: aztest
      allocation_method: Dynamic
      name: testPublicIP
    azure_rm_securitygroup:
      resource_group: aztest
      name: testNSG
      rules:
        - name: SSH
          destination_port_range: 22
          access: Allow
          priority: 1001
          direction: Inbound
    azure_rm_networkinterface:
      resource_group: aztest
      virtual_network: testVnet
      subnet: testSubnet
      public_ip_name: testPublicIP
      security_group: testNSG
    azure_rm_virtualmachine:
      resource_group: aztest
      name: testVM
      vm_size: Standard_DS1_v2
      admin_username: yinsun
      ssh_password_enabled: false
      ssh_public_keys:
        - path: /home/yinsun/.ssh/authorized_keys
          key_data: "ssh-rsa xxx"
      image:
        sku: '7.3'
        version: latest
```

Run the playbook

```bash
```


```bash
 [WARNING]: Unable to parse /etc/ansible/hosts as an inventory source

 [WARNING]: No inventory was parsed, only implicit localhost is available

 [WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit
localhost does not match 'all'



ok: [localhost]

Please enter password for encrypted keyring:
changed: [localhost]

Please enter password for encrypted keyring:
changed: [localhost]

Please enter password for encrypted keyring:
changed: [localhost]

Please enter password for encrypted keyring:
changed: [localhost]

Please enter password for encrypted keyring:
version 2.9. Deprecation warnings can be disabled by setting deprecation_warnings=False in
ansible.cfg.
changed: [localhost]

Please enter password for encrypted keyring:
changed: [localhost]

localhost                  : ok=7    changed=6    unreachable=0    failed=0
```



