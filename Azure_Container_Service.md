
=================

      * [Prerequisite](#prerequisite)
      * [Docker](#docker)
         * [Manage data volumes](#manage-data-volumes)



## Prerequisite 

Kubernetes: https://kubernetes.io/docs/home/

###Service Principals

https://github.com/Azure/acs-engine/blob/master/docs/serviceprincipal.md

Service Accounts in Azure are tied to Active Directory Service Principals. You can read more about Service Principals and AD Applications: ["Application and service principal objects in Azure Active Directory"](https://azure.microsoft.com/en-us/documentation/articles/active-directory-application-objects/).

Kubernetes uses a Service Principal to talk to Azure APIs to dynamically manage resources such as [User Defined Routes](https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-udr-overview/) and [L4 Load Balancers](https://azure.microsoft.com/en-us/documentation/articles/load-balancer-overview/).


```
az login
```


```
az vm list-sizes --location westus
```

## Docker

Ubuntu 14.04 -/etc/default/docker 
Ubuntu 16.04 -/etc/systemd/system/docker.service.d/execstart.conf



offical document: https://dcos.io/docs/1.7/administration/installing/cloud/azure/




```
az group create --name dcos --location southeastasia
```


```
```

Get the IP address 

```
az network public-ip list --resource-group dcos --query "[*].{Name:name,IPAddress:ipAddress}" -o table
```


```
ip=$(az network public-ip list --resource-group dcos --query "[?contains(name,'dcos-master')].[ipAddress]" -o tsv)
ssh -fNL 80:localhost:80 -p 2200 yinsun@$ip
```


```
az acs dcos install-cli
```

Ajusting port for ssh tunnel

```
ip=$(az network public-ip list --resource-group dcos --query "[?co
ntains(name,'dcos-master')].[ipAddress]" -o tsv)
ssh -L 8080:localhost:80 $ip
dcos config set core.dcos_url http://localhost:8080
```


```
dcos marathon app add marathon-app.json
```


```
dcos marathon app list
```


```
az network public-ip list --resource-group dcos --query "[?contains(name,'dcos-agent')].[ipAddress]" -o tsv
```

Delete resource group 

```
az group delete --name dcos --no-wait
```



```
```

Increase the count to 5, use az acs scale command 

```
```

### Manage data volumes 

Link: https://docs.microsoft.com/en-us/azure/container-service/dcos-swarm/container-service-dcos-fileshare


##K8s




###Deployment


```
az group create --name k8s --location southeastasia
```


```
```


```
kubectl get replicaset
```

Delete deployment based on label

```
kubectl delete all -l app=azure-vote-front
pod "azure-vote-front-837696400-b49f9" deleted
deployment "azure-vote-front" deleted
```


kubelet Environment /etc/default/kubelet

```
```

kubelet service 

```
[Unit]
Description=Kubelet
Requires=docker.service
After=docker.service

[Service]
Restart=always
EnvironmentFile=/etc/default/kubelet
SuccessExitStatus=143
ExecStartPre=/bin/bash /opt/azure/containers/kubelet.sh
ExecStartPre=/bin/mkdir -p /var/lib/kubelet
ExecStartPre=/bin/bash -c "if [ $(mount | grep \"/var/lib/kubelet\" | wc -l) -le 0 ] ; then /bin/mount --bind /var/lib/kubelet /var/lib/kubelet ;
 fi"
ExecStartPre=/bin/mount --make-shared /var/lib/kubelet
#  https://github.com/kubernetes/kubernetes/issues/41916#issuecomment-312428731
ExecStartPre=/sbin/sysctl -w net.ipv4.tcp_retries2=8
ExecStartPre=-/sbin/ebtables -t nat --list
ExecStartPre=-/sbin/iptables -t nat --list
ExecStart=/usr/bin/docker run \
  --net=host \
  --pid=host \
  --privileged \
  --rm \
  --volume=/dev:/dev \
  --volume=/sys:/sys:ro \
  --volume=/var/run:/var/run:rw \
  --volume=/var/lib/docker/:/var/lib/docker:rw \
  --volume=/var/lib/kubelet/:/var/lib/kubelet:shared \
  --volume=/var/log:/var/log:rw \
  --volume=/etc/kubernetes/:/etc/kubernetes:ro \
  --volume=/var/lib/waagent/ManagedIdentity-Settings:/var/lib/waagent/ManagedIdentity-Settings:ro \
      /hyperkube kubelet \
        --kubeconfig=/var/lib/kubelet/kubeconfig \
        --require-kubeconfig \
        --address=0.0.0.0 \
        --allow-privileged=true \
        --enable-server \
        --enable-debugging-handlers \
        --pod-manifest-path=/etc/kubernetes/manifests \
        --cluster-domain=cluster.local \
        --cloud-provider=azure \
        --cloud-config=/etc/kubernetes/azure.json \
        --azure-container-registry-config=/etc/kubernetes/azure.json \
        --hairpin-mode=promiscuous-bridge \
```






Install go: https://golang.org/doc/install

