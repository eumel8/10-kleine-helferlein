# 119 Kleine Helferlein

<a href="https://github.com/eumel8/10-kleine-helferlein"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white"></a>

Manche Shell-Einzeiler braucht man irgendwie immer wieder, egal in welche Tastatur man seine Finger steckt. Es wird Zeit, diese kleinen Helferlein mal aufzulisten.

Weiterführung der [Blog-Seite](https://blog.eumelnet.de/blogs/blog8.php/10-kleine-helferlein)

Schönere Ansicht mit [Github Pages](https://eumel8.github.io/10-kleine-helferlein/)


[Bash](#bash) | [MySQL](#mysql) | [Git](#git) | [OpenSSL](#openssl) | [Docker](#docker) | [Kubernetes](#kubernetes) | [Rancher](#rancher) | [Containerd](#containerd) | [Terraform](#terraform) | [Anything Else](#anything) | [Mac](#Mac)


## <a name="bash">Bash</a>

#### find all files in a directory, copy them in another, and keep all properties.

```
find . -depth | cpio -pvdm /new_data
```

#### replace a string in a file with another (here: linebreak \r)

```
perl -p -i -e 's/\r//g' datei
```

#### decode a base64 string in a file

```
perl -MMIME::Base64 -0777 -ne 'print decode_base64($_)' datei
```

#### loop within some server and execute command there (here: "date")

```
for i in 51 52 53 61 62 63; do ssh root@192.168.0.$i "hostname; date";done
```

#### out of loop devices

```
#!/bin/bash
for i in {8..30};
do
/bin/mknod -m640 /dev/loop$i b 7 $i
/bin/chown root:disk /dev/loop$i
done
```

### rpm/deb cheats:

#### To which package owns a file

```
# rpm -qif /path/to/file
# dpkg -S /path/to/file
```

#### Which files owns by an installed package

```
# rpm -qil paket-name
# dpk -L paket-name
```

#### Check dependencies of a package

```
# rpm -qpR ./paket.rpm
# dpkg -I ./paket.deb
```

#### Dependencies of an installed package

```
# rpm -qR paket-name
# apt-cache depends
```

#### copy & paste in vi

prevent zeilen misch masch

```
:set paste
```

#### bash script debug with line numbers

```
PS4='Line ${LINENO}: ' bash -x script
```

#### git-crypt list current key

```
for key in .git-crypt/keys/default/0/* ; do gpg -k $(echo $(basename $key) | sed -e 's/.gpg//') ; done ;
```

#### get gitlab environment variables and convert to shell variables

```
curl -sq --header "PRIVATE-TOKEN: <gitlab-api-token>" "https://gitlab.com/api/v4/projects/188/variables" | jq -r '"export " + .[].key + "=" + .[].value'
```

[Top](#top)

## <a name="mysql">MySQL</a>

#### Grant user permissions

```
GRANT File, Process,suprt,replication client,select on *.* TO  'depl_mon'@'192.168.0.100' identified by 'poddfsdkfskflpr934r1';
```

#### Revoke user permissions

```
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'hans'@'192.168.100.%'
```

#### Setup replication with SQL-Shell

```
mysql>
CHANGE MASTER TO
   MASTER_HOST='master2.mycompany.com',
   MASTER_USER='replication',
   MASTER_PASSWORD='bigs3cret',
   MASTER_PORT=3306,
   MASTER_LOG_FILE='master2-bin.001',
   MASTER_LOG_POS=4,
   MASTER_CONNECT_RETRY=10;
```

#### MySQL replication: skip a error counter (e.g. "Duplicate entry")

```
mysql> slave  stop; set global sql_slave_skip_counter=1; slave  start ; show slave status\G
```

#### Query-log switch on:

```
mysql> show global variables like '%general%';
+------------------+------------+
| Variable_name | Value |
+------------------+------------+
| general_log | OFF |
| general_log_file | mysqld.log |
+------------------+------------+

mysql> set global general_log = 1;
```

#### Dump MySQL Datenbank

```
mysqldump --master-data --all-databases > /tmp/mysql.sql
```

#### MySQl too many connection:

```
mysql> select @@max_connections;

+-------------------+
| @@max_connections |
+-------------------+
| 151 |
+-------------------+
1 row in set (0.00 sec)

mysql> set global max_connections = 500;
```

#### Anzahl Einttraege pro Tabelle anzeigen:

```
mysql> SELECT table_name, table_rows FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'my_schema' order by table_rows;
oder
mysql> SELECT TABLE_ROWS,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = “mydb”
```

[Top](#top)

## <a name="git">Git</a>

#### Git: Eine Datei in 2 Branches vergleichen:

```
git diff reference live -- modules/deploy/manifests/init.pp
```

#### Git: Eine Datei aus einem anderen Branch in den aktuellen kopieren:

```
git checkout reference -- modules/deploy/manifests/init.pp
```

#### lokales git repo mit remote git repo syncen:

```
git remote add mygithub https://github.com/eumel8/ansible-otc
git pull mygithub master
git push
```

[Top](#top)

## <a name="openssl">OpenSSL</a>

#### Openssl: SSL-Zertifikat anlegen (fuer apache, postfix usw.)

```
openssl req -new -x509 -days 730 -nodes -out hostname1.pem -keyout hostname1.pem
```

#### SSL-Zertifkat angucken:

```
openssl x509 -in eumelnetde.pem -noout -text
```

#### Überprüfen, ob ein SSL-Zertifikat zum Key passt:

```
openssl x509 -noout -modulus -in server.crt| openssl md5
openssl rsa -noout -modulus -in server.key| openssl md5

die checksum sollte gleich sein
```

#### Which Ciphers are offered from a TLS connection

```
nmap --script ssl-enum-ciphers -p 443 cloud.telekom.de
```

[Top](#top)

## <a name="docker">Docker</a>

### read Docker logs

```
docker logs kubelet 2>&1| less
```

#### Loesche alle Docker Container

```
for i in `docker ps --all |awk '{print $1}'`;do docker rm --force $i;done
```

#### Loesche alle Docker Images

```
for i in `docker images |awk '{print $3}'`;do docker image rm $i;done
```

[Top](#top)

## <a name="openstack">OpenStack</a>

#### unbenutze volumes loeschen

```
for i in `openstack volume list --status available -f value| awk '{print $1}'`;do openstack volume delete $i;done
```


#### bestimte Sorte VMs loeschen

```
for i in `openstack server list | grep k8s-00 | grep ranchermaster | awk '{print $2}'`;do openstack server delete $i;done
```

### create floating ip with fixed ip

```
openstack floating ip create --floating-ip-address 80.158.7.232 admin_external_net
```

[Top](#top)

## <a name="kubernetes">Kubernetes</a>

#### kubectl bash complition

```
source  <(kubectl completion bash)
```

#### list all workload like pods,deployments,services

```
kubectl get all --all-namespaces -o wide
```

#### tail -f pod log

```
kubectl -n cattle-system logs pod/rancher-7bdd99ccd4-dhpcq  --tail=10 -f
```

#### delete all evicted pods from all namespaces

```
kubectl get pods --all-namespaces --field-selector 'status.phase==Failed' -o json| kubectl delete -f -
kubectl get pods --all-namespaces | grep Evicted | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

#### delete all containers in ImagePullBackOff state from all namespaces

```
kubectl get pods --all-namespaces | grep 'ImagePullBackOff' | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

#### delete all containers in ImagePullBackOff or ErrImagePull or Evicted state from all namespaces

```
kubectl get pods --all-namespaces | grep -E 'ImagePullBackOff|ErrImagePull|Evicted' | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

#### scale up deployment

```
kubectl scale --replicas=1 deployment/rancher -n  cattle-system
```

#### describe pod

```
kubectl -n cattle-system describe pod rancher-7bdd99ccd4-v9rjm
```

#### delete pod

```
kubectl -n cattle-system delete pod/rancher-7bdd99ccd4-4qgt5 
```

#### delete pod in state Terminating

```
kubectl -n cattle-system delete pod/rancher-7bdd99ccd4-4qgt5 --force
```

#### list deployments

```
kubectl get deployments --all-namespaces
```

#### list daemonsets

```
kubectl get daemonsets --all-namespaces
```

#### get detailed status of a pod (failure)

```
kubectl -n cattle-system get pod cattle-node-agent-44xnn -o json
```

#### get events

```
kubectl -n cattle-system get events
```

#### check openstack elb service

```
kubectl -n ingress-nginx describe service openstack-lb
```

#### get all pod logs

```
kubectl get pods --all-namespaces | awk '{print "kubectl logs  "$2" -n "$1}' |  sh
```

#### exec shell into pod (where is a sh bin exists)

```
kubectl exec -it mypod -- /bin/sh
```

#### cert-manager show certs

```
kubectl get certificates --all-namespaces
```

#### cert-manager show challenges

```
kubectl get challenges --all-namespaces
```

#### copy files into pods

```
kubectl cp demo.html default/demoapp-glusterfs-66bcdf58d4-bxfbv:/usr/share/nginx/html/demo.html
```

#### get service endpoints (and describe & edit)

```
kubectl -n glusterstorage get ep heketi
```

#### follow all events

```
kubectl get events -A -w=true
```

#### show cpu/memory usage of a POD

```
kubectl top pod prometheus-cluster-monitoring-0 -n cattle-prometheus
```

#### setup tiller

```
kubectl --namespace kube-system create serviceaccount tiller
kubectl create clusterrolebinding tiller --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm  init --service-account tiller
```

#### kubectl verbose

```
kubectl -v=8
```

#### in which ClusterRoleBinding is a ServiceAccount

```
SA=cluster-monitoring; for i in `kubectl get clusterrolebindings | awk '{print $1}'`;do kubectl get clusterrolebinding $i -o yaml|grep -q $SA;if [[ "$?" -eq 0 ]];then echo $i;fi;done
```

#### run Ubuntu/Busybox in a POD

```
kubectl run -i --tty ubuntu --image=ubuntu --restart=Never -- bash
kubectl run -i --tty busybox --image=busybox --restart=Never -- sh
```

#### deploy a Busybox POD

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/admin/dns/busybox.yaml
```

#### dns debug in cluster

```
kubectl apply -f https://k8s.io/examples/admin/dns/dnsutils.yaml
kubectl exec -i -t dnsutils -- nslookup kubernetes.default
```

#### deploy a priviledged POD on each node as a daemonset

```
kubectl apply -f debug-shell.yaml
```

#### health status of nodes

```
kubectl get nodes --no-headers | awk '{print $1}' | xargs -I {} sh -c 'echo {}; kubectl describe node {} | grep Allocated -A 5 | grep -ve Event -ve Allocated -ve percent -ve -- ; echo'
```

#### list all containers

```
kubectl get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n'
```

#### where are PVCs connected

```
kubectl get pods -A -o=json | jq -c \
'.items[] | {name: .metadata.name, namespace: .metadata.namespace, claimName:.spec.volumes[] | select( has ("persistentVolumeClaim") ).persistentVolumeClaim.claimName }'
```

#### list pod name/resources

```
kubectl get pods -o json | jq '.items[].spec.containers[] | .name,.resources.limits'
```

#### set a new default namespace

```
kubectl config set-context quickstart-cluster --namespace product-api
```

#### set a new context in KUBECONFIG

```
kubectl config set-context mycontext --cluster quickstart-cluster --namespace product-api --user=myaccount
```

#### full example of KUBECONFIG settings

```
kubectl config set-cluster mycluster  --server=https://raseed.eumel.de/k8s/clusters/c-npp6v
kubectl config set-credentials rancher-userXX --token=kubeconfig-user-token
kubectl config set-context mycontext --cluster mycluster --namespace product-api --user=rancher-userXX
```

#### create a deployment

```
kubectl create deployment blog --image eumel8/nginx-none-root
```

####  Restore etcd [in Rancher cluster](https://rancher.com/docs/rancher/v2.x/en/cluster-admin/restoring-etcd/)

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock mtr.external.otc.telekomcloud.com/mcsps/runlike:latest etcd
# save output
docker stop etcd
docker rename etcd etcd-old
# remove all other etcd nodes from --initial-cluster in output
# add --force-new-cluster in output
# run the output script
# add addtional etcd nodes
```

#### Restore etcd [from file](https://etcd.io/docs/v3.4/op-guide/recovery/)

```
unzip /opt/rke/etcd-snapshots/c-tg2bh-rs-8bggs_2022-03-09T09\:25\:42Z.zip
mv backup/c-tg2bh-rs-8bggs_2022-03-09T09\:25\:42Z /var/lib/etcd
docker run --name=etcdrestore --hostname=vm-frank-test-k8s-00-ranchermaster-1 --env=ETCDCTL_API=3 --env=ETCDCTL_ENDPOINTS=https://127.0.0.1:2379 --env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin --volume=/var/lib/etcd/r3:/var/lib/rancher/etcd/ --network=host --workdir=/ --detach=true mtr.external.otc.telekomcloud.com/rancher/mirrored-coreos-etcd:v3.4.16-rancher1 /usr/local/bin/etcdctl snapshot restore /var/lib/rancher/etcd/c-tg2bh-rs-8bggs_2022-03-09T09\:25\:42Z --initial-advertise-peer-urls=https://10.9.3.92:2380 --initial-cluster-token=etcd-cluster-1 --name=etcd-vm-frank-test-k8s-00-ranchermaster-1 --initial-cluster=etcd-vm-frank-test-k8s-00-ranchermaster-1=https://10.9.3.92:2380 --data-dir=/var/lib/rancher/etcd/data
mv /var/lib/etc/r3/data/member /var/lib/etc
```

make the etcd recovery with initial-cluster as above


#### Explain Custome Resource Defintions

```
kubectl explain alertmanagerconfig.spec.receivers
```

#### Set a StorageClass as default

```
kubectl edit sc sata
metadata:
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
```

#### List allocated resources on all Kubernetes Nodes

```
for i in `kubectl get nodes --no-headers --output=name`;do echo $i; kubectl describe $i | grep "Allocated resources" -A 5;done
```

#### Which ServiceAccount is defined in Workloads

```
kubectl -n kube-system get deployments -o json | jq -r '"name :",.items[].metadata.name,"container :",.items[].spec.template.spec.containers[].name,"serviceAccount :",.items[].spec.template.spec.serviceAccountName'
```

#### Which ServiceAccount used which (Cluster)RoleBindings

```
wget -qO- https://github.com/FairwindsOps/rbac-lookup/releases/download/v0.7.1/rbac-lookup_0.7.1_Linux_x86_64.tar.gz | tar xfz - rbac-lookup
./rbac-lookup database-operator -k serviceaccount -o wide
tar xvfz  
```

#### Which nodes are in which AZ

```
kubectl get nodes -o json | jq -r '.items[]| .metadata.labels."topology.kubernetes.io/zone" + " - " + .metadata.labels."kubernetes.io/hostname"' | sort
```

#### K3S Recover cluster failed due the cluster api authentication failure
https://github.com/k3s-io/k3s/issues/2788

```
kubectl get secrets -A|grep service-account-token | awk '{print "kubectel -n "$1 " delete secret "$2}'
kubectl get pods -A| awk '{print "kubectel -n "$1 " delete pod "$2}'

remove all secrets and restart pods with fresh service account token
```

#### Grab information from K8S resource description

```
kubectl get pods --namespace cognigy -l "app=prometheus-redis-exporter,release=prometheus-redis-persistent-exporter" -o jsonpath="{.items[0].metadata.name}"
```

#### Scale down all resources

```
kubectl -n default scale all --all --replicas=0
```

#### Force delete PODs in state Terminating

```
kubectl delete pod --grace-period=0 --force broken_pod
```

#### Which (Cluster)RoleBindings are associated to a ServiceAccount

```
kubectl get clusterrolebindings -o json | jq -r '.items[] | select( .subjects // [] | .[] | [.kind,.namespace,.name] == ["ServiceAccount","cert-manager","cert-manager"]) | .metadata.name'
```

#### Which deprecated API are in use

using Kube No Trouble (kubent)

```
curl -L https://git.io/install-kubent | sh -
kubent -o json | jq -r '.[] | select (."ApiVersion"| contains("networking"))'
```

#### Who requested cpu/memory resources in the cluster

```
kubectl get pods -A -o json | jq -r '.items[] |"\(.spec.containers[].resources.requests.cpu);\(.spec.containers[].resources.requests.memory);\(.metadata.namespace);\(.metadata.name);"'| sort -nr | grep -v "^null"
```

#### Check if all certificates of application are valid

```
kubectl get certificates -A -o json | jq -r '.items[] | .status.notAfter + " => " + .metadata.namespace + "/" + .metadata.name' | sort -n
```


#### Show PODs in state 'Pending'

```
kubectl get pods --no-headers -A --field-selector=status.phase=Pending
```

#### Expande Persistant Volume Claim (PVC) with cinder volume expander

```
# scale down workload
kubectl -n cms scale --replicas=0 statefulset management-solr-master
# increase volume size
kubectl -n cms edit pvc management-solr-master-pv-claim 
# scale up workload
kubectl -n cms scale --replicas=0 statefulset management-solr-master
# show results
kubectl -n cms describe pvc management-solr-master-pv-claim 
```

#### Show taint values on all nodes

```
kubectl get nodes -o json| jq -r '.items[]| .metadata.name + " - " + .spec.taints[]?.value'
```

#### Update kubectl.kubernetes.io/last-applied-configuration annotation (used by kubent for API deprecation)

```
kubectl -n mcsps-certs get ingress mcsps-certs -o yaml |kubectl apply -f -
```

#### Remove finalizer with cli (on batch mode)

```
kubectl patch volumesnapshot redis-persistent-1622552970 -p '{"metadata":{"finalizers":null}}' --type=merge
```

#### top consumer per ip-address on ingress-nginx controller logs

```
for i in `kubectl -n ingress-nginx get pod -lapp=ingress-nginx --no-headers=true| awk '{print $1}'`; do  kubectl -n ingress-nginx logs $i | awk '{print $1}' | grep "^[0-9]*\.";done | sort | uniq -c | sort -nr | head -100
```

[Top](#top)

## <a name="rancher">Rancher</a>

#### Reset admin password

```
kubectl -n cattle-system exec -it <rancher-pod> -- reset-password
```

#### Snapshot Restore in progres??

```
kubectl get clusters c-lvjds -o json | jq -r '. | select(.spec.rancherKubernetesEngineConfig.restore.restore==true)'
```

#### delete namespace in state Terminating (in Rancher)

```
kubectl get  ns glusterstorage  -o json > gl.json # delete entries in finalizers list
curl -k -H "Content-Type: application/json" -H "authorization: Bearer xxxx" -X PUT --data-binary @gl.json  https://raseed-test.external.otc.telekomcloud.com/k8s/clusters/c-bsc65/api/v1/namespaces/glusterstorage/finalize

kubectl get namespace "cattle-system" -o json \
            | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
            | kubectl replace --raw /api/v1/namespaces/cattle-system/finalize -f -
```

#### RKE bad handshake

```
rke cert rotate --rotate-ca --config cluster.yml
```

#### Can't remove nodes from UI which are already removed but still there

```
# get a list of nodes for the cluster
kubectl -n c-lvjds get nodes.management.cattle.io
# edit specific node and remove "Finalizer" and the keys behind, which caused the blocking state
kubectl -n c-lvjds edit nodes.management.cattle.io m-a65b8ee3055b
```

#### Get RKE system images

```
kubectl -n cattle-global-data get rkek8ssystemimages 
```

#### Node Cleanup

* https://gist.githubusercontent.com/superseb/2cf186726807a012af59a027cb41270d/raw/eaa2d235e7693c2d1c5a2a916349410274bb95a9/cleanup.sh

#### CloudController Manager LoadBalancer wrong selector:

remove lb ingress selector io.cattle.field/appId: mcsps-openstack-cloud-controller-manager (ref: https://github.com/rancher/rancher/issues/28275)

```
kubectl -n ingress-nginx edit service openstack-lb 
```

#### Check if cluster certificates are still valid in Rancher

```
curl -s -H "Content-Type: application/json" -H "authorization: Bearer xxxxxxxxxxxxxxx"   https://raseed-test.external.otc.telekomcloud.com/v3/clusters/local | jq -c '.certificatesExpiration|to_entries[] | select(.value.expirationDate <= '\"`date -d "+ 1 month" -I`\"') | [.key, .value.expirationDate']
```

#### rancher-webhhok x509: certificate has expired or is not yet valid

```
kubectl -n cattle-system edit deployments.apps rancher-webhook
```

downgrade image tag from v0.2.1 to v0.1.1 and back


#### Check cert validation on K3S cluster

```
cd /var/lib/rancher/k3s/server/tls
for i in `ls *.crt`; do echo $i; openssl x509 -enddate -noout -in $i; done
```

#### Downstream cluster can't connect to Rancher

```
kubectl -n cattle-system edit deployment cattle-cluster-agent

remove cattle ca checksum value
- name: CATTLE_CA_CHECKSUM
          value: 7a727981d669aa65eb5c2b869eb976011e4dc63cf5eb9f9e9736a4338e578ce9
```

#### Get Admin Credentials from Rancher downstream cluster

```
docker run --rm --net=host -v $(docker inspect kubelet --format '{{ range .Mounts }}{{ if eq .Destination "/etc/kubernetes" }}{{ .Source }}{{ end }}{{ end }}')/ssl:/etc/kubernetes/ssl:ro --entrypoint bash $(docker inspect $(docker images -q --filter=label=org.label-schema.vcs-url=https://github.com/rancher/hyperkube.git) --format='{{index .RepoTags 0}}' | tail -1) -c 'kubectl --kubeconfig /etc/kubernetes/ssl/kubecfg-kube-node.yaml get configmap -n kube-system full-cluster-state -o json | jq -r .data.\"full-cluster-state\" | jq -r .currentState.certificatesBundle.\"kube-admin\".config | sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://127.0.0.1:6443\"_"' > kubeconfig_admin.yaml
```

newer:
```
docker run --rm --net=host -v $(docker inspect kubelet --format '{{ range .Mounts }}{{ if eq .Destination "/etc/kubernetes" }}{{ .Source }}{{ end }}{{ end }}')/ssl:/etc/kubernetes/ssl:ro --entrypoint bash $(docker inspect $(docker images -q --filter=label=org.opencontainers.image.source=https://github.com/rancher/hyperkube.git) --format='{{index .RepoTags 0}}' | tail -1) -c 'kubectl --kubeconfig /etc/kubernetes/ssl/kubecfg-kube-node.yaml get configmap -n kube-system full-cluster-state -o json | jq -r .data.\"full-cluster-state\" | jq -r .currentState.certificatesBundle.\"kube-admin\".config | sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://127.0.0.1:6443\"_"' > kubeconfig_admin.yaml
```

#### Debug Banzaicloud Logging Operator in Rancher

```
kubectl -n cattle-logging-system exec -it rancher-logging-fluentd-0 -- cat /fluentd/log/out
```

#### Replace deprecates kubectl componentstatus

```
kubectl get clusters.management.cattle.io local -o json | jq  '.status.componentStatuses[] | .name,.conditions[].message'
```

```
curl -s -H "Content-Type: application/json" -H "authorization: Bearer <token>" https://raseed-test.external.otc.telekomcloud.com/k8s/clusters/local/apis/management.cattle.io/v3/clusters/local| jq '.status.componentStatuses[] | .name,.conditions[].message'
```

#### Search in Rancher audit logs for sso users


```
audit.user.extra.username
```

[Top](#top)

## <a name="comtainerd">Containerd/K3S</a>

#### Containterd list containers

```
ctr c list
```

#### Containterd list containers within k3s

```
k3s crictl ps
```

#### Containterd list images within k3s

```
k3s crictl images
```

[Top](#top)

## <a name="terraform">Terraform</a>

#### Use local provider instead remote (or snapshot version)

```
cat  ~/.terraformrc
plugin_cache_dir   = "$HOME/.terraform.d/plugin-cache"
disable_checkpoint = true

provider_installation {
  filesystem_mirror {
    path    = "/home/ubuntu/.terraform.d/plugin-cache"
  }
}
```

The plugin location on Linux will be ` ~/.terraform.d/plugin-cache/registry.terraform.io/opentelekomcloud/opentelekomcloud/1.25.3-SNAPSHOT-09496217/linux_amd64/terraform-provider-opentelekomcloud_v1.25.3-SNAPSHOT-09496217` to use
a snapshot version from https://zuul.otc-service.com/t/eco/project/github.com/opentelekomcloud/terraform-provider-opentelekomcloud

## <a name="mac">Mac</a>

#### Can't start unsigned programms in zsh

```
sudo spctl --master-disable
```

## <a name="anything">Anything Else</a>

#### Virtual Console with virt-viewer

```
virt-viewer -c qemu+ssh://root@192.168.0.101/system test
```

#### ZFS set automatic mountpoints (lxd story)

```
zfs get mountpoint lxd00/containers/dns
zfs set mountpoint=/var/lib/lxd/containers/dns.zfs lxd00/containers/dns
zfs mount lxd00/containers/jump
cd /var/lib/lxd/containers
ln -s /var/lib/lxd/containers/dns.zfs dns

used by rollback lxd 2.2 to 2.0
```

#### SMTP connect test with curl

```
curl -v smtp://out-cloud.mms.t-systems-service.com:25 --mail-from noreply@raseed.external.otc.telekomcloud.com --mail-rcpt f.kloeker@t-online.de --upload-file /etc/os-release
oder
openssl s_client -connect securesmtp.t-online.de:465
```

#### My current permissions in Windows

```
rundll32.exe keymgr.dll KRShowKeyMgr
```

#### Linux Logfile Expire

```
journalctl –vacuum-time=3d
```

#### My current Internet ip-address

```
curl https://ipinfo.io/ip
```

[Top](#top)

