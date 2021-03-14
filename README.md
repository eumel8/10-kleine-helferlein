# 10 (85) Kleine Helferlein

Manche Shell-Einzeiler braucht man irgendwie immer wieder, egal in welche Tastatur man seine Finger steckt. Es wird Zeit, diese kleinen Helferlein mal aufzulisten.
Weiterführung der [Blog-Seite](https://blog.eumelnet.de/blogs/blog8.php/10-kleine-helferlein)


## Bash

#### Finde alle Dateien in einem Verzeichnis und kopiere sie in ein anderes Verzeichnis. Alle Dateieigenschaften bleiben erhalten.

```
find . -depth | cpio -pvdm /new_data
```

2. Ersetze einen String durch einen anderen in einer Datei (hier Zeilenendezeichen \r)

```
perl -p -i -e 's/\r//g' datei
```

3. Dekodiere einen base64-String in einer Datei

```
perl -MMIME::Base64 -0777 -ne 'print decode_base64($_)' datei
```

4. Fuehre nacheinander auf vielen Rechnern ein Kommando aus (z.B. "date")

```
for i in 51 52 53 61 62 63; do ssh root@192.168.0.$i "hostname; date";done
```

5. Meine Loop-Devices sind alle.

```
#!/bin/bash
for i in {8..30};
do
/bin/mknod -m640 /dev/loop$i b 7 $i
/bin/chown root:disk /dev/loop$i
done
```

### rpm/deb cheats:

```
6. Zu welchem Paket gehoert eine Datei:

# rpm -qif /path/to/file
# dpkg -S /path/to/file

7. Welche Dateien sind in einem installierten Paket:
# rpm -qil paket-name
# dpk -L paket-name

8. Abhaengigkeiten eines Pakets pruefen:
# rpm -qpR ./paket.rpm
# dpkg -I ./paket.deb

9. Abhaengigkeiten eines installierten Pakets pruefen:
# rpm -qR paket-name
# apt-cache depends
```

10. Text aus Zwischenablage in vi einfuegen:
Manchmal gibt es haessliche Zeilenverschiebungen. Dagegen hilft ein

```
:set paste
```

11. bash script debug mit Zeilennummer

```
PS4='Line ${LINENO}: ' bash -x script
```

## MySQL

12. Lege einen User an, vergebe ein Passwort und bestimmte Rechte

```
GRANT File, Process,suprt,replication client,select on *.* TO  'depl_mon'@'192.168.0.100' identified by 'poddfsdkfskflpr934r1';
```

13. Widerufe die Rechte fuer einen Datenbankuser

```
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'hans'@'192.168.100.%'
```

14. Replikation mit SQL-Shell einrichten

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

15. MySQL-Replikation: Ueberspringe einen Fehlercounter (z.B. "Duplicate entry")

```
mysql> slave  stop; set global sql_slave_skip_counter=1; slave  start ; show slave status\G
```

16. Query-log einschalten:

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

17. Dump MySQL Datenbank

```
mysqldump --master-data --all-databases > /tmp/mysql.sql
```

18. MySQl too many connection:

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

19. Anzahl Einttraege pro Tabelle anzeigen:

```
mysql> SELECT table_name, table_rows FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'my_schema' order by table_rows;
oder
mysql> SELECT TABLE_ROWS,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = “mydb”
```

## Git

20. Git: Eine Datei in 2 Branches vergleichen:

```
git diff reference live -- modules/deploy/manifests/init.pp
```

21. Git: Eine Datei aus einem anderen Branch in den aktuellen kopieren:

```
git checkout reference -- modules/deploy/manifests/init.pp
```

22. lokales git repo mit remote git repo syncen:

```
git remote add mygithub https://github.com/eumel8/ansible-otc
git pull mygithub master
git push
```

## OpenSSL

23. Openssl: SSL-Zertifikat anlegen (fuer apache, postfix usw.)

```
openssl req -new -x509 -days 730 -nodes -out hostname1.pem -keyout hostname1.pem
```

24. SSL-Zertifkat angucken:

```
openssl x509 -in eumelnetde.pem -noout -text
```

25. Überprüfen, ob ein SSL-Zertifikat zum Key passt:

```
openssl x509 -noout -modulus -in server.crt| openssl md5
openssl rsa -noout -modulus -in server.key| openssl md5

die checksum sollte gleich sein
```


## Docker

27. Loesche alle Docker Container

```
for i in `docker ps --all |awk '{print $1}'`;do docker rm --force $i;done
```

28. Loesche alle Docker Images

```
for i in `docker images |awk '{print $3}'`;do docker image rm $i;done
```

# OpenStack

29. unbenutze volumes loeschen

```
for i in `openstack volume list --status available -f value| awk '{print $1}'`;do openstack volume delete $i;done
```

30. bestimte Sorte VMs loeschen

```
for i in `openstack server list | grep k8s-00 | grep ranchermaster | awk '{print $2}'`;do openstack server delete $i;done
```

## Dies & Das

31. Virtuelle Konsole aufrufen mit virt-viewer

```
virt-viewer -c qemu+ssh://root@192.168.0.101/system test
```

32. ZFS set automatic mountpoints (lxd story)

```
zfs get mountpoint lxd00/containers/dns
zfs set mountpoint=/var/lib/lxd/containers/dns.zfs lxd00/containers/dns
zfs mount lxd00/containers/jump
cd /var/lib/lxd/containers
ln -s /var/lib/lxd/containers/dns.zfs dns

used by rollback lxd 2.2 to 2.0
```

33. teste SMTP Verbindung mit curl

```
curl -v smtp://out-cloud.mms.t-systems-service.com:25 --mail-from noreply@raseed.external.otc.telekomcloud.com --mail-rcpt f.kloeker@t-online.de --upload-file /etc/os-release
```

34. Welche Rechte habe ich im Windows

```
rundll32.exe keymgr.dll KRShowKeyMgr
```

35. SMTPS Verbindung testen mit OpenSSL

```
openssl s_client -connect securesmtp.t-online.de:465
```

36. Linux Logfile Expire

```
journalctl –vacuum-time=3d
```

37. Wie ist meine externe IP-Adresse:

```
curl https://ipinfo.io/ip
```

## Kubernetes

38. kubectl bash complition

```
source  <(kubectl completion bash)
```

39. alle pods und servcíces auflisten

```
kubectl get all --all-namespaces -o wide
```

40. tail -f rancher logs

```
kubectl logs pod/rancher-7bdd99ccd4-dhpcq  -n cattle-system --tail=10 -f
```

41. delete all evicted pods from all namespaces

```
kubectl get pods --all-namespaces --field-selector 'status.phase==Failed' -o json| kubectl delete -f -
kubectl get pods --all-namespaces | grep Evicted | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

42. delete all containers in ImagePullBackOff state from all namespaces

```
kubectl get pods --all-namespaces | grep 'ImagePullBackOff' | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

43. delete all containers in ImagePullBackOff or ErrImagePull or Evicted state from all namespaces

```
kubectl get pods --all-namespaces | grep -E 'ImagePullBackOff|ErrImagePull|Evicted' | awk '{print $2 " --namespace=" $1}' | xargs kubectl delete pod
```

44. scale pod

```
kubectl scale --replicas=1 deployment/rancher -n  cattle-system
```

45. describe pod

```
kubectl -n cattle-system describe pod rancher-7bdd99ccd4-v9rjm
```

46. delete pod

```
kubectl delete pod/rancher-7bdd99ccd4-4qgt5 -n cattle-system
```

47. check deployments

```
kubectl get deployments --all-namespaces
```

48. check daemonsets

```
kubectl get daemonsets --all-namespaces
```

49. get detailed status of a pod (failure)

```
kubectl get pod cattle-node-agent-44xnn -n cattle-system -o json
```

50. get events

```
kubectl get events -n cattle-system
```

51. check openstack elb service

```
kubectl describe service openstack-lb -n ingress-nginx
```

52. get all pod logs

```
kubectl get pods --all-namespaces | awk '{print "kubectl logs  "$2" -n "$1}' |  sh
```

53. exec shell into pod (where is a sh bin exists)

```
kubectl exec -it mypod -- /bin/sh
```

54. cert-manager show certs

```
kubectl get certificates --all-namespaces
```

55. cert-manager show challenges

```
kubectl get challenges --all-namespaces
```

56. scale deployments/daemonsets

```
kubectl scale --replicas=2 deployment demoapp-glusterfs -n default
```

57. copy files into pods

```
kubectl cp demo.html  default/demoapp-glusterfs-66bcdf58d4-bxfbv:/usr/share/nginx/html/demo.html
```

58. get service endpoints (and describe & edit)

```
kubectl get ep heketi -n glusterstorage
```

59. delete namespace in state Terminating

```
kubectl get  ns glusterstorage  -o json > gl.json # delete entries in finalizers list
curl -k -H "Content-Type: application/json" -H "authorization: Bearer xxxx" -X PUT --data-binary @gl.json  https://raseed-test.external.otc.telekomcloud.com/k8s/clusters/c-bsc65/api/v1/namespaces/glusterstorage/finalize

kubectl get namespace "cattle-system" -o json \
            | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" \
            | kubectl replace --raw /api/v1/namespaces/cattle-system/finalize -f -
```

60. follow all events

```
kubectl get events -A -w=true
```

61. show cpu/memory usage of a POD

```
kubectl top pod prometheus-cluster-monitoring-0 -n cattle-prometheus
```

62. setup tiller

```
kubectl --namespace kube-system create serviceaccount tiller
kubectl create clusterrolebinding tiller --clusterrole=cluster-admin --serviceaccount=kube-system:tiller
helm  init --service-account tiller
```

63. kubectl verbose

```
kubectl -v=8
```

64. in which ClusterRoleBinding is a ServiceAccount

```
SA=cluster-monitoring; for i in `kubectl get clusterrolebindings | awk '{print $1}'`;do kubectl get clusterrolebinding $i -o yaml|grep -q $SA;if [[ "$?" -eq 0 ]];then echo $i;fi;done
```

65. run Ubuntu/Busybox in a POD

```
kubectl run -i --tty ubuntu --image=ubuntu --restart=Never -- bash
kubectl run -i --tty busybox --image=busybox --restart=Never -- sh
```

66. deploy a Busybox POD

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/admin/dns/busybox.yaml
```

67. dns debug in cluster

```
kubectl apply -f https://k8s.io/examples/admin/dns/dnsutils.yaml
kubectl exec -i -t dnsutils -- nslookup kubernetes.default
```

68. deploy a priviledged POD on each node as a daemonset

```
kubectl apply -f debug-shell.yaml
```

69. health status of nodes

```
kubectl get nodes --no-headers | awk '{print $1}' | xargs -I {} sh -c 'echo {}; kubectl describe node {} | grep Allocated -A 5 | grep -ve Event -ve Allocated -ve percent -ve -- ; echo'
```

70. list all containers

```
kubectl get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n'
```

71. where are PVCs connected

```
kubectl get pods -A -o=json | jq -c \
'.items[] | {name: .metadata.name, namespace: .metadata.namespace, claimName:.spec.volumes[] | select( has ("persistentVolumeClaim") ).persistentVolumeClaim.claimName }'
```

72. list pod name/resources

```
kubectl get pods -o json | jq '.items[].spec.containers[] | .name,.resources.limits'
```

73. set a new default namespace

```
kubectl config set-context quickstart-cluster --namespace product-api
```

74. set a new context in KUBECONFIG

```
kubectl config set-context mycontext --cluster quickstart-cluster --namespace product-api --user=myaccount
```

75. full example of KUBECONFIG settings

```
kubectl config set-cluster mycluster  --server=https://raseed.eumel.de/k8s/clusters/c-npp6v
kubectl config set-credentials rancher-userXX --token=kubeconfig-user-token
kubectl config set-context mycontext --cluster mycluster --namespace product-api --user=rancher-userXX
```

76. create a deployment

```
kubectl create deployment blog --image eumel8/nginx-none-root
```

77.  Restore etcd [in Rancher cluster](https://rancher.com/docs/rancher/v2.x/en/cluster-admin/restoring-etcd/)

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock assaflavie/runlike etcd
# save output
docker stop etcd
docker rename etcd etcd-old
# remove all other etcd nodes from --initial-cluster in output
# add --force-new-cluster in output
# run the output script
# add addtional etcd nodes
```

### Rancher

78. Snapshot Restore in progres??

```
kubectl get clusters c-lvjds -o json | jq -r '. | select(.spec.rancherKubernetesEngineConfig.restore.restore==true)'
```

79. RKE bad handshake

```
rke cert rotate --rotate-ca --config cluster.yml
```

80. Can't remove nodes from UI which are already removed but still there

```
# get a list of nodes for the cluster
kubectl -n c-lvjds get nodes.management.cattle.io
# edit specific node and remove "Finalizer" and the keys behind, which caused the blocking state
kubectl -n c-lvjds edit nodes.management.cattle.io m-a65b8ee3055b
```

81. Node Cleanup

* https://gist.githubusercontent.com/superseb/2cf186726807a012af59a027cb41270d/raw/eaa2d235e7693c2d1c5a2a916349410274bb95a9/cleanup.sh

82. CloudController Manager LoadBalancer wrong selector:

remove lb ingress selector io.cattle.field/appId: mcsps-openstack-cloud-controller-manager (ref: https://github.com/rancher/rancher/issues/28275)

```
kubectl -n ingress-nginx edit service openstack-lb 
```

83. Containterd list containers

```
ctr c list
```

84. Downstream cluster can't connect to Rancher

```
kubectl -n cattle-system edit deployment cattle-cluster-agent

remove cattle ca checksum value
- name: CATTLE_CA_CHECKSUM
          value: 7a727981d669aa65eb5c2b869eb976011e4dc63cf5eb9f9e9736a4338e578ce9
```

85. K3S Recover cluster failed due the cluster api authentication failure
https://github.com/k3s-io/k3s/issues/2788

```
kubectl get secrets -A|grep service-account-token | awk '{print "kubectel -n "$1 " delete secret "$2}'
kubectl get pods -A| awk '{print "kubectel -n "$1 " delete pod "$2}'

remove all secrets and restart pods with fresh service account token
```

85

