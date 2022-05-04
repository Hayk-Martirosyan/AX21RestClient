# AX21RestClient

With the help of this project you can do rest calls to your TP Link Archer AX21/1800 router.
It has encrypted API so it is impossible to directly call and use it rest api.

I needed to check internet conectivity from a host within a local network  and reboot the router since it has a tendency to not get dynamic ip after power outeges.

I got inspired by the work of Oriol Castejón https://the-hyperbolic.com/posts/hacking-the-tlwpa4220-part-3/

Archer AX21 is newer than the router used in the mentioned post. This one uses two RSA keys and one AES compared to  the previous one mentioned in the post.



## Basic Usage
```
restClient = RouterRestClient('192.168.0.1', 'router password')
restClient.get_rsa_keys()
restClient.login()
restClient.reboot()
restClient.logout()
```


## Use with docker

### To build just run a command
```
./build.sh
```

### To execute
```
docker run tplink-api:1.0 bash -c "./checkInternet.sh 8.8.8.8 192.168.0.1 password"
```

## To Make an API call from command line
```
#status?form=all   operation=read
python3 RestClient.py -p router_password -t 192.168.0.1 -path status -f all -o read
```
## API and parameter value samples (list is not complete)
```

URL PostData
firmware?form=upgrade   operation=read
cloud_account?form=check_upgrade   operation=read
system?form=sysmode   operation=read
firmware?form=upgrade   operation=write&upgraded=false
time?form=settings   operation=read
network?form=wan_ipv4_status   operation=read
network?form=lan_ipv4   operation=read
network?form=lan_agg   operation=read
ddns?form=provider   operation=read
dhcps?form=setting   operation=read
status?form=internet   operation=read
access_control?form=black_devices   operation=load
access_control?form=enable   operation=read
access_control?form=mode   operation=read
cloud_account?form=get_deviceInfo   operation=read
wireless?form=wireless_2g   operation=read
wireless?form=wireless_5g   operation=read
wireless?form=guest_2g   operation=read
wireless?form=guest_5g   operation=read
status?form=router   operation=read
status?form=all   operation=read
smart_network?form=game_accelerator   operation=loadDevice
onemesh_network?form=mesh_sclient_list_all   operation=read
cloud_account?form=auto_update_remind   operation=read
status?form=internet   operation=read
time?form=settings   operation=read
firmware?form=auto_upgrade   operation=read
time?form=settings   operation=read
firmware?form=upgrade   operation=read
cloud_account?form=cloud_upgrade   operation=read
status?form=all   operation=read
quick_setup?form=quick_setup   operation=read
cloud_account?form=remind   operation=read
cloud_account?form=check_upgrade   operation=read
status?form=internet   operation=read
status?form=all   operation=read
smart_network?form=game_accelerator   operation=loadDevice
onemesh_network?form=mesh_sclient_list_all   operation=read
```
## Tested on the following firmware
```
Firmware Version: 1.3.2 Build 20210901 rel.68864(5553)
Hardware Version: Archer AX21 v1.20
```
