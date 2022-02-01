# AX21RestClient

With the help of this project you can do rest calls to your TP Link AX21/1800 router.
It has encrypted API so it is impossible to directly call and use it rest api.

I needed to check internet conectivity from a host within a local network  and reboot the router since it has a tendency to not get dynamic ip after power outeges.

I got inspired by the work of Oriol Castejón https://the-hyperbolic.com/posts/hacking-the-tlwpa4220-part-3/
Archer AX21 is newer then the router used in the mentioned post. It uses two RSA keys and one AES compared to  the previous one mentioned in the post.



##Basic Usage
```
restClient = RouterRestClient('192.168.0.1', 'router password')
restClient.get_rsa_keys()
restClient.login()
restClient.reboot()
restClient.logout()
```