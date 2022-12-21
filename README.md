
# Nmap API

Uses python3.10, Debian, python-Nmap, and flask framework to create a Nmap API that can do scans with a good speed online and is easy to deploy.

This is a implementation for our college PCL project which is still under development and constantly updating.


## API Reference

#### Get all items

```url
  GET /api/p1/{username}:{password}/{target}
  GET /api/p2/{username}:{password}/{target}
  GET /api/p3/{username}:{password}/{target}
  GET /api/p4/{username}:{password}/{target}
  GET /api/p5/{username}:{password}/{target}
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `username` | `string` | **Required**. username of the current user |
| `password`| `string`|**Required**. current user password|
| `target`| `string`| **Required**. The target Hostname and IP|

#### Get item

```url
  GET /api/p1/
  GET /api/p2/
  GET /api/p3/
  GET /api/p4/
  GET /api/p5/
```

| Parameter | Return data     | Description | Nmap Command |
| :-------- | :------- | :-------------------------------- | :---------|
| `p1`      | `json` | Effective  Scan | `-Pn -sV -T4 -O -F`|
| `p2`      | `json` | Simple  Scan | `-Pn -T4 -A -v`|
| `p3`      | `json` | Low Power  Scan | `-Pn -sS -sU -T4 -A -v`|
| `p4`      | `json` | Partial Intense  Scan | `-Pn -p- -T4 -A -v`|
| `p5`      | `json` | Complete Intense  Scan | `-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln`|


#### Auth and User management

```url
  POST /adduser/{admin-username}:{admin-passwd}/{id}/{username}/{passwd}
  POST /deluser/{admin-username}:{admin-passwd}/{t-username}/{t-userpass}
  POST /altusername/{admin-username}:{admin-passwd}/{t-user-id}/{new-t-username}
  POST /altuserid/{admin-username}:{admin-passwd}/{new-t-user-id}/{t-username}
  POST /altpassword/{admin-username}:{admin-passwd}/{t-username}/{new-t-userpass}
```
* make sure you use the ADMIN CREDS MENTIONED BELOW

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
|`admin-username`|`String`|Admin username|
|`admin-passwd`|`String`|Admin password|
|`id`|`String`|Id for newly added user|
|`username`|`String`|Username of the newly added user|
|`passwd`|`String`|Password of the newly added user|
|`t-username`|`String`|Target username|
|`t-user-id`|`String`|Target userID|
|`t-userpass`|`String`|Target users password|
|`new-t-username`|`String`|New username for the target|
|`new-t-user-id`|`String`|New userID for the target|
|`new-t-userpass`|`String`|New password for the target|

**DEFAULT** **CREDENTIALS**

```ADMINISTRATOR : zAp6_oO~t428)@,```
