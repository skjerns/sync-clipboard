# sync-clipboard
Synchronize clipboard across several devices using nextcloud as a host.


## usage

first setup your nextcloud login parameters

```
#credentials.json
{
  "url": "https://cloud.host.com",
  "user": "username",
  "app_password": "APP_PASSWORD_FROM_NEXTCLOUD",
  "remote_dir": "/"
}

```

then, start the application on two machines with different hostnames

```
python sync-clip.py hostname
```

