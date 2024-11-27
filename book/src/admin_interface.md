# Admin interface

Sandhole comes with a barebones command-line admin interface available through SSH. In order to access it, you must be a [user with admin credentials](./configuration.md#adding-users-and-admins).

To access it, simply run the command:

```shell
ssh -t server.com -p 2222 admin
```

where `server.com` is your hostname and `2222` is Sandhole's SSH port.

![A terminal screenshot showing the "Sandhole admin" interface, displaying the HTTP services currently running.](./admin_interface.png)
