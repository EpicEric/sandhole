# Admin interface

Sandhole comes with a command-line admin interface available through SSH, which displays information about the system, as well as specific connections. In order to access it, you must be a [user with admin credentials](./configuration.md#adding-users-and-admins).

To access it, simply run the command:

```bash
ssh -t sandhole.com -p 2222 admin
```

where `sandhole.com` is your hostname and `2222` is Sandhole's SSH port.

![A terminal screenshot showing the "Sandhole admin" interface, displaying the HTTP services currently running.](./admin_interface.png)
