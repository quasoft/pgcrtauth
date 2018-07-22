# pgcrtauth

pgcrtauth is a simple cross-platform tool for generation of self-signed certificates for standalone and clustered PostgreSQL servers.

The tool comes handy when you need a self-signed server certificate for tests or development and don't have openssl around.

## How to use

The following two uses cases are currently supported:

1. Generate a self-signed certificate for a single standalone PostgreSQL server:
      
       pgcrtauth generate --hostnames "srv1.company.local,10.0.0.1" --organization "My Company" --common-name "srv1.company.local" --out-dir /certs/srv1/ --self-signed

   or the same command with shorthand flags:

       pgcrtauth generate -H "srv1.domain.local,10.0.0.1" -O "My Company" -C "srv1.domain.local" -o /certs/srv1/ -s

2. Create certificates for servers in a PostgreSQL cluster that are signed by a common certificate authority (CA):

   * The following command creates the `root.crt` and `root.key` files in an empty folder - yours CA:
      
          pgcrtauth init --organization "My Company" --common-name "ClusterCA" --ca-dir /certs/ca/

   * Then generate a certificate signed by "ClusterCA" for each server in the cluster:

          pgcrtauth generate -H "srv1.domain.local,10.0.0.1" -O "My Company" -C "srv1.domain.local" -o /certs/srv1/ --ca-dir /certs/ca/

   * That's it. You can copy the `/certs/ca/root.crt`, `/certs/srv1/server.crt` and `/certs/srv1/server.key` files to the server data directory.
   
      *The tool automatically restricts access to .key files by executing `chmod og-rwe server.key` or `icacls server.key /reset && icacls server.key /inheritance:r /grant:r "CREATOR OWNER:F"`. Make sure to do the same after you transfer the files to the PostgreSQL server*.

### Warning

If you intend to use this tool for anything more than tests and development:

- Use the tool only on a secure offline machine;
- Restrict access to yours `/certs/ca/` directory;
- Keep the `root.key` file only on this offline machine. It's not needed by PostgreSQL;
- Transfer the server certificates (`server.crt` and `server.key`) to the servers via an offline method.

### TODO:

Planned features anyone can contribute to:

- [ ] Always password protect the CA key
- [ ] Support generation of client certificates
- [ ] Add a request subcommand for creation of certificate signing request for external CA.
- [ ] Warn user not to copy root.key to the server after a new CA has been created
- [ ] Warn if creating or using CA on a computer that is running an instance of PostgreSQL
- [ ] Allow customization of commonly used parameters like (eg. Country, State, City, Organization Unit and Email Address).
- [ ] Use Windows API to set file ACL instead of invoking the icacls command