# Databases

DockPanel runs each managed database in its own Docker container, deliberately
isolated from everything else on the box. That isolation is the reason most
questions about databases have surprising answers, so this guide leads with it.

## The one thing to know first

**A database owned by a Site is reachable from the server itself, and from
nothing else.** (A database owned by a Stack is different — see
[Databases owned by a Stack](#databases-owned-by-a-stack) below.)

Two mechanisms put a site-owned database there, and they are both on purpose:

- The container's port is published on the host's **loopback address only**, so
  nothing off-box can reach it.
- The container sits on a bridge network with **container-to-container traffic
  switched off**, so nothing in another container can reach it either.

The practical consequence catches almost everyone once: **a database GUI running
in its own container cannot connect to a site-owned managed database.** Not with
the internal host, not with `127.0.0.1`, not with any value you can type. Inside
that GUI's container, `127.0.0.1` is the GUI itself.

This is not a misconfiguration and it is not something to work around lightly. It
is what stops a compromised container from reaching another tenant's data — every
site-owned database container shares this one bridge, so keeping it ICC-off is
what keeps them from reaching each other too.

## Engines

| Engine | Image | Shown in the panel as |
|--------|-------|-----------------------|
| PostgreSQL | `postgres:16` | PostgreSQL 16 |
| MariaDB | `mariadb:11` | MariaDB 11 |
| MySQL | `mariadb:11` | — |

Choosing **MySQL** gives you **MariaDB**. They are wire-compatible for ordinary
application use, but if you depend on a MySQL-specific feature, know that you are
talking to MariaDB.

Redis and MongoDB are **not** managed database engines. They exist only as
one-click app templates, which means none of this guide applies to them — no
managed credentials, no SQL browser, no automatic cleanup.

## Reading the credentials panel

Open **Databases**, pick a database, and open its credentials. Six fields, and
two of them mean less than they look like they mean.

- **Host** — always `127.0.0.1`. Works from a shell on the machine running the
  database container. Not from another container, not from off-box.
- **Port** — the **host-published** port, allocated per database. It is not the
  in-container port, so it is not 3306 or 5432. MariaDB and MySQL databases are
  allocated from 3307 upward and PostgreSQL from 5433 upward.
- **Database** and **Username** — both are the database's name.
- **Password** — masked on screen, copied in clear text by the copy button, and
  also embedded in the connection string shown above the fields. Treat that
  connection string as a secret.
- **Internal Host** — `dockpanel-db-<name>`, which is the **Docker container's
  name**. Use it with `docker exec`, `docker logs`, or the DockPanel CLI. It is
  not a hostname you can connect to from anywhere.

## Connecting to a database

**From a site on the same server** — use `127.0.0.1` and the published port. This
is the supported path and the one the WordPress installer uses. A site's PHP,
Node or Python process runs on the host, not in a container, so the loopback
publish is reachable to it.

**From your own machine** — tunnel over SSH, the always-available path:

```bash
ssh -L 5433:127.0.0.1:<port> root@your-server
# then point your local client at 127.0.0.1:5433
```

…or enable **remote access**, which publishes the database on a public TCP port
through nginx's stream module — see below.

**From a container** — not possible for a **site-owned** managed database. If you
need a containerised tool to reach one, either run a plain database container
**inside the same compose stack** as the tool (services in one stack share a
network and resolve each other by service name), or provision a **Stack-owned
managed database** instead — see below, which gives you the panel's own
credentials, backups and SQL browser while staying reachable by name from that
stack's own containers.

### Adminer, phpMyAdmin, and the other GUI templates

The app catalogue includes database GUIs. They work against a **Stack-owned**
managed database (see below) if deployed into the same stack, or against a plain
database container you run in your own stack. They do **not** work against a
**site-owned** managed database, for the reasons at the top of this guide —
pointing one at a site-owned database will fail no matter what you type.

### Remote access over TCP

Every managed database can also be published on a public port with the **Remote**
button in the database list. What that does, in order:

- nginx (the same public ingress that serves your sites) gains a `stream`
  listener on a port from the managed pool **40000–44999**, forwarding to the
  container's *existing* `127.0.0.1` binding — the Docker publish never becomes
  public, and no container is recreated.
- The firewall is opened for that port and closed again when you disable it.
- The panel shows the address to connect to (`server-ip:port`) next to the
  Remote button and in the panel it opens.

Enabling is per-database and per-owner: tenants can publish only their own
databases, and a second enable on the same database is refused rather than
silently re-pointed. Disabling removes the listener, the firewall rule and the
panel record; deleting the database (or its owning site/stack) takes the
listener down with it.

**TLS is optional.** With "Terminate TLS" checked, the listener expects a TLS
handshake before it proxies a byte, using a certificate from the panel's
certificate registry (`Settings → Certificates`); pick one your account owns.
Only enable it if your client actually speaks TLS to the database — for
PostgreSQL that means `sslmode=require` and friends, for MySQL `--ssl-mode`.
Plain TCP remains the default because most clients talk to these engines in
the clear.

**It is still a public port.** Anyone who can reach it can attempt to log in,
so use it for tools, not as a substitute for the SSH tunnel when a tunnel
suffices — and consider the firewall if the port should only answer one
office address.

## Generic TCP forwards

Admins can also forward any other TCP service through the same mechanism on the
**TCP Proxies** page: a name, an upstream `host:port`, an optional TLS
certificate. Those rows appear here too (kind `database` vs `generic`), but a
database's own listener stays managed from this page.

## Databases owned by a Stack

A database can also be provisioned against a **Docker Stack** instead of a Site
— for a containerised app that needs a real, panel-managed database (credentials,
backups, the SQL browser) without a site to attach it to. Pick **"Owned by a
Stack"** on the Create Database form.

This is deliberately **not** available for a bare, single-container Docker App —
only for a Stack (a multi-container compose deployment). Docker Apps have no
database row of their own in the panel at all; extending that would be a bigger
change than provisioning a database for something that already does.

**Stacks are admin-only**, so this option only appears for an administrator, and
only once at least one stack exists to pick from.

The container joins **that stack's own private network** — the same one its
other services already use to resolve each other by name — instead of the shared,
inter-container-communication-disabled bridge a site-owned database uses. That
means, unlike a site-owned database, **a Stack-owned database IS reachable by
name from the stack's own containers**: point your app at the database's name
(shown as **Internal Host** in its credentials panel) and the port it listens on
inside the container (5432 for PostgreSQL, 3306 for MariaDB/MySQL) — no extra
networking to configure. It is not reachable from outside that stack, the same
way a site-owned database is not reachable from outside the host.

Everything else works identically to a site-owned database: the SQL browser,
credential reset, backups, and Import. Deleting the stack deletes its databases
along with it — the panel tears down the database container as part of removing
the stack, the same as it does the stack's other containers.

## The built-in SQL browser

**Databases → your database** gives you a table browser, a schema view and a
query runner. It reaches the database by running the client *inside* the database
container, which is why it works when a networked client would not.

Its limits are real and worth knowing before you rely on it:

| Limit | Value | What happens when you hit it |
|-------|-------|------------------------------|
| Rows returned | 1000 | Result is truncated and labelled as truncated |
| Query time | 15 seconds | Query is cancelled |
| Output size | 5 MB | **Query fails** — it does not truncate |
| Query length | 10 KB | Rejected before running |
| Paging | none | Table browsing is a fixed first 100 rows |

The output cap is the one that surprises people: a wide `SELECT *` can fail
outright rather than returning the first 1000 rows. Select the columns you need.

**The query runner is not read-only.** You are connected as the database's owner,
so `UPDATE`, `DELETE` and `DROP` all execute. There is no confirmation step.

Access is by **ownership**, not by role: whoever owns the site (or, for a
Stack-owned database, the stack) owns its databases. An administrator who does
not own the site does not get access to its SQL browser through this route —
Stack ownership is moot here in practice, since only an administrator can own a
stack in the first place.

## Backups

Managed databases are included in the backup system, and a database can be backed
up on its own from **Backup Manager**. Restoring replaces the database's contents.

## Importing a dump you already have

**Databases → Import** loads a `.sql.gz` you put on the server yourself. It replaces
data in the target database, so it asks before it runs.

**It is administrator-only**, and that is a security boundary rather than a policy
preference. The dump directory is named after the database, and a database name can be
reused: deleting a database removes its container but not its dumps, so a directory can
outlive the database that filled it. Restricting the door to administrators means a
tenant who creates a database with a previously-used name cannot read what the previous
holder left behind. It costs nothing in practice — placing a file in that directory needs
root on the server, and an administrator can already read `/var/backups` directly.

The panel does not accept the dump through the browser, and that is deliberate
rather than an omission. An upload travels base64-encoded inside a JSON request
body capped at 2 MiB, which works out to about 1.5 MB of file — see
[Getting files onto a site](file-uploads.md). Almost no real dump fits inside
that, so the panel uses the same shape the Migration wizard has always used:
**you place the file, the panel takes its name.**

Copy it into the database's own backup directory, over SSH, as root:

```bash
mkdir -p /var/backups/dockpanel/databases/mydb
scp mydb.sql.gz root@server:/var/backups/dockpanel/databases/mydb/
chmod 600 /var/backups/dockpanel/databases/mydb/mydb.sql.gz
```

Then open **Databases → Import** and pick it from the list.

A few things that are easy to get wrong, and what the panel does about each:

- **The directory may not exist yet.** It is created the first time a database is
  backed up, so for a database that has never been backed up you have to
  `mkdir -p` it. It is root-owned and re-tightened to `0700` every time the agent
  starts, so a file placed there by a non-root account will not be readable.
- **`/tmp` will not work.** The agent runs with a private `/tmp` and cannot see
  the host's — the same constraint the Migration wizard documents.
- **The dump must be gzipped.** A SQL database imports `.sql.gz` and nothing else,
  because the restore path streams the file through `gunzip` straight into the
  database container. A plain `.sql` is **listed anyway**, greyed out, with the exact
  `gzip` command that fixes it — it is not silently ignored, which is what used to
  happen.
- **Encrypted panel backups are not imported here.** A `.enc` file in that
  directory is one the panel took and encrypted with a key derived from its own
  secret, so **Backup Manager** is the door that can restore it. Import lists them
  and says so rather than offering a button that could only fail.
- **`.archive.gz` is MongoDB's format.** On a PostgreSQL or MariaDB database it is
  listed but not offered, because feeding it to `psql` fails deep inside a
  decompression pipe rather than at the door.
- **A name with a space in it will not work.** `scp "my dump.sql.gz" …` produces one,
  and backup filenames may contain letters, digits, dash, underscore and dot only. Such
  a file is listed with the exact `mv` command that renames it.
- **Do not import a file that is still being copied.** `scp` writes to the final name
  as it goes, so a half-copied dump looks complete in the listing. Wait for the copy to
  finish before you press Import.
- **A large import can outlast the page.** The panel stops waiting after 270
  seconds, because its own request timeout is 300. If that happens it says so and
  tells you the import is still running — it does **not** report a failure, and
  you should not start it again. Watch the tables to see it finish. Behind
  Cloudflare's proxy the cut comes earlier, at 100 seconds; the panel recognises that
  case too and says the same thing.

The import streams the file into the container and never buffers it in memory, so
size is a matter of time rather than RAM.

If the import itself fails — a truncated dump, a dump for a different engine, SQL the
database rejects — you get the database's own error message, not an incident reference.
That is worth stating because it was not true of the restore path before v2.138.0.

The same door is available on the command line:

```bash
dockpanel backup db-list mydb        # shows importable dumps, and rejected ones with the reason
```

## What is not built

Being explicit, so you do not go looking:

- **No database GUI that works against a site-owned managed database from a
  container.** Covered above; this is a design decision, not a gap.
- **No managed database for a bare, single-container Docker App.** Only Sites
  and Stacks can own one — see [Databases owned by a Stack](#databases-owned-by-a-stack).
  If you want a standalone database for a plain Docker App, run it in the app's
  own compose stack, or convert the app to a Stack first.
- **No cross-server database access.** A database is reachable on the machine
  that runs it.
