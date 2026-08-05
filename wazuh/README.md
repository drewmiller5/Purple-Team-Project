# Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Run the certificate creation script:
```
$ docker-compose -f generate-indexer-certs.yml run --rm generator
```

**Do not commit the generated private keys.** `root-ca.key` and
`root-ca-manager.key`, plus every `*-key.pem` file (`admin-key.pem`,
`wazuh.manager-key.pem`, `wazuh.indexer-key.pem`, `wazuh.dashboard-key.pem`)
under `config/wazuh_indexer_ssl_certs/`, are no longer tracked in git
(`*.key` and `*-key.pem` are both in the repo's `.gitignore`) -- this step
regenerates all of them locally, and each clone/deploy should run it and
get its own root CA and per-service keys rather than reuse someone else's
key material. The corresponding `*.pem` certificate files (not `-key.pem`)
are plain certs, not secrets, and stay committed so a fresh clone has a
working, internally-consistent cert bundle without needing to regenerate
before first boot.

2b) Generate the agent-enrollment pre-shared key (Task 8 / H7 / H48):
```
$ openssl rand -hex 32 > wazuh/config/wazuh_cluster/authd.pass
```
This file is gitignored (same treatment as the SSL private keys above) and
bind-mounted into both `wazuh.manager` (as `etc/authd.pass`, read by
`wazuh-authd` because `wazuh_manager.conf` sets
`<use_password>yes</use_password>`) and `target` (read by `entrypoint.sh` to
supply `agent-auth -P`). A fresh clone must generate this file before first
boot, or `target`'s agent enrollment will fail closed (empty password) even
though the containers will still start.

2c) Set the Wazuh indexer/API/dashboard credentials in `.env` -- see
`.env.example` for the three `WAZUH_*_PASSWORD` variables and how to
regenerate `wazuh/config/wazuh_indexer/internal_users.yml`'s matching
bcrypt hashes when rotating them (Task 8 / H7 / H48).

`config/wazuh_dashboard/wazuh.yml`'s manager-API password is templated in
automatically from `WAZUH_API_PASSWORD` at container start (see
`config/wazuh_dashboard/entrypoint.sh`) -- the committed file only ever
holds an inert placeholder, never edit it directly.

3) Start the environment with docker-compose:

- In the foregroud:
```
$ docker-compose up
```
- In the background:
```
$ docker-compose up -d
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.
