# ixy-ci

A CI service to test the [ixy userspace network driver](https://github.com/emmericp/ixy) and its
[derivatives](https://github.com/ixy-languages). The basic idea is spawn three independent VMs which
take on the following roles:

- `pktgen` pushes network packets (with sequence numbers) into network 1
- `fwd` forwards all packets from network 1 to network 2
- `pcap` captures packets from network 2

With this setup we can simultaneously test three applications and make sure that the whole scenario
works correctly by inspecting the captured packets from `pcap`.

While ixy-ci does make sure that the build finishes correctly, you still may want to use ixy-ci in
conjunction with traditional CI services to check builds across a larger variety of OS environments
or to check things like formatting/linting.

## How to test a new repository with ixy-ci
To use ixy-ci you only need to follow these instructions:
- Create a GitHub webhook for your repository (in your repository settings)
    - URL: `http://138.246.233.98:9999/github/webhook`
    - Content type: `application/json`
    - Secret (e.g. `openssl rand -base64 48`); make sure to save this somewhere
    - Events: Issue comments & Pushes
- Securely send your webhook secret to your ixy-ci administrator
- Open a PR adding a `ixy-ci.toml` to your repository (see `ixy-ci.toml.example` for reference)
- Also make sure that your applications match the expected command line interface as described below
- Comment `@ixy-ci test` in your PR until the tests pass :)

### Required command line interface of applications
- `pktgen <pci addr>`
- `fwd <pci addr src> <pci addr dst>`
- `pcap <pci addr> <pcap output file> <stop after n packets>`

## ixy-ci setup instructions
These instructions are only needed when you want to deploy your own instance of ixy-ci.

### OpenStack
- Network `pktgen-fwd`
    - Port `pktgen`
    - Port `fwd-in`
- Network `fwd-pcap`
    - Port `fwd-out`
    - Port `pcap`
- Network require a default subnet for port creation to succeed
- Disable "Port Security" on all ports
- Create a keypair for ixy-ci to SSH into the spawned VMs

### `config.toml`
See config.toml.example for the general format of the `config.toml`. The OpenStack login information
can be extracted from a generated `clouds.yaml`. The only additional information you have to
manually query is the _project domain_. You can do that like this:
```sh
# First retrieve the domain id
openstack --os-cloud openstack project show <project_name>
# Then retrieve the actual domain name
openstack --os-cloud openstack domain show <domain_id>
```

### `clouds.yaml` & OpenStack CLI
Currently you also need to keep a `clouds.yaml` around as we sometimes have to use the OpenStack CLI
tool due to missing APIs in the openstack crate.

### GitHub bot account
ixy-ci requires a GitHub account to post results and to interact with the GitHub API. Any account
should work though we advise to use a dedicated bot account. You need to create a _personal access
token_ (GitHub / Setting / Developer settings) with access to the `public_repo` scope.

### Runner
`cd runner && cargo build --release`
ixy-ci will currently upload the compiled `runner` binary to the spawned VMs (see `remote.rs` for
reasons why this is needed). This should hopefully become obsolete in the future...

## TODO
- Make logs available
- Only allow configured users to start tests (to prevent abuse)
- Do more stuff concurrently once async/await is ready (also trussh instead of libssh2)
- Fix issue where ixy-ci cannot be terminated via ctrl+c after a message has been posted on GitHub
  (related: graceful shutdown?)
- Code documentation
- Track down why OpenStack project domain is required (although OpenStack CLI doesn't need it)

## Future feature plans
- Test on master branch push (+ cronjob?) => endpoint for badges which redirect to shields.io
- Dashboard with status about current job, queue, past results
- Integration with GitHub checks API
