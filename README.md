# Overview

Barnum-Tracer collects Intel PT traces for use by Barnum-Learner. Together, these two parts form Barnum:
an end-to-end system for anomaly detection.

At a high level, Barnum-Tracer requires the following things:

1. The Barnum KVM hypervisor.

2. A virtual machine to trace.

3. An agent configuration.

4. A job script to execute.

# Setup

## Preparing the Host

Barnum-Tracer currently only supports Linux hosts. Specifically, Debian and Ubuntu have been tested.

Barnum-Tracer uses a modified version of KVM-PT. This can be compiled and installed by going into
the `kAFL` directory and executing the `install.sh` script.

Make sure the kernel you are running is Linux 4.6.2 and `kAFL/qemu-2.9.0` and `kAFL/qemu-2.9.0/x86_64-softmmu`
are in your `PATH` environment variable.

You also need to insert the `nbd` kernel module. As root:

    insmod nbd

Lastly, make sure to install the needed python modules:

    pip install -r requirements.txt

## Preparing the Network

You will need a virtual network to attach virtual machines to. The following is an example of how
to create one. These instructions are executed as root:

    ip link add pt0 type bridge
    ip addr add 192.168.56.1/24 dev pt0
    ip link set pt0 up

The above example created the interface `pt0` and the network `192.168.56.0/24`. If you want virtual machines
on this bridge to be able to access the internet, be sure to enable fowarding and configure your firewall rules
accordingly.

The network we created in this example doesn't have DHCP, so virtual machines will need to be configured with
static IP addresses. Alternatively, you can configure and attach `dnsmasq` to the bridge to assign IP addresses.

## Preparing the Guest

Barnum-Tracer supports Windows and Linux guests. Similar to Cuckoo, the only special step is installing Python,
copying `agent/agent.py`
into the virtual machine, and setting it to run on startup. Once configured, the virtual machine can be powered off.
Unlike Cuckoo, you do not need to take a live snapshot. Barnum-Tracer will handle snapshots and reverting.

## Creating an Agent Configuration

See `agent/example.conf` for an example. It's pretty straight forward. If you created the virtual network `pt0`
from the earlier example, the default configuration will work fine.

## Creating a Job

Job scripts tell the virtual machine agent what to do. See `jobs/example.job` for an example of tracing Acrobat
Reader on a Windows guest. The following is a list of currently supported commands:

* `save <filepath>` -- This should always be the first command. It saves the input sample to `filepath`.

* `async <cmd>` -- Executes `cmd` without blocking.

* `exec <cmd>` -- Executes `cmd` and waits for it to finish before continuing.

* `vmi <process_name> -- Instructs the host to lookup the PID and CR3 for `process_name`. This command must be
executed before the `pt` command can be used.

* `pt` -- Starts tracing. After this, the server will close the connection to the agent, so the commands `vmi`,
`save`, and `pt` can no longer be used.

* `sleep <sec>` -- The agent will sleep for `sec` seconds.

# Usage

See `./run.py --help` for details:

    Usage: run.py [options]
    
    Options:
      -h, --help            show this help message and exit
    
      Tracing Options:
        -a AGENT_CONF, --agent-conf=AGENT_CONF
                            Agent config file (default: agent/example.conf)
        -j JOB, --job=JOB   Job script to run (default: jobs/example.job)
        -v VM, --vm=VM      VM to execute inputs in.
        -l LOG_LEVEL, --log-level=LOG_LEVEL
                            Logging level (0 to 50, default: 20).
    
      Label Options:
        -b, --benign        Mark these inputs as benign for Barnum Learner.
        -m, --malicious     Mark these inputs as malicious for Barnum Learner.
        -e EXTRA_LABEL, --extra-label=EXTRA_LABEL
                            Optional extra label string to mark these inputs with
                            (will appear in info.txt).
