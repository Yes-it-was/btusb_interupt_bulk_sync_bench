# btusb poll_sync Test Bench

Test bench to check btusb poll_sync. Uses two adapters to recreate a race that happens between connection complete and MTU request.

## Symptoms

Bench was made to track down the cause of bugged state in client side GATT tables. The table would become connected and resolved, but be missing attriburtes. It was found that this happens because the MTU request was making it to HCI before the connection complete signal, causing it to be dropped for as an invalid handle. 

This could cause problems to any part of the HCI layer not hardened against out of order delivery between the interfaces. The MTU request/conenction complete is just an easy one to create and happens often in regular use.  

Only appears to be problem on kernels configured for 1000HZ. At 300HZ, the rounding up in poll_sync's delay ensures a delay long enough for the interupt to arrive. At least in the devices I tested.   

## Root Problem

In btusb, poll sync only delays for 1 interval. This is only enough to compensate for the USB polling jitter, not enough to sync the two interfaces. As far as I can tell, this is a problem in the spec. It only says "An interrupt endpoint is used to deliver events in a predictable and timely manner. Event packets can be sent across USB with a known latency." I have tested 3 different devices and "predictable and timely manner" means something different to each.
* An Intel that had actual async and maintained 2 intervals. This is as tight of timing as is possible to guarantee for the interface. Poll sync fails 50% of the time on this device.
* A Realtek that isn't actually async, and always delivers interupt 3.108 to 3.110 ms late. Poll sync falls every time.    
* A MediaTek that always internally delays bulk until interupts have been delivered. Poll sync shouldn't be enabled.  

## Quick Start

In config.ini, set server adapter to the device to be tested. Client adapter doesn't seem to effect test results, it is just needed to send the client requests.  

```sh
# Run the benchmark with default settings from config.ini
./run-bench

```

You can override the target controllers or run multiple attempts directly from the command line:

```sh
./run-bench --attempts 25 --server hci1 --client hci0

```

## Output & Analysis

Captures logs on USB and HCI.

Run folder names and result tables identify the server adapter by its device
name and USB `VID:PID`, for example `7392:c611`. 

Negative USB time means the MTU request arrived before connection complete on the USB bus. Negative HCI time means the packets were allowed though out of order.

Logs and anylsis are saved in logs directory. 
## Warning

**Do not run this on your primary workstation if you rely on Bluetooth.**

The service configuration, PHY selections, and adapter power states are restored
after the test. During the test, the harness repeatedly resets controllers,
restarts the system `bluetooth.service`, changes controller settings, and
disrupts all existing Bluetooth connections on the host system. Pairing records
between the two selected adapters are permanently removed when
`reset_peer_bonds = true`.
