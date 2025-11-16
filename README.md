# Proxmox Cluster Monitoring Mesh

This application aims to provide a 3rd party way to monitor the status of nodes in a Proxmox cluster. This service runs on every Proxmox host as a systemd unit and allows notifications to be sent when nodes go down. This application is designed in such a way as to generate notifications even if all but a single node are down.

### Current Status
- [x] Bootstrapping
- [ ] Joining
- [ ] Health Checks
- [ ] Notifications
- [ ] mTLS Certificate Revocation List (CRL)
- [ ] Certificate Renewal
- [ ] Keymaster Rotation
- [ ] Node Removal

### The Problem
Currently, the options I am aware of to monitor Proxmox node health are either a full-blown monitoring stack or more simple scripts. While I have a full-blown monitoring stack in my homelab, it runs on Proxmox. Which leads to a chicken-egg problem where if a Proxmox node running the monitoring stack goes down then the monitoring stack can't notify me that a Proxmox node went down.

### The Solution
An application that can run on each Proxmox node and each instance of the application is capable of monitoring all the nodes individually. It does this by having every instance of the application poll every other instance of the application.

### Target Environment
As mentioned, this application was designed with Proxmox clusters in mind. Its conceivable it could be modified to run in different environments. The environment that I plan on deploying it in is a 3-node Proxmox cluster in my homelab.

## Architecture Overview
This application is meant to run in a mesh topology where every instance of the application monitors every other application. 

### Clustering
The application is build to use a self-managing cluster configuration that allows administrators to easily bootstrap new clusters and join additional nodes with minimal hassle. The setup is outlined below. Traffic between nodes is encrypted using mTLS for all joined nodes and the PKI is managed by the first node that is created (the keymaster node), as such it is recommended to run the keymaster on the proxmox node least-likely to go down or be re-provisioned as adding or removing nodes without the keymaster isn't currently supported (possibly a feature for the future).

### Scalability Concerns
Because this app is meant to monitor every other running instance in a Proxmox cluster, its ability to run in Proxmox clusters with many nodes is questionable. As each node connects to all nodes, the number of polling requests scales quadratically with the number of nodes in the cluster ( n(n-1)/2 ).

---
## License
Apache 2.0