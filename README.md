# SDN-Project-with-Mininet-and-OpenFlow

This repository contains the implementation of a series of exercises for a Networking course project. The project explores various networking concepts using Mininet and Ryu Controller, focusing on topics such as ARP spoofing, static routing, and VLAN configuration using OpenFlow.

## Table of Contents

1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
   1. [Exercise 1: ARP Spoofing](#exercise-1-arp-spoofing)
   2. [Exercise 2: Static Routing](#exercise-2-static-routing)
   3. [Exercise 3: Static Routing with Two Routers](#exercise-3-static-routing-with-two-routers)
   4. [Exercise 4: VLAN with OpenFlow](#exercise-4-vlan-with-openflow)
3. [Setup and Installation](#setup-and-installation)
4. [Running the Exercises](#running-the-exercises)
5. [Examples and Outputs](#examples-and-outputs)
6. [References](#references)
7. [License](#license)

## Introduction

This project involves the use of the Ryu framework to develop network functionalities within the Mininet network emulator. The exercises focus on ARP spoofing, static routing between LANs, and VLAN implementation using OpenFlow v1.0. The project demonstrates key networking concepts such as packet manipulation, routing, and VLAN management in a software-defined network (SDN) environment.

## Project Structure

### Exercise 1: ARP Spoofing

- **Script:** `arp-spoofing.py`
- **Objective:** To create a switch that intercepts ARP requests and sends appropriate ARP responses, effectively spoofing the ARP reply.
- **Description:**
  - The script sets up a Ryu controller that handles ARP requests by generating and sending ARP replies directly, rather than forwarding the request to the intended recipient. This is achieved by inspecting ARP packets, identifying the request's source and destination, and crafting the correct ARP reply to simulate the behavior of the target host.

### Exercise 2: Static Routing

- **Mininet Script:** `mininet-router.py`
- **Controller Script:** `ryu-router-frame.py`
- **Objective:** To create a static router that interconnects two switches, enabling routing between two LANs.
- **Description:**
  - This exercise extends the basic networking concepts by introducing a static router that interconnects two LANs. The router is responsible for replying to ARP requests for its own interfaces and forwarding packets between the LANs by adjusting the Ethernet headers based on the destination IP addresses. The routing is implemented statically, with the router determining the correct interface and MAC address for each packet based on predefined rules.

### Exercise 3: Static Routing with Two Routers

- **Mininet Script:** `mininet-router-two.py`
- **Controller Script:** `ryu-router-two-frame.py`
- **Objective:** To implement a network topology with two static routers that interconnect two LANs.
- **Description:**
  - This exercise builds on the previous static routing scenario by adding a second router, creating a more complex network topology. Each router manages ARP and IP packets within its LAN and forwards packets to the other LAN via the second router when necessary. This setup requires more advanced routing logic to handle inter-router communication and ensure proper packet delivery across the network.

### Exercise 4: VLAN with OpenFlow

- **Mininet Script:** `mininet-router-vlan.py`, `mininet-router-vlan-extended.py`
- **Controller Script:** `vlan.py`
- **Objective:** To implement VLANs across two interconnected switches and routers using OpenFlow.
- **Description:**
  - VLANs are configured using OpenFlow, with the routers managing inter-VLAN routing and the switches handling VLAN tagging and forwarding. An extended scenario introduces an additional link between the routers to prioritize high-priority traffic using the VLAN tagging and trunking functionality. The script also implements ICMP responses for unreachable destinations, further enhancing the network's robustness.

## Setup and Installation

### Prerequisites

- **Mininet:** Version 2.3.0 or higher
- **Ryu Controller:** Version 4.34 or higher
- **Python:** Version 3.6 or higher
- **Linux Environment:** Required for running Mininet and Ryu

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Garyfgeor/SDN-Project-with-Mininet-and-OpenFlow.git
   cd SDN-Project-with-Mininet-and-OpenFlow
