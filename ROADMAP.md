# Keylime Roadmap 2020/2021

## Enhancements process

Keylime is in the process of implementing a kubernetes style enhancement system
that will be used to manage the projects on going Roadmap. For details of the
enhancement process, please visit the enhancements [repository](https://github.com/keylime/enhancements)

Until this work is complete we will collate our project roadmap here.

## Rust Agent
#### End of Q4-2020

The Keylime agent is being ported to Rust Lang. This decision was made based on
several reasons:

* Rust is statically linked and does not require the ability to retrieve
  dependencies. (Important for non internet connected machines or immutable read
  only operating systems)
* Rust can be more performant and generally requires less resources.
* Rust provides strong safety guarantees (memory safe).

For further details of development, please consult the [rust-keylime](https://github.com/keylime/rust-keylime)
repository

## Multi Tenancy and Federation
#### End of Q1-2021
Keylime is at present monolithic in that there is no concept of multi tenancy in
the form of groups, users and permission based access control of Keylime agents.

This roadmap item will set the foundation for developing Keylime into a multi
tenant capable system with an authorization framework that will allow
Federation over multi keylime verifiers

Further details can be [found here](https://github.com/lukehinds/enhancements/blob/master/7_multi-tenancy.md)

## Persist verifier monitoring after restarts
#### End of Q1-2021

Agent will proceed with its former operation state should the machine be
forcefully or gracefully brought offline for a significant amount of time
(greater than the value set for retry handlers)

Further details can be [found here](https://github.com/lukehinds/enhancements/blob/master/1_persist_agent_restart.md)

## Github Actions
#### End of Q4-2020

Migrate from travis to GitHub Actions

Further details can be [found here](https://github.com/keylime/enhancements/issues/18)

## Measurement list format and retrieval system
#### End of Q4-2020

This enhancement proposes a way to allow Keylime to automatically
import IMA Allow-Lists from external sources. These allow-lists will
follow a prescribed JSON format that allows the `keylime_tenant` to
download, cryptographically verify and then upload these lists to the
verifier. This will be done in versioned manner to allow upgrades and
extensions in the future.

Further details can be [found here](https://github.com/keylime/enhancements/issues/16)

## vTPM support and container based integrity measurement.
#### End of Q2-2021 (TBD)

We are working with the Kernel community to develop an IMA Namespace to allow us
to measure within a container by means of a Virtual TPM. At present we have not
agreed a specific design, as this would be contingent upon the upstream
implementation.
