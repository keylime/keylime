# Keylime Roadmap 2022/2023

## Enhancements process

For most features Keylime uses a kubernetes style enhancement system
that is used to manage bigger changes and new features. For details of the
enhancement process, please visit the enhancements [repository](https://github.com/keylime/enhancements).

This document tracks only major changes done to Keylime. 

## Rust Agent
#### End of Q3-2022
**Status:** mostly complete

The Keylime agent is being ported to Rust Lang. This decision was made based on
several reasons:

* Rust is statically linked and does not require the ability to retrieve
  dependencies. (Important for non internet connected machines or immutable read
  only operating systems)
* Rust can be more performant and generally requires less resources.
* Rust provides strong safety guarantees (memory safe).

For further details of development, please consult the [rust-keylime](https://github.com/keylime/rust-keylime)
repository and the [Rust agent roadmap issue](https://github.com/keylime/keylime/issues/986).

## Removal of the Python Agent
#### End of Q4-2022

Once the Rust agent is stable the Python agent will be removed in two stages:

1. Add deprecation warning and keep it for one major release
2. Remove the agent from the code with the release of 7.0.0

## User Experience Improvements
#### End of Q4-2022

Some aspects of Keylime of the Keylime user experience can be improved: 

* Update the user documentation (https://github.com/keylime/keylime/issues/1035)
* Simplify the TLS setup (https://github.com/keylime/enhancements/pull/73)
* Simplify the configuration (https://github.com/keylime/enhancements/pull/73)
* Remove or rework WebUI
* Investigate integration with monitoring systems (e.g. Prometheus)

## Push Model
#### Q4-2022 or Q1-2023

Instead of the verifier connecting to the agent to retrieve the attestation data, 
the agent can also send this data periodically to the verifier.

Proposal: https://github.com/keylime/enhancements/issues/60 

## Improved Quote Validation
Remove the need for “atomic quotes”, add clock validation and validate all IMA data first before validating content.

Proposal: https://github.com/keylime/enhancements/issues/59 

## Durable Attestation
#### Q4-2022

Attestation "artifacts" (e.g., quotes, IMA logs) collected by the verifier can be optionally written on a "persistent 
time-series like store", allowing a third-party (e.g., an auditor) to assess the state of a given node N at a certain date D, 
far in the past. This functionality will include the use of a "transparency log" to record the association between an given EK and AIK, 
and a new command-line tool (keylime_attest) to perform "offline attestation").

Proposal: https://github.com/keylime/enhancements/pull/76