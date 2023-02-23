# Keylime Roadmap 2022/2023

## Enhancements process

For most features Keylime uses a kubernetes style enhancement system
that is used to manage bigger changes and new features. For details of the
enhancement process, please visit the enhancements [repository](https://github.com/keylime/enhancements).

This document tracks only major changes done to Keylime. 

## Removal of the Python Agent
#### Q1-2023

Once the Rust agent is stable the Python agent will be removed in two stages:

1. Add deprecation warning and keep it for one major release
2. Remove the agent from the code with the release of 7.0.0

## User Experience Improvements

Some aspects of Keylime's user experience can be improved: 

* Update the user documentation (https://github.com/keylime/keylime/issues/1035)
* Investigate integration with monitoring systems (e.g. Prometheus)


## Move Keylime to a new Architecture and Refactoring
### Q2/Q3-2023

The main eventloop in Keylime is very focused on TPM based attestation in combination with IMA and Measured Boot.
This has the disadvantage that it is currently not easy to support other forms of claims and evidence 
(e.g. Intel SGX, AMD SEV) and their retrieval via different methods (e.g. push model, one shot attestation).
Moving to a more flexible plugin or layered architecture allows us to implement those changes without requiring core changes to Keylime. 

This entails the following aspects:
* Evaluating the use of general policy languages for validation (e.g. Rego or Seedwing)
* Use common remote attestation terminology (see where the current one differs to the [rats](https://datatracker.ietf.org/wg/rats/about/) one)
* Evaluate the use of a plugin API and runtime specification
* Moving the current validation parts into separate modules: quote validation, IMA validation, static PCR checks, Measured Boot
* Implement the pull model as the default runtime
* General cleanup of the code base: removing the tpm2-tools abstraction layer, cleanup API endpoints
* Complete the split of the Rust agent into a library and the agent itself

## Push Model
#### Q3-2023
Once the new architecture is implemented, we can implement another runtime that allows the agents
to push the claims and evidence periodically to the verifier. This has the advantage, that the 
verifier does not need a direct connection to the agents.

Proposal: https://github.com/keylime/enhancements/issues/60 

## Improved Quote Validation
Remove the need for “atomic quotes”, add clock validation and validate all IMA data first before validating content.
Also done after the architecture change.

Proposal: https://github.com/keylime/enhancements/issues/59 


## IDevID Support
### 2023
IDevID is a standardized way for device identities that are generally deployed by the manufacturer.
This allows Keylime to use this identity for remote attestation.

More details can be found in the proposal: https://github.com/keylime/enhancements/blob/master/81-IDevID_and_IAK_support.md