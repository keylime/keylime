# Keylime Roadmap 2023/2024

## Enhancements process

For most features Keylime uses a kubernetes style enhancement system
that is used to manage bigger changes and new features. For details of the
enhancement process, please visit the enhancements [repository](https://github.com/keylime/enhancements).

This document tracks only major changes done to Keylime. 

## User Experience Improvements

Some aspects of Keylime's user experience can be improved: 

* Update the user documentation (https://github.com/keylime/keylime/issues/1035)
* Investigate integration with monitoring systems (e.g. Prometheus)


## Move Keylime to a new Architecture
### Q1/Q2-2024

The main eventloop in Keylime is very focused on TPM based attestation in combination with IMA and Measured Boot.
This has the disadvantage that it is currently not easy to support other forms of claims and evidence 
(e.g. Intel SGX, AMD SEV) and their retrieval via different methods (e.g. push model, one shot attestation).
Moving to a more flexible layered architecture allows us to implement those changes without requiring core changes to Keylime. 

This entails the following aspects:
* Evaluating the use of general policy languages for validation (e.g. Rego or Seedwing) (done for Measured Boot)
* Use common remote attestation terminology (see where the current one differs to the [rats](https://datatracker.ietf.org/wg/rats/about/) one)
* Moving the current validation parts into separate modules: quote validation, IMA validation, static PCR checks, Measured Boot (mostly done)
* Complete the split of the Rust agent into a library and the agent itself

## Changes to the Keylime Core
### Q1/Q2-2024

Besides the architecture changes there are changes planned to the core of Keylime.

* Introduce the concept of "named measured policy", very similar to what already is done to "runtime policies" (IMA). This will require both API and database changes
* Refactoring of verifier and registrar server API implementation
* Add support for "external actions" during the initial registration
* Switch to the Python UEFI event log parser

### Q3/Q4-2024
* Add "named tpm policies", completing the transition on having "policies" as a first-class object in keylime, with a life cycle independent of an agent
* Harden the "Durable Attestation" implementation, taking the feature out of "experimental" status


## Push Model
#### 2024
We are implementing a mode that allows the agents
to push the claims and evidence periodically to the verifier. This has the advantage, that the 
verifier does not need a direct connection to the agents.

Accepted proposal: https://github.com/keylime/enhancements/issues/103

The goal is to have an initial implementation in Q1/Q2 and refine it during Q3/Q4.

## Keylime Operator
### Q1/Q2-2024
There is an ongoing effort of integrating Keylime with Kubernetes/Openshift: https://github.com/keylime/attestation-operator

* Enable a full CI/CD
* Full support for multi-verifier and multi-registrar
* Initial implementation of CRD to represent generic (i.e., runtime/IMA, measured boot and even tpm) keylime policies
* Agent scheduler
* Agent policy selector


### Q3/Q4-2024
* Map "named policies" model to CRDs
* Implement verifier-driven status updates


## Improved Quote Validation
Remove the need for “atomic quotes”, add clock validation and validate all IMA data first before validating content.
Also done after the architecture change.

Proposal: https://github.com/keylime/enhancements/issues/103
