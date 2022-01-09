#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 IBM Corporation
'''

import threading

from keylime.ima.ast import get_FF_HASH, get_START_HASH
from keylime.common.algorithms import Hash
from keylime.ima.file_signatures import ImaKeyrings

class TPMState():
    """ TPMState models the state of the TPM's PCRs """

    def __init__(self):
        """ constructor """
        self.pcrs = {}
        self.hash_alg = {}  # Record the hash algorithm that a given PCR uses
        for pcr_num in range(0, 24):
            self.reset_pcr(pcr_num)

    def init_pcr(self, pcr_num, hash_alg):
        """" Initializes a PCR """
        if pcr_num not in self.hash_alg:
            self.hash_alg[pcr_num] = hash_alg

        if self.pcrs[pcr_num] is None:
            if 17 <= pcr_num <= 23:
                self.pcrs[pcr_num] = get_FF_HASH(self.hash_alg[pcr_num])
            else:
                self.pcrs[pcr_num] = get_START_HASH(self.hash_alg[pcr_num])

    def reset_pcr(self, pcr_num):
        """ Reset a specific PCR """
        self.pcrs[pcr_num] = None

    def get_pcr(self, pcr_num):
        """
        Get the state of a PCR.

        :returns: PCR value or None if not initialized
        """
        return self.pcrs.get(pcr_num, None)

    def used_pcr(self, pcr_num):
        """Check if a PCR was actually requested at least once"""
        return (pcr_num in self.hash_alg) and (self.pcrs[pcr_num] is not None)

    def set_pcr(self, pcr_num, pcr_value):
        """ Set the value of a PCR """
        self.pcrs[pcr_num] = pcr_value


class AgentAttestState():
    """ AgentAttestState is used to support incremental attestation """
    def __init__(self, agent_id):
        """ constructor """

        self.agent_id = agent_id
        self.next_ima_ml_entry = 0
        self.set_boottime(0)

        self.tpm_state = TPMState()
        self.ima_pcrs = set()

        self.ima_keyrings = ImaKeyrings()

        self.reset_ima_attestation()

        self.ima_dm_state = None

    def get_agent_id(self):
        """ Get the agent_id """
        return self.agent_id

    def reset_ima_attestation(self):
        """ Reset the IMA attestation state to start over with 1st entry
            ad start over with learning the keys """
        self.next_ima_ml_entry = 0
        for pcr_num in self.ima_pcrs:
            self.tpm_state.reset_pcr(pcr_num)
        self.set_boottime(0)
        self.ima_keyrings = ImaKeyrings()

    def update_ima_attestation(self, pcr_num, pcr_value, num_ml_entries):
        """ Update the attestation by remembering the new PCR value and the
            number of lines that were successfully processed. """
        self.ima_pcrs.add(pcr_num)
        self.tpm_state.set_pcr(pcr_num, pcr_value)
        self.next_ima_ml_entry += num_ml_entries

    def get_ima_pcrs(self):
        """ Return a dict with the IMA pcrs """
        ima_pcrs_dict = {}
        for pcr_num in self.ima_pcrs:
            # Only output IMA PCRs that were used at least once
            if self.tpm_state.used_pcr(pcr_num):
                ima_pcrs_dict[pcr_num] = self.tpm_state.get_pcr(pcr_num)
        return ima_pcrs_dict

    def set_ima_pcrs(self, ima_pcrs_dict):
        """ Set the values of the given ima_pcrs dict in the tpm_state """
        for pcr_num, pcr_value in ima_pcrs_dict.items():
            self.tpm_state.set_pcr(pcr_num, pcr_value)
        self.ima_pcrs = set(ima_pcrs_dict.keys())

    def get_next_ima_ml_entry(self):
        """ Return the next IMA measurement list entry we want to request from agent """
        return self.next_ima_ml_entry

    def set_next_ima_ml_entry(self, next_ima_ml_entry):
        """ Set the value of the next_ima_ml_entry field """
        self.next_ima_ml_entry = next_ima_ml_entry

    def get_pcr_state(self, pcr_num, hash_alg=Hash.SHA1):
        """ Return the PCR state of the given PCR """
        if not self.tpm_state.used_pcr(pcr_num):
            self.tpm_state.init_pcr(pcr_num, hash_alg)
        return self.tpm_state.get_pcr(pcr_num)

    def get_boottime(self):
        """ Return the boottime of the system """
        return self.boottime

    def set_boottime(self, boottime):
        """ Set the boottime of the system """
        self.boottime = boottime

    def is_expected_boottime(self, boottime):
        """ Check whether the given boottime is the expected boottime """
        return self.boottime == boottime

    def set_ima_keyrings(self, ima_keyrings):
        """ Set the ImaKeyrings object """
        self.ima_keyrings = ima_keyrings

    def get_ima_keyrings(self):
        """ Get the ImaKeyrings object """
        return self.ima_keyrings

    def get_ima_dm_state(self):
        """ Get encoded state of the DmValidator """
        return self.ima_dm_state

    def set_ima_dm_state(self, state):
        self.ima_dm_state = state

class AgentAttestStates():
    """ AgentAttestStates administers a map of AgentAttestState's indexed by agent_id """
    instance = None
    @staticmethod
    def get_instance():
        """ Create and return a singleton AgentAttestState """
        if not AgentAttestStates.instance:
            AgentAttestStates.instance = AgentAttestStates()
        return AgentAttestStates.instance

    def __init__(self):
        """ constructor """
        self.map_lock = threading.Lock()
        self.map = {}

    def get_by_agent_id(self, agent_id):
        """ Get an agent's state given its id """

        with self.map_lock:
            agentAttestState = self.map.get(agent_id)
            if not agentAttestState:
                agentAttestState = AgentAttestState(agent_id)
                self.map[agent_id] = agentAttestState

        return agentAttestState

    def delete_by_agent_id(self, agent_id):
        """ Delete an agent's state given its id """

        with self.map_lock:
            try:
                del self.map[agent_id]
            except KeyError:
                pass

    def add(self, agent_id, boottime, ima_pcrs_dict, next_ima_ml_entry, learned_ima_keyrings):
        """ Add or replace an existing AgentAttestState initialized with the given values """
        agentAttestState = self.get_by_agent_id(agent_id)
        agentAttestState.set_boottime(boottime)
        agentAttestState.set_ima_pcrs(ima_pcrs_dict)
        agentAttestState.set_next_ima_ml_entry(next_ima_ml_entry)
        agentAttestState.set_ima_keyrings(ImaKeyrings.from_json(learned_ima_keyrings))
