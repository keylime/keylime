#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 IBM Corporation
'''

import threading

from keylime.ima_ast import START_HASH, FF_HASH

class TPMState():
    """ TPMState models the state of the TPM's PCRs """
    def __init__(self):
        """ constructor """
        self.pcrs = {}
        for pcr_num in range(0, 24):
            self.reset_pcr(pcr_num)

    def reset_pcr(self, pcr_num):
        """ Reset a specific PCR """
        if 17 <= pcr_num <= 23:
            self.pcrs[pcr_num] = FF_HASH
        else:
            self.pcrs[pcr_num] = START_HASH

    def get_pcr(self, pcr_num):
        """ Get the state of a PCR """
        return self.pcrs[pcr_num]

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

        self.reset_ima_attestation()

    def get_agent_id(self):
        """ Get the agent_id """
        return self.agent_id

    def reset_ima_attestation(self):
        """ Reset the IMA attestation state to start over with 1st entry """
        self.next_ima_ml_entry = 0
        for pcr_num in self.ima_pcrs:
            self.tpm_state.reset_pcr(pcr_num)
        self.set_boottime(0)

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

    def get_pcr_state(self, pcr_num):
        """ Return the PCR state of the given PCR """
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

        self.map_lock.acquire()
        agentAttestState = self.map.get(agent_id)
        if not agentAttestState:
            agentAttestState = AgentAttestState(agent_id)
            self.map[agent_id] = agentAttestState
        self.map_lock.release()

        return agentAttestState

    def delete_by_agent_id(self, agent_id):
        """ Delete an agent's state given its id """

        self.map_lock.acquire()
        try:
            del self.map[agent_id]
        except KeyError:
            pass
        self.map_lock.release()

    def add(self, agent_id, boottime, ima_pcrs_dict, next_ima_ml_entry):
        """ Add or replace an existing AgentAttestState initialized with the given values """
        agentAttestState = self.get_by_agent_id(agent_id)
        agentAttestState.set_boottime(boottime)
        agentAttestState.set_ima_pcrs(ima_pcrs_dict)
        agentAttestState.set_next_ima_ml_entry(next_ima_ml_entry)
