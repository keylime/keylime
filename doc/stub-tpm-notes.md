# Stubbed TPM and vTPM Notes

Keylime offers stubbing functionality for both the TPM and vTPM, allowing you to simulate the behavior (including timings) of a real TPM. Canned values have been provided with Keylime, but it is also possible to generate your own canned values (allowing customization of timings and responses for a specific TPM architecture).

## Enabling Stubbed TPM and/or vTPM Modes

Stubbing can be easily accomplished by modifying some variables in your `keylime/common.py` file.

### TPM Stubbing

Changing the `STUB_TPM` variable to 'True', for instance, will stub out functionality of the TPM and cause Keylime to use canned values instead of communicating with a TPM.  When `STUB_TPM` mode is enabled, *a canned values file is also required to be specified* using the `TPM_CANNED_VALUES_PATH` variable.  You can find sample canned values in the `test-data/` folder.

For example:
````python
STUB_TPM=True
TPM_CANNED_VALUES_PATH=/home/test/keylime/test-data/tpm-inputs.txt
````

Since the canned values also include timings from the TPM, an artificial delay will also be inserted to simulate the amount of time the TPM takes to respond (of course this is dependent on the TPM used to generate the canned values).

### vTPM Stubbing

Functionality for a stubbed vTPM is also possible with Keylime, and can be enabled by changing the `STUB_VTPM` variable to 'True' and specifying a canned values file.

For example:
````python
STUB_VTPM=True
TPM_CANNED_VALUES_PATH=/home/test/keylime/test-data/vtpm-inputs.txt
````

Note that stubbing out vTPM functionality will automatically stub out TPM functionality (in other words, `STUB_VTPM` = True implies `STUB_TPM` = True).

## Saving Canned Values

If you are interested in canning your own TPM values, then this can also be done in Keylime by specifying a `TPM_CANNED_VALUES_PATH` file, but *turning off TPM/vTPM stubbing*.

For example:
````python
STUB_TPM=False
STUB_VTPM=False
TPM_CANNED_VALUES_PATH=/home/test/keylime/test-data/custom-inputs.txt
````

You can then run the unit and integration tests in Keylime (see `test/run_tests.sh`) to kick off the generation process.  You can also manually run Keylime with your desired workload, which will also result in canned values being saved.

Note that only requests that are actually made to the TPM will be canned and saved, so your workload must include everything that you need for stubbing out.  If you need vTPM functionality, then the workload you run while canning must include all necessary vTPM requests.

Also note that timings are based on the time it took your TPM to respond to requests during canning; if you generate canned values using an emulated TPM, then the timings that are saved will probably not be indicative of a real, physical TPM (since the timings are based on an emulated TPM).

### Special notes for vTPM canning

For help with running a vTPM workload for the canning process, please refer to [doc/xen-vtpm-notes.md#running-keylime-with-vtpms](xen-vtpm-notes.md#running-keylime-with-vtpms).

In particular, note that you will need to collect canned inputs from both the *linux-vtpmmgr* and *linux-keylime* domains, and then append the two files to each other.  This will allow you to catch both the vTPM initialization and execution of Keylime in your canned inputs file.

## Benchmarking the TPM

If you are only interested in benchmarking TPM queries, then you can instead choose to only output timing data.  This can be done by setting the `TPM_BENCHMARK_PATH` variable in `keylime/common.py` to 'True' (with stubbing disabled).

For example:
````python
STUB_TPM=False
STUB_VTPM=False
TPM_BENCHMARK_PATH=/home/test/keylime/test-data/tpm-benchmark.txt
````

The resulting file will include every request made to the TPM along with the amount of time the TPM took to respond, as well as other relevant information (number of lines returned by the TPM, etc.)
