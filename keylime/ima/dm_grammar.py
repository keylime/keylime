# The grammar is based on: https://www.kernel.org/doc/html/v5.15/admin-guide/device-mapper/dm-ima.html
DM_GRAMMAR = r"""
// Rules are prefixed with name to allow the LALR parser to work
?start: "dm_table_load" load_event | "dm_device_resume" resume_event |  "dm_device_remove" remove_event
       | "dm_target_update" update_event | "dm_table_clear" clear_event | "dm_device_rename" rename_event

load_event: dm_version ";" device_metadata ";" targets

rename_event: dm_version ";" device_metadata ";" rename_new_name "," rename_new_uuid  ";" current_device_capacity ";"

update_event: dm_version ";" device_metadata ";" target

rename_new_name: "new_name=" STRING
rename_new_uuid: "new_uuid=" optional_string
resume_event: dm_version ";" device_metadata ";" resume_optional ";" current_device_capacity ";"
resume_optional: active_table_hash | resume_no_data
resume_no_data: "device_resume=no_data" -> no_data

remove_event: dm_version ";" remove_optional  remove_all ";" current_device_capacity ";"
remove_optional: device_active_metadata ";" device_inactive_metadata ";" active_table_hash ";" inactive_table_hash ","
                | device_active_metadata ";" active_table_hash ","
                | device_inactive_metadata ";" inactive_table_hash ","
                | remove_no_data ";"
remove_no_data: "device_remove=no_data" -> no_data


clear_event: dm_version ";" clear_optional ";" current_device_capacity ";"
clear_optional: device_metadata ";" inactive_table_hash | device_name "," device_uuid ";" clear_no_data
clear_no_data: "table_clear=no_data" -> no_data

device_active_metadata: "device_active_metadata=" device_metadata
device_inactive_metadata: "device_inactive_metadata=" device_metadata
remove_all: "remove_all=" STRING

current_device_capacity: "current_device_capacity=" NUMBER
active_table_hash: "active_table_hash=" STRING
inactive_table_hash: "inactive_table_hash=" STRING

dm_version: "dm_version=" version_nb
device_metadata: device_name ","  device_uuid "," device_major "," device_minor "," device_minor_count "," device_num_targets
device_name: "name=" STRING
device_uuid: "uuid=" optional_string
device_major: "major=" NUMBER
device_minor: "minor=" NUMBER
device_minor_count: "minor_count=" NUMBER
device_num_targets: "num_targets=" NUMBER


targets: target+
target: target_index "," target_begin "," target_len "," target_name "," target_version "," target_attributes ";"
target_index: "target_index=" NUMBER
target_begin: "target_begin=" NUMBER
target_len: "target_len=" NUMBER
target_name: "target_name=" STRING
target_version: "target_version=" version_nb
target_attributes: verity_attributes | cache_attributes | crypt_attributes | integrity_attributes | linear_attributes | snapshot_attributes | mirror_attributes

// verity specific target attributes
verity_attributes: verity_hash_failed "," verity_verity_version "," verity_data_device_name "," verity_hash_device_name "," verity_verity_algorithm "," verity_root_digest "," verity_salt "," verity_ignore_zero_blocks "," verity_check_at_most_once ("," verity_root_hash_sig_key_desc)? ("," verity_verity_mode)?
verity_hash_failed: "hash_failed=" STRING
verity_verity_version: "verity_version=" NUMBER
verity_data_device_name: "data_device_name=" STRING
verity_hash_device_name: "hash_device_name=" STRING
verity_verity_algorithm: "verity_algorithm=" STRING
verity_root_digest: "root_digest=" STRING
verity_salt: "salt=" STRING
verity_ignore_zero_blocks: "ignore_zero_blocks=" yes_no
verity_check_at_most_once: "check_at_most_once=" yes_no
verity_root_hash_sig_key_desc: "root_hash_sig_key_desc=" STRING
verity_verity_mode: "verity_mode=" STRING

// cache specific target attributes
cache_attributes: cache_metadata_mode "," cache_cache_metadata_device "," cache_cache_device "," cache_cache_origin_device "," cache_writethrough "," cache_writeback "," cache_passthrough "," cache_metadata2 "," cache_no_discard_passdown
cache_metadata_mode: "metadata_mode=" STRING
cache_cache_metadata_device: "cache_metadata_device=" STRING
cache_cache_device: "cache_device=" STRING
cache_cache_origin_device: "cache_origin_device=" STRING
cache_writethrough: "writethrough=" yes_no
cache_writeback: "writeback=" yes_no
cache_passthrough: "passthrough=" yes_no
cache_metadata2: "metadata2=" yes_no
cache_no_discard_passdown: "no_discard_passdown=" yes_no


// crypt specific target attributes
crypt_attributes: crypt_allow_discards "," crypt_same_cpu_crypt "," crypt_submit_from_crypt_cpus "," crypt_no_read_workqueue "," crypt_no_write_workqueue "," crypt_iv_large_sectors ("," crypt_integrity_tag_size)? ("," crypt_cipher_auth)?  ("," crypt_sector_size)? ("," crypt_cipher_string)? "," crypt_key_size "," crypt_key_parts "," crypt_key_extra_size "," crypt_key_mac_size
crypt_allow_discards: "allow_discards=" yes_no
crypt_same_cpu_crypt: "same_cpu_crypt=" yes_no
crypt_submit_from_crypt_cpus: "submit_from_crypt_cpus=" yes_no
crypt_no_read_workqueue: "no_read_workqueue=" yes_no
crypt_no_write_workqueue: "no_write_workqueue=" yes_no
crypt_iv_large_sectors: "iv_large_sectors=" yes_no
crypt_integrity_tag_size: "integrity_tag_size=" INT 
crypt_cipher_auth: "cipher_auth=" STRING
crypt_sector_size: "sector_size=" INT
crypt_cipher_string: "cipher_string=" STRING
crypt_key_size: "key_size=" INT
crypt_key_parts: "key_parts=" INT
crypt_key_extra_size: "key_extra_size=" INT
crypt_key_mac_size: "key_mac_size=" INT


// integrity 
integrity_attributes: integrity_dev_name "," integrity_start "," integrity_tag_size "," integrity_mode ("," integrity_meta_device)?  ("," integrity_block_size)?  "," integrity_recalculate "," integrity_allow_discards "," integrity_fix_padding "," integrity_fix_hmac "," integrity_legacy_recalculate "," integrity_journal_sectors "," integrity_interleave_sectors "," integrity_buffer_sectors
integrity_dev_name: "dev_name=" STRING
integrity_start: "start=" INT
integrity_tag_size: "tag_size=" INT
integrity_mode: "mode=" STRING // This could be replaced with "J" | "B" | "D" | "R", but is not done to keep the Tranformer simple
integrity_meta_device: "meta_device=" STRING
integrity_block_size: "block_size=" STRING
integrity_recalculate: "recalculate=" yes_no
integrity_allow_discards: "allow_discards=" yes_no
integrity_fix_padding: "fix_padding=" yes_no
integrity_fix_hmac: "fix_hmac=" yes_no
integrity_legacy_recalculate: "legacy_recalculate=" yes_no
integrity_journal_sectors: "journal_sectors=" INT
integrity_interleave_sectors: "interleave_sectors=" INT
integrity_buffer_sectors: "buffer_sectors=" INT


// linear
linear_attributes: linear_device_name "," linear_start
linear_device_name: "device_name=" STRING
linear_start: "start=" STRING

// mirror
mirror_attributes: mirror_nr_mirrors  mirror_mirror_device_data ","  mirror_handle_errors "," mirror_keep_log "," mirror_log_type_status
mirror_nr_mirrors: "nr_mirrors=" INT
mirror_mirror_device_data: mirror_mirror_device_row  | mirror_mirror_device_data mirror_mirror_device_row // Do explicit left recursion becaus otherwise the LALR parser breaks 
mirror_mirror_device_row: ("," mirror_mirror_device_name ","  mirror_mirror_device_status)
mirror_mirror_device_name: "mirror_device_" INT "=" STRING  // The INT gets removed by the Transformer
mirror_mirror_device_status: "mirror_device_" INT "_status=" STRING // The INT gets removed by the Transformer
mirror_handle_errors: "handle_errors=" yes_no
mirror_keep_log: "keep_log=" yes_no
mirror_log_type_status: "log_type_status=" optional_string

// TODO: multipath

// TODO: raid

// snapshot
snapshot_attributes: snapshot_snap_origin_name "," snapshot_snap_cow_name "," snapshot_snap_valid "," snapshot_snap_merge_failed "," snapshot_snapshot_overflowed
snapshot_snap_origin_name: "snap_origin_name=" STRING
snapshot_snap_cow_name: "snap_cow_name=" STRING
snapshot_snap_valid: "snap_valid=" yes_no
snapshot_snap_merge_failed: "snap_merge_failed=" yes_no
snapshot_snapshot_overflowed: "snapshot_overflowed=" yes_no


// TODO: striped


// generic rules
?yes_no: "y" -> yes | "n" -> no
optional_string: STRING? 
STRING: /([A-z]|[0-9]|\-|\:)+/
NUMBER: INT
version_nb: INT "." INT "." INT

%import common.INT
%import common.WORD

// the no data entries might produce entries that contain multiple zeros inside the string
ZERO_PADDING: "\x00"+
%ignore ZERO_PADDING
"""
