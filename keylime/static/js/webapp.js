/* 
 * DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
 *
 * This material is based upon work supported by the Assistant Secretary of Defense for 
 * Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
 * FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in 
 * this material are those of the author(s) and do not necessarily reflect the views of the 
 * Assistant Secretary of Defense for Research and Engineering.
 *
 * Copyright 2017 Massachusetts Institute of Technology.
 *
 * The software/firmware is provided to you on an As-Is basis
 *
 * Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
 * 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
 * rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
 * above. Use of this work other than as specifically authorized by the U.S. Government may 
 * violate any copyrights that exist in this work.
*/

'use strict';

// Make AJAX call to submit events 
function asyncRequest(type, uuid, body, callback) {
    // Need more details before we can do an ADD node 
    if (type == 'POST' && typeof(body) === 'undefined') {
        return addNodeDialog(uuid);
    }
    
    let xmlHttp = new XMLHttpRequest();
    if (typeof(callback) === 'function') {
        xmlHttp.onreadystatechange = function() {
            if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
                callback(xmlHttp.responseText);
            }
            else if (xmlHttp.readyState == 4 && xmlHttp.status == 500) {
                let json = JSON.parse(xmlHttp.responseText);
                if ("results" in json) {
                    alert("ERROR: " + json["results"]);
                }
            }
        }
    }
    
    xmlHttp.open(type, "/v2/nodes/"+uuid, true);
    xmlHttp.send(body);
}

// Default/generic async request callback
function defaultReqCallback(responseText) {}

// Callback for node data requests 
let style_mappings = {
    0 : {"class":"inactive","action":"POST"},
    1 : {"class":"processing","action":"DELETE"}, 
    2 : {"class":"inactive","action":"PUT"}, 
    3 : {"class":"processed","action":"DELETE"}, 
    4 : {"class":"processing","action":"DELETE"},
    5 : {"class":"processed","action":"DELETE"},
    6 : {"class":"processing","action":"DELETE"},
    7 : {"class":"failed","action":"POST"},
    8 : {"class":"inactive","action":"PUT"},
    9 : {"class":"invalid","action":"DELETE"},
}
let STR_MAPPINGS = {
    0 : "Registered",
    1 : "Start",
    2 : "Saved",
    3 : "Get Quote",
    4 : "Get Quote (retry)",
    5 : "Provide V",
    6 : "Provide V (retry)",
    7 : "Failed",
    8 : "Terminated",
    9 : "Invalid Quote"
}
function nodeDataCallback(responseText) {
    let json = JSON.parse(responseText);
    
    // Ensure response packet isn't malformed
    if (!("results" in json)) {
        console.log("ERROR nodeDataCallback: Malformed response for node refresh callback!");
        return;
    }
    let response = json["results"];
    
    // Figure out which instance id we refer to 
    if (!("id" in response)) {
        console.log("ERROR nodeDataCallback: Cannot determine instance id from callback!");
        return;
    }
    let instanceId = response["id"];
    
    // Format address to display 
    let fulladdr = "<i>N/A</i>";
    if ("ip" in response && "port" in response) {
        let ipaddr = response["ip"];
        let port = response["port"];
        fulladdr = ipaddr + ":" + port;
    }
    
    // Format status to display 
    let state = response["operational_state"];
    let stat_str = "<i>N/A</i>";
    if ("operational_state" in response) {
        stat_str = response["operational_state"];
        let readable = STR_MAPPINGS[stat_str];
        stat_str = stat_str + " (" + readable + ")";
    }
    
    let nodeId_short = instanceId.substr(0,8);
    let classSuffix = style_mappings[state]["class"];
    let action = style_mappings[state]["action"];
    
    let node_overview_insert = "" 
            + "<div onclick=\"asyncRequest('" + action + "','" + instanceId + "')\" class='tbl_ctrl_" + classSuffix + "'>&nbsp;</div>"
            + "<div onclick=\"toggleVisibility('" + instanceId + "-det')\" style='display:block;float:left;'>"
            + "<div class='tbl_col_" + classSuffix + "' title='" + instanceId + "'>" + nodeId_short + "&hellip;</div>"
            + "<div class='tbl_col_" + classSuffix + "'>" + fulladdr + "</div>"
            + "<div class='tbl_col_" + classSuffix + "'>" + stat_str + "</div>"
            + "<br style='clear:both;'>"
            + "</div>"
            + "<br style='clear:both;'>"
            
    let node_details_insert = "<div class='tbl_det_" + classSuffix + "'><b><i>Details:</i></b><br><pre>";
    
    // Parse out detailed specs for node 
    for (let stat in response) {
        stat_str = response[stat];
        
        // Make operational state code more human-readable 
        if (stat == "operational_state") {
            let readable = STR_MAPPINGS[stat_str];
            stat_str = stat_str + " (" + readable + ")";
        }
        else if (typeof(stat_str) === "object") {
            stat_str = JSON.stringify(stat_str, null, 2);
        }
        
        node_details_insert += stat + ": " + stat_str + "<br>";
    }
    node_details_insert += "</pre></div>";
    
    // Update node on GUI 
    document.getElementById(instanceId+"-over").innerHTML = node_overview_insert;
    document.getElementById(instanceId+"-det").innerHTML = node_details_insert;
}

// Validate form inputs 
function validateForm(form) {
    
    // Make sure JSON fields are well-formed 
    let jsonFields = document.getElementsByClassName("json_input");
    for (let i = 0; i < jsonFields.length; i++) {
        try {
            let json = JSON.parse(jsonFields[i].value);
            jsonFields[i].style.backgroundColor = "#fff";
        } 
        catch (e) {
            jsonFields[i].focus();
            jsonFields[i].style.backgroundColor = "#f99";
            alert('ERROR: Malformed JSON detected!');
            return false;
        }
    }
    
    return true;
}

// Wrapper to submit Add Node form 
function submitAddNodeForm(form) {
    // Ensure inputs validate 
    if (!validateForm(form)) return;
    
    // Build POST string and send request (generic/default response handler) 
    let data = new FormData(form);
    asyncRequest("POST", form.uuid.value, data, defaultReqCallback);
    
    // Cleanup 
    toggleVisibility('modal_box');
    resetAddNodeForm();
}

// Modal dialog box to add new node (more details needed) 
function addNodeDialog(uuid) {
    document.getElementById('uuid').value = uuid;
    document.getElementById('uuid_str').innerHTML = "("+uuid+")";
    toggleVisibility('modal_box');
}

// When closing modal dialog, reset form 
function resetAddNodeForm() {
    // Overall form reset (puts HTML-input values to defaults) 
    document.getElementById('add_node').reset();
    document.getElementById('uuid').value = '';
    
    // Auto-collapse IMA-related inputs 
    document.getElementById('imalist_block').style.display = 'none';
    document.getElementById('policy_block').style.display = 'none';
    
    // Reset styles for json inputs (in case errors were left) 
    let jsonFields = document.getElementsByClassName("json_input");
    for (let i = 0; i < jsonFields.length; i++) {
        jsonFields[i].style.backgroundColor = "#fff";
    }
    
    // Reset to default tab 
    toggleTabs('0');
    
    // Clear out any uploaded files 
    let droppable = document.getElementsByClassName("file_drop");
    for (let i = 0; i < droppable.length; i++) {
        droppable[i].innerHTML = "<i>Drag payload here &hellip;</i>";
        document.getElementById(droppable[i].id + '_data').value = '';
        document.getElementById(droppable[i].id + '_name').value = '';
    }
}

// Toggle visibility of requested node 
function toggleVisibility(eleId) {
    if (document.getElementById(eleId).style.display != 'block') {
        document.getElementById(eleId).style.display = 'block';
    }
    else {
        document.getElementById(eleId).style.display = 'none';
    }
}

// Switch between payload type tabs 
function toggleTabs(target) {
    switch (target) {
        case '0': // File upload
            document.getElementById('ca_dir_container').style.display = 'none';
            document.getElementById('keyfile_container').style.display = 'none';
            document.getElementById('file_container').style.display = 'block';
            break;
        case '1': // Key file upload
            document.getElementById('ca_dir_container').style.display = 'none';
            document.getElementById('keyfile_container').style.display = 'block';
            document.getElementById('file_container').style.display = 'block';
            break;
        case '2': // CA dir upload
            document.getElementById('ca_dir_container').style.display = 'block';
            document.getElementById('keyfile_container').style.display = 'none';
            document.getElementById('file_container').style.display = 'none';
            break;
    }
}

// Allow drag-drop of payload file(s) without browser propagation 
function dragoverCallback(event) {
    event.stopPropagation();
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
}

// When file dropped onto drop area, prepare as upload 
function fileUploadCallback(event) {
    let target = event.target;
    
    // Bubble up to find the file_drop node 
    if (target.classList.contains) {
        while (!target.classList.contains("file_drop")) {
            target = target.parentNode;
        }
    }
    
    let multi = false;
    if (target.classList.contains("multi_file")) {
        multi = true;
    }
    
    // Don't let event bubble up any farther 
    dragoverCallback(event);
    
    // Ensure a file was given by user 
    let files = event.dataTransfer.files;
    if (files.length == 0) {
        console.log("fileUploadCallback: No files provided!");
        return false;
    }
    
    // Only multi-files can accept multiple files 
    if (files.length > 1 && !multi) {
        console.log("fileUploadCallback: Attempted to upload multiple files in a single upload box!");
        return false;
    }
    
    // Clear out old uploads (just in case) 
    document.getElementById(target.id + '_data').value = "";
    target.innerHTML = "";
    
    // Load files from user's computer 
    for (let fi in files) {
        let reader = new FileReader();
        reader.onload = function(event) {
            document.getElementById(target.id + '_data').value += reader.result + "\n";
            document.getElementById(target.id + '_name').value += escape(files[fi].name) + "\n";
            
            let size = files[fi].size;
            let label = 'bytes';
            if (size > 1048576) {
                size = Math.round((size/1048576)*100)/100;
                label = 'MB';
            }
            else if (size > 1024) {
                size = Math.round((size/1024)*100)/100;
                label = 'KB';
            }
            target.innerHTML += '<b>' + escape(files[fi].name) + '</b> <i>' + size + ' ' + label + '</i><br>';
        }
        reader.readAsDataURL(files[fi]);
    }
    
    return true;
}

// Attach dragging capabilities for payload upload functionality 
window.onload = function(e) { 
    // Add node drag-drop functionality 
    let droppable = document.getElementsByClassName("file_drop");
    for (let i = 0; i < droppable.length; i++) {
        droppable[i].addEventListener('dragover', dragoverCallback, false);
        droppable[i].addEventListener('drop', fileUploadCallback, false);
    }
    
    // Auto-update node data functionality
    let nodes = document.getElementById("node_container").children;
    for (let i = 0; i < nodes.length; i++) {
        setInterval(function() {asyncRequest("GET", nodes[i].id, undefined, nodeDataCallback);}, 1000);
    }
}

