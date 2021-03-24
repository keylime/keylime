/*
* SPDX-License-Identifier: Apache-2.0
* Copyright 2017 Massachusetts Institute of Technology.
*/

'use strict';
let API_VERSION=2;
let MAX_TERM_LEN=100;
let DEBUG=false;
let gTerminalOffset=0;


// Report that error occurred
function reportIssue(issueStr) {
    if (!DEBUG) return;
    if (window.console && window.console.log) {
        console.log(issueStr);
    }
}

// Return items in array #1 but not in array #2
function arrayDiff(ary1, ary2) {
    let diffAry = [];
    for (let i = 0; i < ary1.length; i++) {
        if (ary2.indexOf(ary1[i]) == -1) {
            diffAry.push(ary1[i]);
        }
    }
    return diffAry;
}

// Make AJAX call to submit events
function asyncRequest(method, res, resId, body, callback) {
    // Need more details before we can do an ADD agent
    if (method == 'POST' && typeof(body) === 'undefined') {
        return addAgentDialog(resId);
    }

    let xmlHttp = new XMLHttpRequest();
    if (typeof(callback) === 'function') {
        xmlHttp.onreadystatechange = function() {
            if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
                callback(xmlHttp.responseText);
            }
            else if (xmlHttp.readyState == 4 && xmlHttp.status == 500) {
                let json = JSON.parse(xmlHttp.responseText);
                let results = xmlHttp.responseText;
                let statusText = xmlHttp.statusText;
                if ("results" in json) {
                    results = json["results"];
                }
                if ("status" in json) {
                    statusText = json["status"];
                }

                // Append error to terminal
                appendToTerminal(["WEBAPP ERROR (AJAX): code=" + xmlHttp.status + ", statusText=" + statusText + ", results=" + results]);

                // Report issue to console
                reportIssue("WEBAPP ERROR (AJAX): code=" + xmlHttp.status + ", statusText=" + statusText + ", results:");
                reportIssue(results);
            }
        }
    }

    xmlHttp.open(method, "/v"+API_VERSION+"/"+res+"/"+resId, true);
    xmlHttp.send(body);
}

// Default/generic async request callback
function defaultReqCallback(responseText) {}

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
            appendToTerminal(["WEBAPP ERROR (FORM): Malformed JSON detected!"]);
            return false;
        }
    }

    return true;
}

// Wrapper to submit Add Agent form
function submitAddAgentForm(form) {
    // Ensure inputs validate
    if (!validateForm(form)) return;

    // Build POST string and send request (generic/default response handler)
    let data = new FormData(form);
    asyncRequest("POST", "agents", form.uuid.value, data, defaultReqCallback);

    // Cleanup
    toggleVisibility('modal_box');
    resetAddAgentForm();
}

// Modal dialog box to add new agent (more details needed)
function addAgentDialog(uuid) {
    document.getElementById('uuid').value = uuid;
    document.getElementById('uuid_str').innerHTML = "("+uuid+")";
    toggleVisibility('modal_box');
}

// When closing modal dialog, reset form
function resetAddAgentForm() {
    // Overall form reset (puts HTML-input values to defaults)
    document.getElementById('add_agent').reset();
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

// Toggle visibility of requested agent
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
        reportIssue("fileUploadCallback: No files provided!");
        return false;
    }

    // Only multi-files can accept multiple files
    if (files.length > 1 && !multi) {
        reportIssue("fileUploadCallback: Attempted to upload multiple files in a single upload box!");
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

// Update agent boxes on page with details
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
    10 : {"class":"invalid","action":"DELETE"},
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
    9 : "Invalid Quote",
    10: "Tenant Quote Failed"
}
function updateAgentsInfo() {
    let childAgentsObj = document.getElementsByClassName('agent');
    for (let i = 0; i < childAgentsObj.length; i++) {
        if (typeof childAgentsObj[i].id == 'undefined' || childAgentsObj[i].id == '') {
            continue;
        }

        asyncRequest("GET", "agents", childAgentsObj[i].id, undefined, function(responseText){
            let json = JSON.parse(responseText);

            // Ensure response packet isn't malformed
            if (!("results" in json)) {
                reportIssue("ERROR updateAgentsInfo: Malformed response for agent refresh callback!");
                return;
            }
            let response = json["results"];

            // Figure out which agent id we refer to
            if (!("id" in response)) {
                reportIssue("ERROR updateAgentInfo: Cannot determine agent id from callback!");
                return;
            }
            let agentId = response["id"];

            // Format address to display
            let fulladdr = "<i>N/A</i>";
            if ("ip" in response && "port" in response) {
                let ipaddr = response["ip"];
                let port = response["port"];
                fulladdr = ipaddr + ":" + port;
            }

            // Format status to display
            let state = response["operational_state"];
            let statStr = "<i>N/A</i>";
            if ("operational_state" in response) {
                statStr = response["operational_state"];
                let readable = STR_MAPPINGS[statStr];
                statStr = statStr + " (" + readable + ")";
            }

            let agentIdShort = agentId.substr(0,8);
            let classSuffix = style_mappings[state]["class"];
            let action = style_mappings[state]["action"];

            let agentOverviewInsert = ""
                    + "<div onmousedown=\"asyncRequest('" + action + "','agents','" + agentId + "')\" class='tbl_ctrl_" + classSuffix + "'>&nbsp;</div>"
                    + "<div onmousedown=\"toggleVisibility('" + agentId + "-det')\" style='display:block;float:left;'>"
                    + "<div class='tbl_col_" + classSuffix + "' title='" + agentId + "'>" + agentIdShort + "&hellip;</div>"
                    + "<div class='tbl_col_" + classSuffix + "'>" + fulladdr + "</div>"
                    + "<div class='tbl_col_" + classSuffix + "'>" + statStr + "</div>"
                    + "<br style='clear:both;'>"
                    + "</div>"
                    + "<br style='clear:both;'>"

            let agentDetailsInsert = "<div class='tbl_det_" + classSuffix + "'><b><i>Details:</i></b><br><pre>";

            // Parse out detailed specs for agent
            for (let stat in response) {
                statStr = response[stat];

                // Make operational state code more human-readable
                if (stat == "operational_state") {
                    let readable = STR_MAPPINGS[statStr];
                    statStr = statStr + " (" + readable + ")";
                }
                else if (typeof(statStr) === "object") {
                    statStr = JSON.stringify(statStr, null, 2);
                }

                agentDetailsInsert += stat + ": " + statStr + "<br>";
            }
            agentDetailsInsert += "</pre></div>";

            // Update agent on GUI
            document.getElementById(agentId+"-over").innerHTML = agentOverviewInsert;
            document.getElementById(agentId+"-det").innerHTML = agentDetailsInsert;
        });
    }
}

// Populate agents on page (does not handle ordering!)
function populateAgents() {
    asyncRequest("GET", "agents", "", undefined, function(responseText){
        let json = JSON.parse(responseText);

        // Ensure response packet isn't malformed
        if (!("results" in json)) {
            reportIssue("ERROR populateAgents: Malformed response for agent list refresh callback!");
            return;
        }
        let response = json["results"];

        // Figure out which agent id we refer to
        if (!("uuids" in response)) {
            reportIssue("ERROR populateAgents: Cannot get uuid list from callback!");
            return;
        }

        // Get list of agent ids from server
        let agentIds = response["uuids"];
        //console.log(agentIds);

        // Get all existing agent ids
        let childAgentsObj = document.getElementsByClassName('agent');
        let existingAgentIds = [];
        for (let i = 0; i < childAgentsObj.length; i++) {
            if (typeof childAgentsObj[i].id != 'undefined' && childAgentsObj[i].id != '') {
                existingAgentIds.push(childAgentsObj[i].id);
            }
        }
        //console.log(existingAgentIds);

        // Find new agents (in new, not in old)
        let newAgents = arrayDiff(agentIds, existingAgentIds);
        //console.log(newAgents);
        // Find removed agents (in old, not in new)
        let removedAgents = arrayDiff(existingAgentIds, agentIds);
        //console.log(removedAgentss);

        // Add agent
        for (let i = 0; i < newAgents.length; i++) {
            let ele = document.getElementById('agent_template').firstElementChild.cloneNode(true);
            ele.style.display = "block";
            ele.id = newAgents[i];
            ele.firstElementChild.id = newAgents[i] + "-over";
            ele.lastElementChild.id = newAgents[i] + "-det";
            document.getElementById('agent_container').appendChild(ele);
        }

        // Remove agents
        for (let i = 0; i < removedAgents.length; i++) {
            let ele = document.getElementById(removedAgents[i]);
            //console.log(ele);
            ele.parentNode.removeChild(ele);
        }
    });
}

// Tenant log "terminal" window functions: append-to and update (periodic)
function appendToTerminal(logLines) {
    if (typeof(logLines) === 'undefined') {
        return;
    }

    // Get the terminal agent
    let term = document.getElementById('terminal');

    // Keep list at MAX_TERM_LEN items (prune)
    while (term.firstChild && (term.childElementCount+logLines.length) > MAX_TERM_LEN) {
        term.removeChild(term.firstChild);
    }

    // Add each new log line to the terminal
    for (let i = 0; i < logLines.length; i++) {
        gTerminalOffset++; // remember new offset for next request (append logs)
        term.innerHTML += "<div>" + logLines[i] + "</div>";
    }

    // Scroll so newest are in view
    term.scrollTop = term.scrollHeight - term.clientHeight;
}
function updateTerminal() {
    asyncRequest("GET", "logs", "tenant?pos="+gTerminalOffset, undefined, function(responseText){
        let json = JSON.parse(responseText);

        // Ensure response packet isn't malformed
        if (!("results" in json)) {
            reportIssue("ERROR updateTerminal: Malformed response for log refresh callback!");
            return;
        }
        let response = json["results"];

        // Figure out which agent id we refer to
        if (!("log" in response)) {
            reportIssue("ERROR updateTerminal: Cannot get log data from callback!");
            return;
        }

        if (response["log"].length == 0) {
            // nothing new, don't bother!
            return;
        }

        // update terminal display to user
        appendToTerminal(response["log"]);
    });
}
