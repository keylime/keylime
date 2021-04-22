/*
* SPDX-License-Identifier: Apache-2.0
* Copyright 2017 Massachusetts Institute of Technology.
*/

'use strict';
let API_VERSION=2;
let MAX_TERM_LEN=100;
let DEBUG=false;
let gTerminalOffset=0;

// global variables
let page = 0;
let selectedAgents = [];
let agentIdx = 0;
let statusArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

google.charts.load("current", {packages:["corechart"]});

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

async function renderCharts(chart, agentIdToState) {
    let response = await fetch(`/v${API_VERSION}/agents/`);
    let json = await response.json();
    if (!("results" in json)) {
        reportIssue("ERROR populateAgents: Malformed response for agent list refresh callback!");
        return;
    }
    response = json["results"];

    // Figure out which agent id we refer to
    if (!("uuids" in response)) {
        reportIssue("ERROR populateAgents: Cannot get uuid list from callback!");
        return;
    }

    // Get list of agent ids from server
    let agentIds = response["uuids"];
    
    for (const uuid of agentIdToState.keys()) {
        if (agentIds.indexOf(uuid) === -1) {
            // if uuid is not in the response, remove it from the map
            agentIdToState.delete(uuid);
        }
    }

    // collect visualization data for pie chart
    if (agentIdx == agentIds.length) {
        agentIdx = 0;
    }

    let urls = [];
    let batchStart = agentIdx;
    for (; agentIdx < Math.min(agentIds.length, batchStart + BATCH_SIZE); agentIdx++) {
        urls.push(`/v${API_VERSION}/agents/${agentIds[agentIdx]}`);
    }
    let requests = urls.map((url) => fetch(url));
    Promise.all(requests)
        .then((responses) => Promise.all(responses.map((res) => res.json())))
        .then((dataItems) => {
            dataItems.forEach((resJson) => {
                let ss = resJson['results']['operational_state'];
                let uuid = resJson['results']['id'];
                
                if (agentIdToState.has(uuid)) {
                    let oldState = agentIdToState.get(uuid).operational_state;
                    statusArray[oldState]--;
                }
                
                statusArray[ss]++;
                agentIdToState.set(uuid, resJson['results']);
            });
        })
        .then(() => {
            drawChart(chart, statusArray);
        });
}

function drawChart(chart, statusArray) {
    let data = google.visualization.arrayToDataTable([
        ['Status', 'status'],
        ['Registered', statusArray[0]],
        ['Start', statusArray[1]],
        ['Saved', statusArray[2]],
        ['Get Quote', statusArray[3]],
        ['Get Quote (retry)', statusArray[4]],
        ['Provide V', statusArray[5]],
        ['Provide V (retry)', statusArray[6]],
        ['Failed', statusArray[7]],
        ['Terminated', statusArray[8]],
        ['Invalid Quote', statusArray[9]],
        ['Tenant Quote Failed', statusArray[10]]
    ]);

    let options = {
            title: 'Agents Status Pie Chart',
            pieHole: 0.4,
            titleTextStyle: {
            fontSize: 25
        },
        colors:['#BEBEBE', '#FFFF00', '#BEBEBE', '#88FF99', '#FFFF00', '#88FF99', '#FFFF00', '#FF6666', '#BEBEBE', '#FF6666', '#FF6666'],
        pieSliceTextStyle: {fontSize: 18},
        legend: {
            textStyle: {
                fontSize: 20
            }
        }
    };

    chart.draw(data, options);
}

function selectHandler(chart, agentIdToState) {
    let selectedItem = chart.getSelection()[0];
    if (selectedItem) {
        selectedAgents = [];
        page = 0;
        for (const agentDetail of agentIdToState.values()) {
            if (agentDetail.operational_state === selectedItem.row) {
                selectedAgents.push(agentDetail);
            }
        }
        renderAgentList();
    }
}

function nextPageHandler() {
    if ((page + 1) * PAGE_SIZE < selectedAgents.length) {
        page += 1;
        renderAgentList(page);
    }
}

function prevPageHandler() {
    if ((page - 1) >= 0) {
        page -= 1;
        renderAgentList(page);
    }
}

function insertAgent(agent) {
    let ele = document.getElementById('agent_template').firstElementChild.cloneNode(true);
    ele.style.display = "block";
    ele.id = agent.id;
    ele.firstElementChild.id = agent.id + "-over";
    ele.lastElementChild.id = agent.id + "-det";

    // Format address to display
    let fulladdr = "<i>N/A</i>";
    if ("ip" in agent && "port" in agent) {
        let ipaddr = agent.ip;
        let port = agent.port;
        fulladdr = ipaddr + ":" + port;
    }

    // Format status to display
    let state = agent.operational_state;
    let statStr = "<i>N/A</i>";
    if ("operational_state" in agent) {
        statStr = agent.operational_state;
        let readable = STR_MAPPINGS[statStr];
        statStr = statStr + " (" + readable + ")";
    }

    let agentIdShort = agent.id.substr(0,8);
    let classSuffix = style_mappings[state]["class"];
    let action = style_mappings[state]["action"];

    let agentOverviewInsert = ""
            + "<div onmousedown=\"asyncRequest('" + action + "','agents','" + agent.id + "')\" class='tbl_ctrl_" + classSuffix + "'>&nbsp;</div>"
            + "<div onmousedown=\"toggleVisibility('" + agent.id + "-det')\" style='display:block;float:left;'>"
            + "<div class='tbl_col_" + classSuffix + "' title='" + agent.id + "'>" + agentIdShort + "&hellip;</div>"
            + "<div class='tbl_col_" + classSuffix + "'>" + fulladdr + "</div>"
            + "<div class='tbl_col_" + classSuffix + "'>" + statStr + "</div>"
            + "<br style='clear:both;'>"
            + "</div>"
            + "<br style='clear:both;'>"

    let agentDetailsInsert = "<div class='tbl_det_" + classSuffix + "'><b><i>Details:</i></b><br><pre>";

    // Parse out detailed specs for agent
    for (let stat in agent) {
        statStr = agent[stat];

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
    ele.firstElementChild.innerHTML = agentOverviewInsert;
    ele.lastElementChild.innerHTML = agentDetailsInsert;

    document.getElementById("agent_container").appendChild(ele);
}

function clearAgentList() {
    // remove existing agents in the list
    let agentContainer = document.getElementById("agent_container");

    while (agentContainer.firstChild) {
        agentContainer.removeChild(agentContainer.firstChild);
    }

    document.getElementById("prev_page").disabled = true;
    document.getElementById("next_page").disabled = true;
    document.getElementById("page_number").innerHTML = ""; 
}

function renderAgentList(page_num=0) {
    clearAgentList();
    // add agents
    for (const agent of selectedAgents.slice(page_num * PAGE_SIZE, (page_num + 1) * PAGE_SIZE)) {
        insertAgent(agent);
    }

    document.getElementById("prev_page").disabled = false;
    document.getElementById("next_page").disabled = false;
    document.getElementById("page_number").innerHTML = `page: ${page + 1}/${Math.ceil(selectedAgents.length / PAGE_SIZE)}`;
}
