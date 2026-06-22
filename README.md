# Spider Agent - Agentic penetration testing based on captured traffic

## Idea
Traditionally, penetration testing has been web-focused. This domain is not only of high relevance but also allows for powerful instrumentation through browser configuration, such as proxy configuration, JS tampering, and TLS secret logging via SSLKEYLOGFILE.
The niche yet important area of application security for proprietary binaries running on end devices, such as mobile or desktop applications, receives less attention as instrumentation in this field is hindered by various layers of process and machine protection mechanisms, such as app armor or secure enclaves.

While a customer company may specify endpoints to be tested, they typically do not provide the traffic patterns that we are used to observing, intercepting, modifying, and replaying in the browser-based setting.
In this project, we obtain a baseline for remote configuration and business logic through forensic analysis of application memory dumps, using a novel GPU-accelerated extraction approach that allows us to omit traditional application instrumentation, such as FRIDA.

Equipped with the recorded plain text traffic of the application under test, we perform parsing and evaluate it using an LLM. The AI proposes attack vectors based on the observed traffic and publicly known vulnerabilities and exploit techniques. We then proceed to task a powerful agent with examining the exploitability of each relevant, identified attack vector. This agent is able to access an array of popular and well-documented penetration testing tools, such as dirbuster or sqlmap, through MCP.

### Disclamer
**Penetration testing without prior consent is illegal.**

Use this tool only in the domain of bug bounty in the authorized scope or your self hosted services. Beware that the tool may target 3rd party APIs due to their presence in the traffic. Make sure to take this into consideration when selecting attack vectors for exploitation analysis.

### Pipeline

1. Traffic Generation: Application under test runs in a virtual environment and is repeatedly interrupted for RAM dumping upon creating TLS/DTLS/QUIC sessions. The user chooses an interesting application flow to examine in the tests later.
2. Secret Extraction: VoSeS is run on the recorded, encrypted traffic and the RAM dump files, obtaining a NSS format master secret key log file.
3. Parsing: A parser is run on the encrypted traffic and the key log file, filtering and parsing packets into a SQL database.
4. POI selection: The tool user selects network events (e.g., HTTP exchanges) that they find interesting for further analysis.
5. LLM Attack Vector Conception: In parallel execution on all selected events, runs an LLM agent with access to the SQL database and RAG MCP tooling. It devises a list of attack ideas for each event.
6. Attack Vector Selection: The user selects attack angles for each event that they want to further investigate.
7. LLM Penetration Test: In parallel execution on each attack vector selected, the LLM performs a penetration test with user-specified constraints, user-specified MCP pentesting tools, and RAG access. The LLM assesses whether the proposed attack vector is applicable/exploitable or whether it can be proven that it is not.
8. Impact Analysis: The user selects interesting LLM findings from the prior stage and tasks agents to demonstrate high impact while respecting remote service integrity. This layer serves as a filter for hallucinated or exaggerated findings in the prior stage. For example, the penetration test analysis may deem HTTP 200 responses to unauthenticated API queries an auth bypass, but it has no impact without an HTTP response with a relevant payload.

The drawio pipeline file is not up to date and only reflects an initial draft.

### Guided Analysis

The user can access an LLM agent with all implemented tools to perform a free-form vulnerability analysis.

## Setup

### Requirements
- OpenAI or Deepseek API key for LLM tasks (Deepseek preferred)
- Tavily API key for RAG tooling
- ProtonVPN key for VPN tunneling of pentest tool traffic (not to get flagged by the ISP)
- Docker

### Choosing a Target
Pick an application that has a public bug bounty program! Test only within bug bounty or explicit permission! Any application traffic will be persistently stored in plain test so only use test accounts with test data! Maybe test your own webpage first.

### Traffic Generation and Secret Extraction

You can skip this stage if you have a database dump at the ready, which contains prior recorded traffic
```bash
./db/dump_load_db.sh load <dump-file>
```
You can also skip this stage by examining a browser application. Simply run a Wireshark recording of you, using the application under test in a browser such as Chrome. Make sure to set the SSLKEYLOGFILE environment variable before starting the browser in the terminal. e.g.
```bash
export SSLKEYLOGFILE=~/keylog.txt
google-chrome
```
Your Wireshark recording should capture the application under test's traffic as isolated as possible. Ideally, run the browser and the recording in a virtual machine with little noise, e.g., Ubuntu, and start the recording right before opening the services' first page.
You can proceed with stage 4-8.

Without a database dump, you need to generate your own traffic and secrets. Setup a VM with the application under test. If you use VirtualBox under Linux, you can use the `/poc/profiling/vm-capture/vm_traffic_monitor.py` script to obtain RAM dumps.
The `/poc/profiling/key-extraction/dumps2keylog.py` can then be used in combination with a VoSeS binary on a machine with an Nvidia GPU to extract the secret material from the RAM dumps.
Refer to [VoSeS](https://github.com/DeltaTecs/VoSeS) for compilation. 

### Parsing

Parsing and all following stages are integrated in a Docker setup, which can be built in the `poc` folder:
```bash
docker compose up -d
```
Expect this to take a while on initial setup. The hexstrike container takes a long time to build due to pentest tool installs. Additionally, ca. 10GB of free storage is required.

You can then run the parsing stage
```bash
poc/run_parsing.sh <traffic pcap file> <key log file>
```

### AI Analysis

At this point, make sure you have all API keys set in `/poc/.env`. It is possible to omit the VPN setup, but it is not recommended, as the ISP may flag pentesting tool traffic.

Stages 4-8 are facilitated through a web client. After the Docker setup is running, it should be available at `http://localhost:8093/`. The current flow is
1. Go to Test Planner and inspect events. Check mark events that you want to investigate further. Configure an AI for attack vector analysis (recommended DeepSeek v4 pro, high effort, 35 max iterations), then press Launch Analysis.
2. Inspect proposed vectors to each event and checkmark interesting ones (recommended 1-5 for testing, 10-100 for full-scale scan (expect up to 20$ cost))
3. Go to Analysis Queue and configure AI (recommended deepseek v4 pro, max effort, 50 iterations, few tools (packet_info, packet_payload_hexdump, conversation_packets, tavily_search, tavily_extract, gobuster_scan, create_file, modify_file, delete_file, python, dirb, sqlmap, ffuf, graphql, jwt analyzer, wafw00f, fierce_scan, dnsenum), automatic review deepseek v4 flash, default effort, 4 iterations). Make sure to specify tool use constraints of the application's bug bounty program (f.e, rate limit, user agent).
3. If you are superstitious, enable manual tool review. Run a (parallel) exploitability analysis. After an item has finished, evaluate if you want to investigate further and press "send to Exploit Queue" if so.
4. In Exploit Queue, run a similar analysis to Analysis Queue and investigate findings

## Improvements and downsides

### Agentic application control
A major downside of our approach is the reliance on old traffic data. Many exploits require modification of traffic in transit due to the short life of authentication tokens and specific application flows / state progression (e.g., OAuth).
This could be improved by redesigning the tool chain and designing application-controlling MCP tools.

### Application Protocol Analysis
The tool mainly focuses on HTTP security at the moment, as it is not able to collect sufficient ideas for attack vectors on the custom application layer of many applications. The area of HTTP-based attacks is well researched as well as guarded. A high potential lies in understanding and tricking the propriatery application logic, which we are able to access with the traffic decryption. 

