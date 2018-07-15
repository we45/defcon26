*** Settings ***
Library  ThreatPlaybook  Cut the Funds Corporate Expenser
Library  Collections
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  RoboSslyze
Library  RoboNodeJSScan
Library  REST  http://localhost:3000  proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
Library  RoboNpmAudit

*** Variables ***
${TARGET_NAME}  Cut the Funds Expenser Application
${TARGET_URI}  localhost:3000
${TARGET_HOST}  localhost
${SSL_TARGET}  207.148.70.86
#CONFIG
${RESULTS_PATH}  /Users/abhaybhargav/Documents/Code/Python/defcon26/ci_cd/results
#Sslyze
${SSLYZE_JSON}  /Users/abhaybhargav/Documents/Code/Python/defcon26/ci_cd/results/sslyze.json
#ZAP
${ZAP_PATH}  /Applications/OWASP_ZAP.app/Contents/Java/
${APPNAME}  Cut the Funds NodeJS API
${CONTEXT}  Cut_The_Funds_API
${REPORT_TITLE}  Cut the Funds NodeJS API Test Report - ZAP
${REPORT_FORMAT}  json
${ZAP_REPORT_FILE}  ctf.json
${REPORT_AUTHOR}  Abhay Bhargav
${SCANPOLICY}  Light

${TO_PATH}  /Users/abhaybhargav/Documents/Code/node/cut_the_funds

*** Test Cases ***
Create Targets
    find or create target  ${TARGET_NAME}  ${TARGET_URI}

Run NodeJSScanner
    run nodejsscan against source  ${TO_PATH}  ${RESULTS_PATH}
    parse nodejsscan result  ${RESULTS_PATH}/nodejsscan.json  ${TARGET_NAME}

Run NPM Audit against packageJSON
    run npmaudit against source  ${TO_PATH}  ${RESULTS_PATH}
    parse npmaudit scan result  ${RESULTS_PATH}/npm_audit.json  ${TARGET_NAME}

Test for SSL
    test ssl basic  ${SSL_TARGET}
    test ssl server headers  ${SSL_TARGET}
    write results to json file  json_file=${SSLYZE_JSON}
    create and link recon  sslyze  ${TARGET_NAME}  file_name=${RESULTS_PATH}/sslyze.json

Initialize ZAP
    [Tags]  zap_init
    start gui zap  ${ZAP_PATH}
    sleep  10
    zap open url  http://${TARGET_URI}

Authenticate to Cut the Funds as Admin
    [Tags]  walk_web_service
    &{res}=  POST  /users/login  {"email": "andy.roberts@widget.co", "password": "spiderman"}
    Integer  response status  200
    Boolean  response body auth  true
    set suite variable  ${TOKEN}  ${res.body["token"]}
    log  ${TOKEN}

Search the Currency Lookup Service
    [Tags]  walk_web_service
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /projects/search_expense_db  { "search": "Chile" }
    Integer  response status  200
    String  $[0].country  Chile

ZAP Contextualize
    [Tags]  zap_context
    ${contextid}=  zap define context  ${CONTEXT}  http://${TARGET_URI}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Active Scan
    [Tags]  zap_scan
    ${scan_id}=  zap start ascan  ${CONTEXT_ID}  http://${TARGET_URI}  ${SCANPOLICY}
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    [Tags]  zap_generate_report
    zap export report  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

Write ZAP Results to DB
    parse zap json  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${TARGET_NAME}  ${TARGET_URI}

ZAP Die
    [Tags]  zap_kill
    zap shutdown
    sleep  3

Write Final Report
    ${all_false}=  convert to boolean  False
    write markdown report  gen_diagram=${all_false}  gen_threat_model=${all_false}