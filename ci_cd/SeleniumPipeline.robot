*** Settings ***
Library  SeleniumLibrary
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  OperatingSystem

*** Variables ***
${ZAP_PATH}  /Applications/OWASP_ZAP.app/Contents/Java/
${TARGET}  http://localhost:9000/
${CONTEXT}  CTF2
${BASE_URL}  http://localhost:9000/
${LOGIN_URL}  http://localhost:9000/login/
${SCANPOLICY}  Light
${APPNAME}  weCare
${REPORT_TITLE}  weCare Test Report - ZAP
${REPORT_FORMAT}  json
${EXPORT_FILE_PATH}  /Users/abhaybhargav/Documents/Code/Python/defcon26/ci_cd/selenium_results/wecare.json
${REPORT_AUTHOR}  Abhay

*** Test Cases ***
ZAP Init
    [Tags]  zap_init
    start gui zap  ${ZAP_PATH}
    sleep  4
    zap open url  ${TARGET}

Open Healthcare App
    [Tags]  phantomjs
#    set Environment Variable  webdriver.chrome.driver  /Users/abhaybhargav/Documents/Code/Python/ZapRobotSelenium/chromedriver
    ${list} =  Create List  --proxy-server=http://127.0.0.1:8090
    ${args} =  Create Dictionary  args=${list}
    ${desired_caps} =  Create Dictionary  chromeOptions=${args}
    create webdriver  Chrome  desired_capabilities=${desired_caps}
    go to  ${LOGIN_URL}


Login to Healthcare App
    [Tags]  login
    input text  email_id  bruce.banner@we45.com
    input password  password  secdevops
    click button  id=submit
    set browser implicit wait  10
    location should be  ${BASE_URL}dashboard/

Visit Random Pages
    [Tags]  visit
    go to  ${BASE_URL}tests/
    input text  search  something
    click button  name=look
    go to  ${BASE_URL}secure_tests/

ZAP Contextualize
    [Tags]  zap_context
    ${contextid}=  zap define context  ${CONTEXT}  ${TARGET}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Active Scan
    [Tags]  zap_scan
    ${scan_id}=  zap start ascan  ${CONTEXT_ID}  ${TARGET}  ${SCANPOLICY}
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    [Tags]  zap_generate_report
    zap export report  ${EXPORT_FILE_PATH}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

ZAP Die
    [Tags]  zap_kill
    zap shutdown

Close App
    [Tags]  browser_close
    close browser