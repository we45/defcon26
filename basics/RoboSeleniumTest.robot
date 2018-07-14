*** Settings ***
Library  SeleniumLibrary
Library  OperatingSystem

*** Variables ***
${goog}  https://www.google.com


*** Test Cases ***
Open Browser
    create webdriver  Chrome

Go to Google
    go to  ${goog}

Type in a Search Query
    input text  xpath=//*[@id="lst-ib"]  DEF CON 26
    click element  xpath=//*[@id="tsf"]/div[2]/div[3]/center/input[1]

Check if the Top hit is DEFCON and Screenshot
    page should contain link  xpath=//*[@id="rso"]/div[1]/div/div/div/div/h3/a  https://www.defcon.org/
    ${screen_path}=  capture page screenshot
    set suite variable  ${screen_path}

Destroy the Browser Session
    close browser
    sleep  3

Nested Keyword Test
    Do multiple file tasks after you are done


*** Keywords ***
Do multiple file tasks after you are done
    create file  test.txt
    append to file  test.txt  The test has been executed\n
    ${filesize}=  get file size  ${screen_path}
    append to file  test.txt  The size of the screenshot is: ${filesize} bytes\n
    log  File size of the Screenshot is: ${filesize} bytes