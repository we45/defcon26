*** Settings ***
Library  OperatingSystem
Library  Screenshot
Library  Collections
Library  DateTime

*** Test Cases ***
Python Primitives and Operations
    Log  Hello from DEFCON 26  #simply logs the string to the log file
    convert to boolean  true
    convert to integer  13
    convert to number  15.0
    ${my_number}=  convert to integer  1000
    log  ${my_number}

Python Date and Time Operations
    ${curr_date}=  get current date
    log  ${curr_date}
    ${new_time}=  add time to date  ${curr_date}  7 days
    log  ${new_time}
    set suite variable  ${new_time}

Python Data Structures and Operations
    ${simple_dict}=  create dictionary  conference=defcon  city=Las Vegas  message=Automation is awesome
    should be equal  ${simple_dict.conference}  defcon
    run keyword and continue on failure  should be equal  ${simple_dict.city}  San Francisco  #this test will fail
    should start with  ${simple_dict.city}  Las


Lets Run a Tagged Test Case Now
    [Tags]  mytag
    create file  test.txt
    append to file  test.txt  Hello from DEF CON 26

Basic Operating System Ops
    ${file_count}=  count files in directory  .
    log  ${file_count}
    ${file_size}=  get file size  Robo101.robot
    log  ${file_size} bytes

File Grep
    grep file  /var/log/system.log  ERROR




