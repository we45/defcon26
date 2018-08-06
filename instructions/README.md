## Instructions - DEF CON 26 Training

## Prep
* In your Desktop environment, open up a Terminal
* Run: `cd ~/Desktop/tooling/defcon26`
* Once you are in this directory, run: `source venv/bin/activate` to activate the virtualenv
* You need to install a bunch of packages
    * `pip install -r requirements.txt` (this is the requirements file in this directory)
    * If you have downloaded the v6.ova file from the Google Drive link, then a lot of these packages would be installed already

## Basics - Robo101
* Go to the `basics` directory and run Robo101 with: `robot Robo101.robot`
* Observe the results
* Delete the file `test.txt`
* Now run the example with a tagged test case `robot -i mytag Robo101.robot`

## Basics - RoboSeleniumTest.robot
* Make sure you are in the root directory (defcon26)
* Run this command to add this path to the PATH variable: `export PATH=$PATH:$(PWD)`
* Now cd into the `basics` directory
* Run `robot RoboSeleniumTest.robot`

## Basics - RESTExample.robot
* Run the vulnerable web service with `start_flask.sh`, starts the flask app on port 5050
* Now cd into the `basics` directory
* Run `robot RESTExample.robot`
* Run `stop_all_containers.sh`

## CI/CD - NodeAppPipeline
* Run the vulnerable web service with `start_node.sh`, starts the NodeJS AppStack
* Now open a separate terminal and cd into the `ci_cd` directory
* Remove all the existing files in the `results` directory
* Run `robot NodeAppPipeline.robot`

## CI/CD - SeleniumPipeline
* Run `stop_node.sh`
* Run `stop_all_containers.sh`
* Make sure you are in the root directory (defcon26)
* Run `start_wecare.sh`
* Run this command to add this path to the PATH variable: `export PATH=$PATH:$(PWD)`
* Now open a separate terminal and cd into the `ci_cd` directory
* Activate the Virtualenv in the `defcon26` `venv` directory
* Run `robot SeleniumPipeline.robot`

## Pentest Pipeline
* Run `stop_node.sh`
* Run `stop_all_containers.sh`
* Make sure you are in the root directory (defcon26)
* Run this command to add this path to the PATH variable: `export PATH=$PATH:$(PWD)`
* CD into the `pentest_pipeline` directory
* Activate the Virtualenv in the `defcon26` `venv` directory
* Add Shodan Token to perform Shodan Search
* **you might have to change the default altoromutual.com example**
* Run `robot SeleniumPipeline.robot`

## ThreatPlaybook
* Run `stop_all_containers.sh`
* Run `start_node.sh`
*

## Bonus Example - Reuse Test Automation for Security Test Automation
* Run the vulnerable web service with `start_flask.sh`, starts the flask app on port 5050
* Now cd into the `basics` directory
* Follow the instructor

