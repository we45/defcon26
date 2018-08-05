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