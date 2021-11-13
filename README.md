# Q-Safe-Forward-Secrecy
Even Google's quantum computers can't stop you from sending "Good Morning" pics.

## Usage (docker)
The only blue whale app you should be messing with.
* Build the image: `docker build --tag qsfs .`
* Run the container: `docker run --detach qsfs`
* Start one side: `docker exec -it <container-name> python bob.py`
* Start the other: `docker exec -it <container-name> python alice.py`

## Usage (native)
Like bare metal eh? Good for you, it saves bandwidth.
* Install everything: `pip install -r requirements.txt`
* Start one side `python3 bob.py`
* Start the other `python3 alice.py` (in that order!)
* Send anything you want