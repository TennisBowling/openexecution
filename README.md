# openengine
openengine lets multiple CL's connect to one EE.  
One CL is designated as the "canonical" CL, and it's fork choices are always considered valid by us.  
We then store the responses to the canonical CL's forkchoices, and then when an "untrusted" (client) CL sends a forkchoice to us, we check if the CL already sent it. If so, we simply return the EE's response to that forkchoice. Otherwise, we return SYNCING.  

Problems with this:
- we're trusting the operator to not lead the client CL's into some incorrect fork and get slashed.
Assuming the operator is not trying to lead them into a bad fork, we can basically nullify the possibility of getting slashed by using a minority client or something like executionbackup so that the worst outcome is offline penalty for validators.

## How to use
You can connect to this program as if it's your own EL. Simply provide an instance of this program (such as https://openexecution.tennisbowling.com) to your CL, use literally whatever JWT secret you would like, and run!
