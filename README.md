# elastic_to_llm
Code to connect Elastic index data to be analyzed by local llm.

For this to work, you'll need:
- LM STudio
- Elasticsearch
- Python: add elasticsearch libraries

# Initial Run
Use this syntax below for the initial run:
```chatinput
VERBOSE_ENABLED=1 EXPLAIN_MAX_TOKENS=768 BYPASS_FILTER=1 BATCH_SIZE=10 LM_MAX_TOKENS=768 python main.py
```
We can also set these values as system variables, i.e. you can: export VERBOSE_ENABLED=1 as the script reads env variables.

When run, it will create a file: anomalies_verbose.txt

anomalies_verbose.txt has the output of the run.  Tail this file to keep an eye on if it's correctly parsing data.

## Results
Results in the anomalies_verbose.txt will look like:

```chatinput
ID: ...........
Time: 2025-09-26T19:56:51.777Z
IP: xx.xx.xx.xx
Request: - - → -
Reason (concise): SuspPath: /blog/wp-admin, query: u=admin&p=blahblah
Explanation:
Anomaly: Suspicious User Agent and IP Combination
Score: 8/10
Reason: The user agent is "GPTbot" which is a known suspicious bot, and the request is coming from an IP address (xx.xx.xx.xx) that is not explicitly identified as malicious but is associated with this unusual user agent.

What's happening:
- A GET request was made to "/blog/wp-admin" with a query string containing sensitive information.
- The request came from an unknown source, and the user agent "GPTbot" suggests potential scraping or malicious activity.
- The IP address xx.xx.xx.xx is not flagged as malicious but its association with this suspicious user agent warrants further investigation.

This anomaly requires closer examination to determine if it's a genuine request or a malicious attempt to gather sensitive information.
```


For more info:
https://medium.com/@darkly_splendid/elasticsearch-to-local-llm-d34128bf57e7

