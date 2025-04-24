# Wazuh Custom Decoder for Browser History Monitoring

This documentation explains how to create a custom Wazuh decoder and a corresponding rule to parse browser history logs and generate alerts based on visited sites.

## Objectives

The objective is to monitor browser activity by parsing custom log entries that contain visited URLs, page titles, visit counts, and timestamps. Wazuh will be configured to:

1.  **Decode:** Extract meaningful fields (URL, title, count, date) from the raw log lines.
2.  **Alert:** Generate alerts when a browser history log entry is detected.

## Prerequisites

*   **Wazuh Manager:** You need access to your Wazuh manager to add custom decoders and rules.
*   **`wazuh-logtest` Tool:** This tool is essential for testing your decoders and rules without needing real-time logs. It's typically located at `/var/ossec/bin/wazuh-logtest`.



## Sample Log Format
So we are going to use 2 sample logs that are need to be decoded first, then we make the rules for alerting the browser history to wazuh

```
#1 url=https://github.com/, title=github.com, visited_count=43, visited_date=13384253246912614
#2 url=https://github.com/login, title=Sign in to GitHub · GitHub, visited_count=8, visited_date=13380966268773599
```

If we try to use the wazuh-logtest, we will have no decoder matched
![image](https://github.com/user-attachments/assets/b33055e5-67d7-4dcc-aa51-a66733bc7c86)


## Creating the Custom Decoder (/var/ossec/etc/decoders/local_decoder.xml)
We'll create the decoder in two parts: a parent decoder for initial identification and a child decoder for extracting specific fields.

## Step 1: Parent Decoder (Initial Matching)
This first decoder simply identifies logs that potentially belong to our browser history format.

![image](https://github.com/user-attachments/assets/790cadbd-5700-46b6-bd76-534696071acb)

link:<a href="https://github.com/5thWindShadow/Iman_Portofolio/blob/main/Wazuh_Custom_Decoder_History_Browser/Custom_Decoder">Custom Decoder</a>

**Explanation**:
* `<decoder name="browser_history">`: Assigns a unique name to this decoder. You can choose any descriptive name.
* `<prematch>^url=</prematch>`: This is the crucial part for initial identification. It tells Wazuh: "If a log line starts with (^) the exact string url=, then it should be processed by this decoder (and its children)." This acts as an indicator.
* `</decoder>`: Closes the decoder definition.

### Testing the Parent Decoder :
Note: restart the wazuh-manager first to apply changes (systemctl restart wazuh-manager)

![image](https://github.com/user-attachments/assets/c110aa50-9516-4972-b8f6-3ce7055e5aad)

The output should show that Wazuh recognized the log format based on the prematch condition.


## Step 2: Child Decoder (Extracting Fields)
Now that we've identified the correct logs, we create a child decoder to parse the content and extract meaningful fields.

![image](https://github.com/user-attachments/assets/e4fb8c9b-7bcb-49b1-a7d5-4d2e5a942e9c)

link:<a href="https://github.com/5thWindShadow/Iman_Portofolio/blob/main/Wazuh_Custom_Decoder_History_Browser/Custom_Decoder">Custom Decoder</a>

**Explanation**:
* `<decoder name="browser_history_data">`: Gives a name to this child decoder.
* `<parent>browser_history</parent>`: Links this decoder to the browser_history parent decoder defined earlier. This decoder will only run if the parent matched.
* `<regex offset="after_parent">`: Specifies that the regular expression should be applied to the log data after the parent's prematch. The ^ anchor ensures we match from the beginning of the relevant part.
* `^url=`: Matches the literal start url=.
* `(https?:\/\/[^,]+)`: Captures (()) the URL. It matches http:// or https://, followed by any characters ([^,]) that are not a comma, one or more times (+). This extracts the URL value.
* `, title=`: Matches the literal separator and key.
* `(.*?)`: Captures (()) the title. . matches any character, * matches zero or more times, and ? makes it non-greedy (matching the shortest possible string until the next part of the regex). This is safer for titles that might contain commas unexpectedly.
* `, visited_count=`: Matches the literal separator and key.
* `(\d+)`: Captures (()) the visited count. \d matches any digit (0-9), and + matches one or more digits.
* `, visited_date=`: Matches the literal separator and key.
* `(\d+)`: Captures (()) the visited date (assuming it's a numerical timestamp).
* `$`: Anchors the match to the end of the log line.
* `<order>url, title, visited_count, visited_date</order>`: Defines the names for the captured fields, in the same order as the capture groups (()) appear in the regex. Wazuh will store the extracted data under these field names.
* `</decoder>`: Closes the child decoder definition.

### Testing the Complete Decoder:

Don't forget to restart wazuh-manager first and run wazuh-logtest again and paste the sample logs.

![image](https://github.com/user-attachments/assets/2d4cc67a-5174-4cba-a5d8-e56112d653a2)
![image](https://github.com/user-attachments/assets/0fa3dfab-17d1-4e23-9b0d-0fcb480a3553)

The output in Phase 2 should now show the extracted fields with their corresponding values for each log tested.

## Step 3: Creating the Custom Rule (/var/ossec/etc/rules/local_rules.xml)
With the decoder successfully parsing the logs, we need a rule to generate alerts based on this decoded information.

Add the following rule to /var/ossec/etc/rules/local_rules.xml:
![image](https://github.com/user-attachments/assets/d7e7d47f-0eb4-4dc8-a5f3-ffdf297671b9)

link:<a href="https://github.com/5thWindShadow/Iman_Portofolio/blob/main/Wazuh_Custom_Decoder_History_Browser/Custom_Rules">Custom Rules</a>

**Explanation**:
* `<group name="browser_history,">`: Groups related rules. The trailing comma is standard practice for Wazuh groups.
* `<rule id="100800" level="4">`: Defines the rule:
* `id="100800"`: A unique ID for this custom rule (ensure it's 100000 or higher and doesn't conflict).
* `level="4"`: Sets the alert severity level (4 is relatively low, "System information," adjust as needed).
* `<decoded_as>browser_history</decoded_as>`: This is the crucial link. It tells Wazuh this rule should only match events that were successfully processed by the decoder named browser_history (our parent decoder).
* `<description>Browser History Recorded`: URL='$(url)', Title='$(title)'</description>: This defines the alert message that will be generated.

$(url) and $(title) are dynamic fields. Wazuh automatically replaces these placeholders with the actual values extracted by the browser_history_data child decoder for the specific log that triggered the rule.

### Result
After implementing the decoder and rule and restarting the Wazuh manager, any incoming browser history logs matching the specified format will now be:

![image](https://github.com/user-attachments/assets/3fe02841-ca47-46e4-8790-01ba9216c892)
![image](https://github.com/user-attachments/assets/d2dca106-5307-4d85-bb17-af3f605de786)

**Explanation** :
1. Identified by the browser_history parent decoder.
2. Parsed by the browser_history_data child decoder, extracting the url, title, visited_count, and visited_date fields.
3. Trigger rule 100800, generating an alert in Wazuh with a description containing the specific URL and Title from the log.

You can then view these alerts in the Wazuh dashboard
