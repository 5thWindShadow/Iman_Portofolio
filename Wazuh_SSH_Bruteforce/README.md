# Detecting and Blocking Delayed/Slow SSH Brute-Force Attacks with Wazuh

This documentation outlines a custom Wazuh configuration designed to identify and block SSH brute-force attacks, including those that employ delaying tactics (like using `timesleep`) to evade simpler detection mechanisms.

## Problem Statement

Standard brute-force detection often relies on a high frequency of failed login attempts in a very short time. Attackers can bypass this by introducing delays between attempts. This configuration aims to catch these slower, more persistent attacks by correlating multiple related events over a longer timeframe.

## Identifying Relevant Existing Rules

Wazuh already has several rules related to SSH authentication failures. We will leverage some of these as indicators. The key is that a *single* trigger of these rules might be insignificant, but *multiple* triggers over time suggest a brute-force attempt.

Here are some relevant base rule IDs involved:

*   **`rule.id = 5763`**: SSH insecure connection attempt (e.g., protocol mismatch). (Often already has an active response configured by default).
*   **`rule.id = 5760`**: SSH authentication failed. (Common indicator).
*   **`rule.id = 5710`**: SSH login session opened (after multiple failed attempts). (Can indicate success *after* a brute-force).
*   **`rule.id = 5503`**: PAM authentication failure. (Related to login attempts).
*   **`rule.id = 2502`**: User login failed. (Generic login failure).
*   **`rule.id = 5551`**: Non-standard user authentication failure.
*   **`rule.id = 5712`**: SSH authentication failed (multiple times).
*   **`rule.id = 5758`**: SSH maximum authentication attempts exceeded.
*   **`rule.id = 5720`**: Multiple SSH authentication failures.

**Note:** For the rules below marked with `freq=X`, it means the original rule needs to trigger X times within a specific timeframe for our *new* detection rule to activate.

*   `rule.id = 5760`, requires `freq=5`
*   `rule.id = 5710`, requires `freq=5`
*   `rule.id = 5503`, requires `freq=5`
*   `rule.id = 2502`, requires `freq=2`

## Creating New Rules for Delayed Brute-Force Detection

To detect the *pattern* of repeated failures over time, we create new parent rules that trigger only when the underlying rules (like `5760`, `5710`, etc.) fire a certain number of times within a defined timeframe.

These rules should be added to your Wazuh manager's `local_rules.xml` file (located at `/var/ossec/etc/rules/local_rules.xml`).

Link: <a href="https://github.com/5thWindShadow/Iman_Portofolio/blob/main/Wazuh_SSH_Bruteforce/Custom_Rules">Custom Rules</a>

Custom Rules Explanation:
* `group name`="sshbrute": Groups these custom rules together logically.
* `rule id`="10070X": Unique IDs for the new rules (ensure they don't conflict with existing ones).
* `level`="10": Sets the severity level (10 is typically "High Importance").
* `frequency`="X": The number of times the if_matched_sid rule must trigger.
* `timeframe`="120": The time window (in seconds) during which the frequency count is checked. For example, frequency="5" and timeframe="120" means the base rule must trigger 5 times within 120 seconds.
* `if_matched_sid`: Specifies the original rule ID that acts as the trigger condition.
* `description`: Explains what this new alert signifies.

These rules effectively correlate multiple lower-level events to identify a sustained attack pattern, even if the individual attempts are spaced out.

## Configuring Active Response
Once the new rules are in place to detect the delayed attacks, we need to configure Active Response to automatically block the offending IP addresses.

This configuration should be added to your Wazuh manager's ossec.conf file (located at /var/ossec/etc/ossec.conf) within the <ossec_config> tags.

Link: <a href="https://github.com/5thWindShadow/Iman_Portofolio/blob/main/Wazuh_SSH_Bruteforce/Active-Response">Active-Response</a>

Active-Response Explanation:
* `<active-response>`: Defines an active response block.
* `command`: Specifies the response script to execute. firewall-drop is a common Wazuh script that uses iptables, firewalld, or other firewalls to block the source IP of the alert. Ensure this script is properly configured and working on your system.
* `location`: local means the command runs on the Wazuh manager (or agent, depending on setup, but typically local for firewall-drop triggered by manager rules).
* `rules_id`: A comma-separated list of rule IDs that will trigger this active response.
* `timeout`: The duration (in seconds) for which the IP address will be blocked. 1800 seconds is 30 minutes.

*Important*: Remember to restart the Wazuh manager (systemctl restart wazuh-manager or /var/ossec/bin/ossec-control restart) after modifying rules or configuration files for the changes to take effect.

## Results and Verification
After implementing these rules and the active response configuration, you should observe offending IP addresses being automatically blocked. You can verify this by checking the Wazuh active response log (/var/ossec/logs/active-responses.log) on the manager.

![image](https://github.com/user-attachments/assets/60078b7f-e45d-459d-975d-1d1ba0ea0377)

The logs should show entries indicating that the firewall-drop command was executed for the rule IDs specified in the active response configuration, targeting the source IP addresses triggering the alerts. This confirms that the system is successfully detecting and mitigating both standard and delayed SSH brute-force attacks.
