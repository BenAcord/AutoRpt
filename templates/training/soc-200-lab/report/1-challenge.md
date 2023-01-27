
# Attacker Phases

## Phase 1

### RDP Brute Force

The initial indicator of an attack happening was the triggering of a pre-defined threshold rule called "Possible RDP brute force" as shown below.

![ImgPlaceholder](images/placeholder-image-300x225.png)

By looking at how the rule was defined, it is triggered by more than 100 instances of event ID 4625, which is a failed logon. This could align with a brute force attack where the attacker makes use of a user and/or password list.

When we inspect some of the events that triggered the alert, as shown below, we notice that the server reporting the events is APPSRV02.

![ImgPlaceholder](images/placeholder-image-300x225.png)

Given that an attacker may have attempted to brute force the server, we should search for a subsequent successful log on event to APPSRV02 to determine if they obtained access.

We do this with the following KQL query:

```ini
event.code : "4624" and NOT user.name : SYSTEM and NOT user.name : DWM-2
```

From this query we find the following event entry:

![ImgPlaceholder](images/placeholder-image-300x225.png)

This shows that the user Peter did a successful logon to APPSRV02 shortly after the suspected brute force attack.
The source IP of the logon event was 192.168.67.69 which means its not a local logon, but remotely.

At this point we have a strong suspicion that the account with the username Peter was compromised and a malicious actor obtained access to APPSRV02 coming from the IP address 192.168.67.69.
We should escalate this to an incident and contact the user to verify whether this was a legitimate logon.

### Persistence

After suspicion of a compromise, additional investigation should be performed.
One area is looking for persistence and a common way attackers employ is through the registry.

To try and determine if this happed, we can use the KQL query:

```ini
process.name : "reg.exe"
```

As a result, we find the following event:

![ImgPlaceholder](images/placeholder-image-300x225.png)

This shows that a registry change was performed. An entry for the Run key was added.
The Run registry key is used when a user logs on to the computer and thus is often used for persistence.

In particular we notice that the file `C:\Windows\System32\update.exe` will be executed when a user logs on to APPSRV02.

We should escalate this to investigate what the file update.exe is.

### Summary

In this phase we have strong suspicions that a malicious actor performed a brute force attack against APPSRV02 and managed to compromise the user account with the username "Peter".
Additionally, we suspect that persistence was set up through a Run key in the registry to execute the file `C:\Windows\System32\update.exe`.

## Phase 2

## Phase 3

## Phase 4

## Phase 5

## Phase 6

## Phase 7

## Phase 8

## Phase 9

## Phase 10