# Collecting email samples

## Microsoft Outlook

### Microsoft Outlook for Windows

If you save an email to a file using Microsoft Outlook on Windows, it will
save the file in a proprietary Microsoft OLE format with a `.msg` extension.
There are tools like `msgconvert` that make an attempt to convert a `.msg`
file to a standard RFC 822 `.eml` file, and `yaramail` will attempt to use
this tool when encountering a `.msg` file if it is installed on the system.
However, anomalies are introduced during conversion that make the results
unsuitable for forensic analysis.

Instead of using `msgconvert`, use one of these other Outlook clients.

```{note}
If a `.msg` file is attached to an email and sent from a Windows Outlook
client, the email will actually be sent as a `.eml` file. So, users can send 
email samples without needing to worry about the file format.
```

### Microsoft Outlook for macOS

Drag the email from the inbox or other folder and drop it on the desktop.
Attached emails can be saved to a file like any other attachment.

### Outlook Web Access (OWA)

1. Create a new email and leave it open a separate window.
2. Drag the email from the inbox or other folder and drop it in the message of the draft.
3. Download the attachment that was created in step 2

Emails that are already attached to an email can be downloaded from OWA like
any other attachment.
