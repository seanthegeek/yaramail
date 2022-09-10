# Collecting email samples

In order to be properly analyzed, email samples must be stored or sent with
the foll content intact, including any headers. The process of obtaining
raw/original depends on the email service or client being used.

## AOL webmail

1. In the list of emails in your in inbox or folder, right-click on the message (not in the message itself)
2. Click View Message Source
3. Select the entire raw message content, copy it, paste it into an empty text editor, and save the file with a `.eml` file extension

## Apple Mail on macOS

1. Right-click on the message in the list of messages
2. Click Forward as Attachment
3. Save the attachment and/or send the email

## Gmail/Google Workspace webmail

1. Open the message
2. Click on the three vertical dots in the upper right
3. Click Show original
4. Click Download Original

## GoDaddy and Rackspace webmail

1. Open the message you want to forward. To forward multiple emails, instead of opening an email, use the checkboxes to select the emails you want to forward.
2. In the top right corner of the page, click the More Actions menu.
3. Select Fwd. as Attachment.
4. Click Apply. A new email is created with a `.eml` file attached.
5. Save the attachment(s) and/or send the email

## GroupWise

1. From the GroupWise item list, select the e-mail(s) you wish to forward (multiple messages can be selected with Shift-Click, Ctrl-Click, etc.)
2. Select the Action Menu
3. From the Action Menu, select the “Forward As Attachment” Item
4. Save the attachment(s) and/or send the email

## Notes

1. Open the email
2. Save it to a file by going to the File > Save As menu item

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

:::{note}
If a `.msg` file is attached to an email and sent from a Windows Outlook
client, the email will actually be sent as a `.eml` file. So, users can send
email samples without needing to worry about the file format.
:::

### Microsoft Outlook for macOS

Drag the email from the inbox or other folder and drop it on the desktop.
Attached emails can be saved to a file like any other attachment.

### Outlook Web Access (OWA)/Outlook.com

1. Create a new email and leave it open a separate window.
2. Drag the email from the inbox or other folder and drop it in the message of the draft.
3. Download the attachment that was created in step 2

Emails that are already attached to an email can be downloaded from OWA like
any other attachment.

## Thunderbird

1. In the messages list, right-click on the message you want to forward (or select multiple messages and then right click)
2. Select Forward as attachment
3. Save the attachment(s) and/or send the email

## Windows 10 Mail app

1. Open the message
2. Click on the three horizontal dots in the upper right
3. Click Save As, and save the email as a file
4. Attach the saved file to a new email, fill in the To field, and click send

## Yahoo webmail

1. Open the message
2. Click on the three horizontal dots in the upper right, and click View Raw Message
3. Select the entire raw message content, copy it, paste it into an empty text editor, and save the file with a .eml file extension
