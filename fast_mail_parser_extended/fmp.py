import sys
import colors
from fast_mail_parser import parse_email, ParseError
import msg_to_eml
import re
from urlextract import URLExtract

# eml = msg_to_eml.load('sencillo.msg')


with open('sencillo.eml', 'r') as f:
    message_payload = f.read()

try:
    email = parse_email(message_payload)
except ParseError as e:
    print("Failed to parse email: ", e)
    sys.exit(1)

print(colors.bcolors.OKBLUE + 'SUBJECT: \t' + colors.bcolors.ENDC, end='')
print(email.subject)

print(colors.bcolors.OKBLUE + 'DATE: \t' + colors.bcolors.ENDC, end='')
print(email.date)

print(colors.bcolors.OKGREEN + '\tHEADER -> MIME-Version: \t' + colors.bcolors.ENDC, end='')
print(email.headers['MIME-Version'])

print(colors.bcolors.OKGREEN + '\tHEADER -> Date: \t' + colors.bcolors.ENDC, end='')
print(email.headers['Date'])

print(colors.bcolors.OKGREEN + '\tHEADER -> Message-ID: \t' + colors.bcolors.ENDC, end='')
print(email.headers['Message-ID'])

print(colors.bcolors.OKGREEN + '\tHEADER -> Subject: \t' + colors.bcolors.ENDC, end='')
print(email.headers['Subject'])

print(colors.bcolors.OKGREEN + '\tHEADER -> From and Return-Path: \t' + colors.bcolors.ENDC, end='')
print(email.headers['From'], end=' ')
print(colors.bcolors.FAIL + ' <==> ' + colors.bcolors.ENDC, end='')
print(email.headers['Return-Path'], end=' ')
print(colors.bcolors.OKGREEN + '\tComprobación: \t' + colors.bcolors.ENDC, end=' ')

mail_from = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', email.headers['From'])
mail_return_path = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', email.headers['Return-Path'])

if(mail_from.group(0) == mail_return_path.group(0)):
    print(colors.bcolors.OKGREEN + "MATCH" + colors.bcolors.ENDC)
else:
    print(colors.bcolors.WARNING + "NO MATCH" + colors.bcolors.ENDC)

print(colors.bcolors.OKGREEN + '\tHEADER -> From and Return-Path limpios: \t' + colors.bcolors.ENDC, end='')
print(mail_from.group(0), end=' ')
print(colors.bcolors.FAIL + ' <==> ' + colors.bcolors.ENDC, end='')
print(mail_return_path.group(0), end=' ')
print(colors.bcolors.OKGREEN + '\tComprobación: \t' + colors.bcolors.ENDC, end=' ')

if(mail_from.group(0) == mail_return_path.group(0)):
    print(colors.bcolors.OKGREEN + "MATCH" + colors.bcolors.ENDC)
else:
    print(colors.bcolors.WARNING + "NO MATCH" + colors.bcolors.ENDC)

print(colors.bcolors.OKGREEN + '\tHEADER -> Content-Type: \t' + colors.bcolors.ENDC, end='')
print(email.headers['Content-Type'])

print(colors.bcolors.OKGREEN + '\tHEADER -> To:' + colors.bcolors.ENDC)
destinatarios = email.headers['To'].split(',')
for i in range(len(destinatarios)):
    destinatarios_mail = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', destinatarios[i])
    print('\t\t\t' + destinatarios[i] + colors.bcolors.OKBLUE + '\t-->> Sólo mail: ' + colors.bcolors.ENDC + destinatarios_mail[0])

print(colors.bcolors.OKGREEN + '\tHEADER -> ARC-Authentication-Results:' + colors.bcolors.ENDC)
ARC_Authentication_Results = email.headers['ARC-Authentication-Results'].split(';')
for i in range(len(ARC_Authentication_Results)):
    print('\t\t\t' + ARC_Authentication_Results[i])

print(colors.bcolors.OKGREEN + '\tHEADER -> DKIM-Signature:' + colors.bcolors.ENDC)
DKIM_Signature = email.headers['DKIM-Signature'].split(';')
for i in range(len(DKIM_Signature)):
    print('\t\t\t' + DKIM_Signature[i])



url_regex ="((?:https?://)?(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)"
#mail_regex = r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])'

#mail_regex = r'[\w.+-]+@[\w-]+\.[\w.-]+'
#mail_regex = r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])"
#mail_regex = r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"

mail_regex = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])"

text_plain_limpio = str(email.text_plain)
text_plain_limpio = text_plain_limpio.replace(r'\n', ' ')
text_plain_limpio = text_plain_limpio.replace(r'\r', ' ')

array_de_URLs = re.findall(url_regex, str(text_plain_limpio))
array_de_mails = re.findall(mail_regex, str(text_plain_limpio))


print(colors.bcolors.OKBLUE + 'URLs en el cuerpo:' + colors.bcolors.ENDC)
for i in range(len(array_de_URLs)):
    print('\t' + array_de_URLs[i])

print(colors.bcolors.OKCYAN + '\tURLs en el cuerpo (únicos):' + colors.bcolors.ENDC)
urls_unicas = []
for url_unica in array_de_URLs:
  if url_unica not in urls_unicas:
    print('\t\t' + url_unica + ' ('+ str(array_de_URLs.count(url_unica)) + ') veces')
    urls_unicas.append(url_unica)

print(colors.bcolors.OKBLUE + 'Mails en el cuerpo:' + colors.bcolors.ENDC)
for i in range(len(array_de_mails)):
    print('\t' + str(array_de_mails[i]))

print(colors.bcolors.OKCYAN + '\tMails en el cuerpo (únicos):' + colors.bcolors.ENDC)
mails_unicos = []
for mail_unico in array_de_mails:
  if mail_unico not in mails_unicos:
    print('\t\t' + mail_unico + ' ('+ str(array_de_mails.count(mail_unico))+ ') veces')
    mails_unicos.append(mail_unico)

print(colors.bcolors.OKCYAN + "*\n*\n*\n********************************** RAW **********************************" + colors.bcolors.ENDC)

print(colors.bcolors.FAIL + "HEADERS" + colors.bcolors.ENDC)
print(colors.bcolors.FAIL + "-------" + colors.bcolors.ENDC)
print(email.headers)

print(colors.bcolors.FAIL + "EMAIL.TEXT_PLAIN" + colors.bcolors.ENDC)
print(colors.bcolors.FAIL + "----------------" + colors.bcolors.ENDC)
print(email.text_plain)

print(colors.bcolors.FAIL + "text_plain_limpio" + colors.bcolors.ENDC)
print(colors.bcolors.FAIL + "-----------------" + colors.bcolors.ENDC)
print(text_plain_limpio)

print(colors.bcolors.FAIL + "EMAIL.TEXT_HTML" + colors.bcolors.ENDC)
print(colors.bcolors.FAIL + "---------------" + colors.bcolors.ENDC)
print(email.text_html)

print(colors.bcolors.FAIL + "ATTACHMENTS" + colors.bcolors.ENDC)
print(colors.bcolors.FAIL + "----------->>>>" + colors.bcolors.ENDC)

i = 0
for attachment in email.attachments:
    print(colors.bcolors.WARNING + "\tATTACHMENT Nº" + str(i) + colors.bcolors.ENDC)
    i += 1
    print("\t",end='')
    print(attachment.mimetype)
    print("\t",end='')
    print(attachment.content)
    print("\t",end='')
    print(attachment.filename)
    
