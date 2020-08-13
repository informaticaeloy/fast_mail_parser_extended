# nc_mail_parser

nc_mail_parser is a Python library for .eml files parsing.
The main benefit is a performance: the library is much faster than python implementations.

Based on [mailparse](https://github.com/staktrace/mailparse) library using [pyo3](https://github.com/PyO3/pyo3).

## Installation

Use the package manager [pip](https://pypi.org/project/nc_mail_parser/) to install nc_mail_parser.

```bash
pip install nc-mail-parser
```

## Usage

```python
import sys
from nc_mail_parser import parse_email, ParseError

with open('message.eml', 'r') as f:
    message_payload = f.read()

try:
    email = parse_email(message_payload)
except ParseError as e:
    print("Failed to parse email: ", e)
    sys.exit(1)

print(email.subject)
print(email.date)
print(email.text_plain)
print(email.text_html)
print(email.headers)

for attachment in email.attachments:
    print(attachment.mimetype)
    print(attachment.content)

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
