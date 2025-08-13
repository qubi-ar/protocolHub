# Manual line-udp test

```bash
echo -n 'hola qubi' | nc -u -w1 127.0.0.1 5515
```

# Manual snmp trap test

```bash
snmptrap -v 2c -c public 127.0.0.1:9162 '' \
  1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.1 i 1
```


