## Netascii CR/LF conversion per RFC 1350.
## On the wire: CR/LF line endings.
## Local: platform-native line endings.

proc toNetascii*(data: seq[byte]): seq[byte] =
  ## Convert local line endings to CR/LF for transmission.
  for i, b in data:
    if b == byte('\n'):
      # Check if already preceded by CR
      if i > 0 and data[i-1] == byte('\r'):
        result.add b  # already CR/LF
      else:
        result.add byte('\r')
        result.add byte('\n')
    elif b == byte('\r'):
      result.add byte('\r')
      # If not followed by LF, add NUL per RFC 764
      if i + 1 >= data.len or data[i+1] != byte('\n'):
        result.add byte('\0')
    else:
      result.add b

proc fromNetascii*(data: seq[byte]): seq[byte] =
  ## Convert CR/LF from wire to local line endings.
  var i = 0
  while i < data.len:
    if data[i] == byte('\r'):
      if i + 1 < data.len and data[i+1] == byte('\n'):
        # CR/LF -> native newline
        result.add byte('\n')
        i += 2
      elif i + 1 < data.len and data[i+1] == byte('\0'):
        # CR/NUL -> bare CR
        result.add byte('\r')
        i += 2
      else:
        result.add byte('\r')
        i += 1
    else:
      result.add data[i]
      i += 1
