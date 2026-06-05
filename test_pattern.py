import re
pattern = re.compile(r"\{\{.{1,50}\}\}", re.IGNORECASE)
test = "{\"msg\":\"name={{7*7}}\"}"
print("Match:", bool(pattern.search(test)))
print("Body:", test)
body2 = "name={{7*7}}"
print("Direct match:", bool(pattern.search(body2)))

