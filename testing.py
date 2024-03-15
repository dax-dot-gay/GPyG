import gpyg

context = gpyg.GPGMEContext()
print(repr(context.protocol))
context.protocol = gpyg.GpgmeProtocol.ASSUAN
print(repr(context.protocol))
