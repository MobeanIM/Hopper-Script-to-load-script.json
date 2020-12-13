import json
processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

doc = Document.getCurrentDocument()
path = Document.askFile("Symbols file", None, False)
data = json.loads(open(path, 'rb').read().decode('utf-8'))
baseAddress = 0x100000000
if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	for scriptMethod in scriptMethods:
		addr = int(scriptMethod["Address"] + baseAddress)
		name = scriptMethod["Name"].encode("utf-8")
		doc.setNameAtAddress(addr, name)
if "ScriptString" in data and "ScriptString" in processFields:
	scriptStrings = data["ScriptString"]
	for scriptString in scriptStrings:
		addr = int(scriptString["Address"] + baseAddress)
		value = scriptString["Value"].encode("utf-8")
		doc.setNameAtAddress(addr, value)
if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	for scriptMetadata in scriptMetadatas:
		addr = int(scriptMetadata["Address"] + baseAddress)
		name = scriptMetadata["Name"].encode("utf-8")
		doc.setNameAtAddress(addr, name)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
	scriptMetadataMethods = data["ScriptMetadataMethod"]
	for scriptMetadataMethod in scriptMetadataMethods:
		addr = int(scriptMetadataMethod["Address"] + baseAddress)
		name = scriptMetadataMethod["Name"].encode("utf-8")
		methodAddr = scriptMetadataMethod["MethodAddress"]
		doc.setNameAtAddress(addr, name)
